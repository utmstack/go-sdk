package plugins

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/threatwinds/go-sdk/catcher"
)

// The stream the logs are published to. It is declared the same way by everything that publishes to
// it, so none of them has to start first.
const (
	LogsStreamName    = "INGEST_LOGS"
	LogsShardSubjects = "logs.shard.*"
	LogsDLQSubject    = "logs.dlq"

	logsStreamMaxAge = 24 * time.Hour

	// DefaultLogShards is how many subjects the logs are spread over when SHARDS is not set.
	DefaultLogShards = 16
	maxLogShards     = 1024

	defaultNATSWorkers = 8
	maxNATSWorkers     = 64

	publishAttemptTimeout = 10 * time.Second
)

// Environment variables that decide how a plugin sends its logs.
const (
	// LogsTransportEnv chooses where SendLogsFromChannel puts the logs: "nats" publishes them
	// straight to the stream, "grpc" sends them to the event processor's input over the local
	// socket, and "auto" (the default) uses NATS when NATS_URL is set and the socket otherwise.
	LogsTransportEnv = "LOGS_TRANSPORT"
	// NATSURLEnv is where the NATS server is.
	NATSURLEnv = "NATS_URL"
	// LogShardsEnv is how many subjects the logs are spread over.
	LogShardsEnv = "SHARDS"
	// NATSWorkersEnv is how many logs are published at the same time.
	NATSWorkersEnv = "LOGS_NATS_WORKERS"
)

// publishBackoff is how long a log waits before each new attempt to publish it. Past the last one
// the log is dropped and reported. It is a variable so tests do not have to wait.
var publishBackoff = []time.Duration{200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond, 1600 * time.Millisecond, 3200 * time.Millisecond}

// NATSPublisher publishes logs to the ingestion stream and waits for the server to confirm each one,
// so a log it accepted is stored.
type NATSPublisher struct {
	nc     *nats.Conn
	js     jetstream.JetStream
	shards int
}

// NewNATSPublisher connects to NATS and makes sure the stream exists. It keeps trying to reconnect
// for as long as the process lives, so a NATS restart makes publishing wait instead of failing.
func NewNATSPublisher(ctx context.Context, url, name string, shards int) (*NATSPublisher, error) {
	if shards < 1 {
		shards = DefaultLogShards
	}

	nc, err := nats.Connect(url,
		nats.Name(name),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.RetryOnFailedConnect(true),
	)
	if err != nil {
		return nil, fmt.Errorf("connecting to NATS: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()

		return nil, fmt.Errorf("creating the JetStream context: %w", err)
	}

	if _, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:      LogsStreamName,
		Subjects:  []string{LogsShardSubjects, LogsDLQSubject},
		Retention: jetstream.WorkQueuePolicy,
		MaxAge:    logsStreamMaxAge,
	}); err != nil {
		nc.Close()

		return nil, fmt.Errorf("creating the stream: %w", err)
	}

	return &NATSPublisher{nc: nc, js: js, shards: shards}, nil
}

// Close ends the connection.
func (p *NATSPublisher) Close() {
	if p != nil && p.nc != nil {
		p.nc.Close()
	}
}

// Publish stores one log and waits for the server to confirm it.
func (p *NATSPublisher) Publish(ctx context.Context, l *Log) error {
	payload, err := ProtoMessageToString(l)
	if err != nil {
		return fmt.Errorf("serialising the log: %w", err)
	}

	subject := LogShardSubject(l, p.shards)
	if _, err := p.js.Publish(ctx, subject, []byte(*payload)); err != nil {
		return fmt.Errorf("publishing to %s: %w", subject, err)
	}

	return nil
}

// LogShardSubject is the subject a log is published to. It spreads logs by source rather than at
// random, so one source's logs land on one subject and a consumer can be given a shard of its own
// later without resharding what is already published.
func LogShardSubject(l *Log, shards int) string {
	if shards < 1 {
		shards = DefaultLogShards
	}

	h := fnv.New32a()
	_, _ = h.Write([]byte(l.TenantId))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(l.DataSource))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(l.DataType))

	return fmt.Sprintf("logs.shard.%d", int(h.Sum32())%shards)
}

// logPublisher is what the sender needs from a publisher.
type logPublisher interface {
	Publish(ctx context.Context, l *Log) error
}

// logsTransport says where SendLogsFromChannel sends the logs: "nats" or "grpc".
func logsTransport() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(LogsTransportEnv))) {
	case "nats":
		return "nats"
	case "grpc":
		return "grpc"
	}

	if os.Getenv(NATSURLEnv) != "" {
		return "nats"
	}

	return "grpc"
}

func envPositiveInt(name string, fallback, max int) int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil || n < 1 {
		return fallback
	}

	if n > max {
		return max
	}

	return n
}

// publishLogs drains in with workers goroutines, each publishing one log at a time and retrying it
// with a growing pause. A log that still cannot be published is reported and dropped, so one bad
// moment of the server does not stop the plugin. It returns when in is closed and empty.
func publishLogs(pub logPublisher, in <-chan *Log, workers int, processName string) {
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for l := range in {
				publishWithRetry(pub, l, processName)
			}
		}()
	}

	wg.Wait()
}

func publishWithRetry(pub logPublisher, l *Log, processName string) {
	var err error

	for attempt := 0; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), publishAttemptTimeout)
		err = pub.Publish(ctx, l)
		cancel()

		if err == nil {
			return
		}

		if attempt >= len(publishBackoff) {
			break
		}

		time.Sleep(publishBackoff[attempt])
	}

	_ = catcher.Error("cannot publish a log, dropping it", err, map[string]any{
		"process":  processName,
		"logId":    l.GetId(),
		"attempts": len(publishBackoff) + 1,
	})
}

// sendLogsToNATS publishes what the plugin enqueues straight to the ingestion stream. A plugin that
// cannot reach NATS at start exits and is restarted, as it does when the engine socket is missing.
func sendLogsToNATS(pluginName, processName string) {
	url := os.Getenv(NATSURLEnv)
	if url == "" {
		_ = catcher.Error("LOGS_TRANSPORT is nats but NATS_URL is not set", nil, map[string]any{"process": processName})
		time.Sleep(5 * time.Second)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	pub, err := NewNATSPublisher(ctx, url, "plugin_"+pluginName, envPositiveInt(LogShardsEnv, DefaultLogShards, maxLogShards))

	cancel()

	if err != nil {
		_ = catcher.Error("failed to connect to NATS", err, map[string]any{"url": url, "process": processName})
		time.Sleep(5 * time.Second)
		os.Exit(1)
	}
	defer pub.Close()

	publishLogs(pub, logsQueue(), envPositiveInt(NATSWorkersEnv, defaultNATSWorkers, maxNATSWorkers), processName)
}
