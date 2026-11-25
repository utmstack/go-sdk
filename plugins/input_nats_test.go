package plugins

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/grpc"
)

func TestLogShardSubjectKeepsTheSpreadLogInputUses(t *testing.T) {
	// These values come from the algorithm log-input has always used: FNV-1a over tenant, source and
	// type, separated by a zero byte. If they change, a source's logs would move to another subject.
	cases := []struct {
		l      *Log
		shards int
		want   string
	}{
		{&Log{TenantId: "ce66672c-e36d-4761-a8c8-90058fee1a24", DataSource: "host-1", DataType: "linux"}, 16, "logs.shard.15"},
		{&Log{TenantId: "ce66672c-e36d-4761-a8c8-90058fee1a24", DataSource: "163.247.100.135", DataType: "firewall-sophos-xg"}, 16, "logs.shard.9"},
		{&Log{}, 16, "logs.shard.13"},
		{&Log{TenantId: "ce66672c-e36d-4761-a8c8-90058fee1a24", DataSource: "host-1", DataType: "linux"}, 4, "logs.shard.3"},
	}

	for _, c := range cases {
		if got := LogShardSubject(c.l, c.shards); got != c.want {
			t.Errorf("%+v over %d shards: got %s, want %s", c.l, c.shards, got, c.want)
		}
	}
}

func TestLogShardSubjectIsStablePerSourceAndFallsBackToTheDefaultShardCount(t *testing.T) {
	l := &Log{TenantId: "t", DataSource: "s", DataType: "d"}

	if LogShardSubject(l, 16) != LogShardSubject(l, 16) {
		t.Error("the same source must always land on the same subject")
	}

	if LogShardSubject(l, 0) != LogShardSubject(l, DefaultLogShards) {
		t.Error("a shard count that is not positive means the default")
	}

	for i := 0; i < 200; i++ {
		s := LogShardSubject(&Log{TenantId: "t", DataSource: fmt.Sprint("s", i), DataType: "d"}, 4)
		if s != "logs.shard.0" && s != "logs.shard.1" && s != "logs.shard.2" && s != "logs.shard.3" {
			t.Fatalf("subject out of range: %s", s)
		}
	}
}

func TestTransportDefaultsToNATSOnlyWhenItsURLIsSet(t *testing.T) {
	t.Setenv(LogsTransportEnv, "")
	t.Setenv(NATSURLEnv, "")

	if got := logsTransport(); got != "grpc" {
		t.Errorf("no NATS_URL: got %s, want grpc", got)
	}

	t.Setenv(NATSURLEnv, "nats://nats:4222")

	if got := logsTransport(); got != "nats" {
		t.Errorf("with NATS_URL: got %s, want nats", got)
	}
}

func TestTransportCanBeChosenExplicitly(t *testing.T) {
	t.Setenv(NATSURLEnv, "nats://nats:4222")

	for value, want := range map[string]string{"grpc": "grpc", "GRPC": "grpc", " nats ": "nats", "auto": "nats", "nonsense": "nats"} {
		t.Setenv(LogsTransportEnv, value)

		if got := logsTransport(); got != want {
			t.Errorf("%q: got %s, want %s", value, got, want)
		}
	}

	t.Setenv(NATSURLEnv, "")
	t.Setenv(LogsTransportEnv, "nats")

	if got := logsTransport(); got != "nats" {
		t.Error("an explicit nats is honoured; sending then fails loudly if there is no URL")
	}
}

func TestEnvPositiveIntFallsBackAndCaps(t *testing.T) {
	t.Setenv("X_TEST_INT", "")

	if envPositiveInt("X_TEST_INT", 7, 10) != 7 {
		t.Error("unset must give the fallback")
	}

	for value, want := range map[string]int{"3": 3, "0": 7, "-2": 7, "abc": 7, "99": 10, " 5 ": 5} {
		t.Setenv("X_TEST_INT", value)

		if got := envPositiveInt("X_TEST_INT", 7, 10); got != want {
			t.Errorf("%q: got %d, want %d", value, got, want)
		}
	}
}

type fakePublisher struct {
	mu        sync.Mutex
	published []string
	calls     map[string]int
	failFirst int // how many times each log fails before it succeeds; <0 means always
	inFlight  atomic.Int32
	maxSeen   atomic.Int32
	delay     time.Duration
}

func (f *fakePublisher) Publish(_ context.Context, l *Log) error {
	n := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)

	for {
		m := f.maxSeen.Load()
		if n <= m || f.maxSeen.CompareAndSwap(m, n) {
			break
		}
	}

	if f.delay > 0 {
		time.Sleep(f.delay)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.calls == nil {
		f.calls = map[string]int{}
	}

	f.calls[l.Id]++

	if f.failFirst < 0 || f.calls[l.Id] <= f.failFirst {
		return errors.New("nats unavailable")
	}

	f.published = append(f.published, l.Id)

	return nil
}

func fastBackoff(t *testing.T) {
	t.Helper()

	previous := publishBackoff
	publishBackoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { publishBackoff = previous })
}

func feed(ids ...string) <-chan *Log {
	ch := make(chan *Log, len(ids))
	for _, id := range ids {
		ch <- &Log{Id: id}
	}

	close(ch)

	return ch
}

func TestEveryLogIsPublishedOnceByTheWorkers(t *testing.T) {
	f := &fakePublisher{}
	ids := make([]string, 200)

	for i := range ids {
		ids[i] = fmt.Sprint("log-", i)
	}

	publishLogs(f, feed(ids...), 8, "plugin_test")

	if len(f.published) != 200 {
		t.Fatalf("published %d of 200", len(f.published))
	}

	for id, n := range f.calls {
		if n != 1 {
			t.Errorf("%s was published %d times", id, n)
		}
	}
}

func TestAFailingPublishIsRetriedUntilItSucceeds(t *testing.T) {
	fastBackoff(t)

	f := &fakePublisher{failFirst: 2}

	publishLogs(f, feed("a"), 1, "plugin_test")

	if len(f.published) != 1 || f.calls["a"] != 3 {
		t.Errorf("published %v after %d calls, want one log after 3", f.published, f.calls["a"])
	}
}

func TestALogThatNeverGetsThroughIsDroppedAndTheRestKeepFlowing(t *testing.T) {
	fastBackoff(t)

	bad := &fakePublisher{failFirst: -1}
	publishLogs(bad, feed("a", "b"), 1, "plugin_test")

	if len(bad.published) != 0 || bad.calls["a"] != len(publishBackoff)+1 {
		t.Errorf("a log must be attempted %d times, then dropped: %v", len(publishBackoff)+1, bad.calls)
	}

	// Another log, after the dropped one, still goes through.
	mixed := &mixedPublisher{badID: "bad"}
	publishLogs(mixed, feed("bad", "good"), 1, "plugin_test")

	if len(mixed.published) != 1 || mixed.published[0] != "good" {
		t.Errorf("published %v, want only the good one", mixed.published)
	}
}

type mixedPublisher struct {
	badID     string
	published []string
}

func (m *mixedPublisher) Publish(_ context.Context, l *Log) error {
	if l.Id == m.badID {
		return errors.New("rejected")
	}

	m.published = append(m.published, l.Id)

	return nil
}

func TestNoMoreLogsAreInFlightThanThereAreWorkers(t *testing.T) {
	f := &fakePublisher{delay: 5 * time.Millisecond}
	ids := make([]string, 60)

	for i := range ids {
		ids[i] = fmt.Sprint("log-", i)
	}

	publishLogs(f, feed(ids...), 4, "plugin_test")

	if f.maxSeen.Load() > 4 {
		t.Errorf("%d logs were in flight with 4 workers", f.maxSeen.Load())
	}

	if f.maxSeen.Load() < 2 {
		t.Error("the workers must publish in parallel")
	}
}

// TestPublishToARealServer runs only when NATS_TEST_URL points at a NATS server with JetStream.
func TestPublishToARealServer(t *testing.T) {
	url := os.Getenv("NATS_TEST_URL")
	if url == "" {
		t.Skip("NATS_TEST_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	pub, err := NewNATSPublisher(ctx, url, "sdk-test", 4)
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()

	l := &Log{Id: fmt.Sprint("sdk-test-", time.Now().UnixNano()), TenantId: "sdk-test-tenant", DataSource: "sdk-test-source", DataType: "linux", Raw: "x"}
	if err := pub.Publish(ctx, l); err != nil {
		t.Fatal(err)
	}

	stream, err := pub.js.Stream(ctx, LogsStreamName)
	if err != nil {
		t.Fatal(err)
	}

	msg, err := stream.GetLastMsgForSubject(ctx, LogShardSubject(l, 4))
	if err != nil {
		t.Fatal(err)
	}

	var _ jetstream.RawStreamMsg = *msg

	if len(msg.Data) == 0 {
		t.Error("the stored message is empty")
	}
}

// TestSendLogsFromChannelPublishesToNATS follows a log from EnqueueLog to the stream. It runs only
// when NATS_TEST_URL points at a NATS server with JetStream.
func TestSendLogsFromChannelPublishesToNATS(t *testing.T) {
	url := os.Getenv("NATS_TEST_URL")
	if url == "" {
		t.Skip("NATS_TEST_URL is not set")
	}

	t.Setenv(LogsTransportEnv, "nats")
	t.Setenv(NATSURLEnv, url)
	t.Setenv(LogShardsEnv, "4")

	go SendLogsFromChannel("sdk-test")

	l := &Log{Id: fmt.Sprint("sdk-e2e-", time.Now().UnixNano()), TenantId: "sdk-test-tenant", DataSource: "sdk-e2e-source", DataType: "linux", Raw: "x"}

	deadline := time.Now().Add(10 * time.Second)

	if err := EnqueueLog(l, "sdk-test"); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pub, err := NewNATSPublisher(ctx, url, "sdk-test-reader", 4)
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()

	stream, err := pub.js.Stream(ctx, LogsStreamName)
	if err != nil {
		t.Fatal(err)
	}

	for time.Now().Before(deadline.Add(5 * time.Second)) {
		msg, err := stream.GetLastMsgForSubject(ctx, LogShardSubject(l, 4))
		if err == nil && len(msg.Data) > 0 && strings.Contains(string(msg.Data), l.Id) {
			return
		}

		time.Sleep(50 * time.Millisecond)
	}

	t.Error("the log never reached the stream")
}

type fakeEngine struct {
	UnimplementedEngineServer

	received chan *Log
}

func (f *fakeEngine) Input(stream Engine_InputServer) error {
	for {
		l, err := stream.Recv()
		if err != nil {
			return err
		}

		f.received <- l

		if err := stream.Send(&Ack{LastId: l.Id}); err != nil {
			return err
		}
	}
}

// TestSendLogsToEngineStillSendsOverTheSocket keeps the gRPC path working: it is chosen with
// LOGS_TRANSPORT=grpc, or when there is no NATS_URL.
func TestSendLogsToEngineStillSendsOverTheSocket(t *testing.T) {
	// A unix socket path is limited to about a hundred characters, which t.TempDir often exceeds.
	dir, err := os.MkdirTemp("/tmp", "sdkeng")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	previous := WorkDir
	WorkDir = dir
	t.Cleanup(func() { WorkDir = previous })

	if err := os.MkdirAll(WorkDir+"/sockets", 0o755); err != nil {
		t.Fatal(err)
	}

	lis, err := net.Listen("unix", WorkDir+"/sockets/engine_server.sock")
	if err != nil {
		t.Fatal(err)
	}

	engine := &fakeEngine{received: make(chan *Log, 10)}
	srv := grpc.NewServer()
	RegisterEngineServer(srv, engine)

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	queue := make(chan *Log, 10)

	go sendLogsToEngine(queue, "plugin_test")

	queue <- &Log{Id: "over-grpc", TenantId: "t", DataSource: "s", DataType: "d", Raw: "x"}

	select {
	case got := <-engine.received:
		if got.Id != "over-grpc" {
			t.Errorf("received %q", got.Id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the engine never received the log")
	}
}
