package plugins

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/threatwinds/go-sdk/catcher"
	"github.com/threatwinds/go-sdk/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var logsChannel chan *Log
var logsChannelOnce sync.Once

// logsQueue is the channel plugins enqueue their logs on. It is made the first time anyone asks,
// from either side, so a plugin that enqueues before the sender has started is never sending to a
// channel that does not exist yet.
func logsQueue() chan *Log {
	logsChannelOnce.Do(func() {
		logsChannel = make(chan *Log, runtime.NumCPU()*1000)
	})

	return logsChannel
}

// SendLogsFromChannel listens to the logsChannel and sends the logs on, by default straight to NATS
// when NATS_URL is set and to the engine server over gRPC otherwise; LOGS_TRANSPORT ("nats", "grpc"
// or "auto") overrides that. It logs an error if the connection fails, if sending a log fails, or if
// receiving an acknowledgment fails. It runs indefinitely and should be run as a goroutine.
func SendLogsFromChannel(pluginName string) {
	processName := fmt.Sprintf("plugin_%s", pluginName)

	queue := logsQueue()

	if logsTransport() == "nats" {
		sendLogsToNATS(pluginName, processName)

		return
	}

	sendLogsToEngine(queue, processName)
}

// sendLogsToEngine sends what is enqueued to the engine server's input over the local socket.
func sendLogsToEngine(queue <-chan *Log, processName string) {
	socketDir, err := utils.MkdirJoin(WorkDir, "sockets")
	if err != nil {
		_ = catcher.Error("failed to create socket directory", err, map[string]any{
			"process": processName,
		})
		time.Sleep(5 * time.Second)
		os.Exit(1)
	}
	socketFile := socketDir.FileJoin("engine_server.sock")

	conn, err := grpc.NewClient(fmt.Sprintf("unix://%s", socketFile), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		_ = catcher.Error("failed to connect to engine server", err, map[string]any{
			"socket":  socketFile,
			"process": processName,
		})
		time.Sleep(5 * time.Second)
		os.Exit(1)
	}

	client := NewEngineClient(conn)

	inputClient, err := client.Input(context.Background())
	if err != nil {
		_ = catcher.Error("failed to create input client", err, map[string]any{
			"socket":  socketFile,
			"process": processName,
		})
		time.Sleep(5 * time.Second)
		os.Exit(1)
	}

	go func() {
		for {
			log := <-queue

			err := inputClient.Send(log)
			if err != nil {
				if strings.Contains(err.Error(), "EOF") {
					return
				}
				_ = catcher.Error("failed to send log", err, map[string]any{
					"socket":  socketFile,
					"process": processName,
				})
				time.Sleep(5 * time.Second)
				os.Exit(1)
			}
		}
	}()

	for {
		_, err := inputClient.Recv()
		if err != nil {
			if strings.Contains(err.Error(), "EOF") {
				return
			}
			_ = catcher.Error("failed to receive ack", err, map[string]any{
				"process": processName,
			})
			time.Sleep(5 * time.Second)
			os.Exit(1)
		}
	}
}

// EnqueueLog sends a log to the local logs queue.
// Parameters:
//   - log: The log to enqueue
func EnqueueLog(log *Log, pluginName string) error {
	select {
	case logsQueue() <- log:
		return nil
	case <-time.After(1 * time.Second):
		return catcher.Error("cannot enqueue log", errors.New("queue is full"), map[string]any{
			"advise":  "please consider to increase resources",
			"process": fmt.Sprintf("plugin_%s", pluginName),
		})
	}
}
