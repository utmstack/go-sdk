package opensearch

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/threatwinds/go-sdk/catcher"
	sdkos "github.com/threatwinds/go-sdk/os"
	"github.com/tidwall/gjson"
	"github.com/utmstack/go-sdk/v2/store"
)

const (
	defaultFlushThreshold = 2000
	defaultFlushInterval  = 10 * time.Second
	defaultMaxRetries     = 3
)

func (d *Driver) BulkWriter(dataset store.Dataset) (store.BulkWriter, error) {
	if _, err := d.cfg.Layout.ReadIndices(store.Scope{Dataset: dataset}); err != nil {
		return nil, err
	}
	w := &bulkWriter{driver: d, dataset: dataset}
	w.queue = sdkos.NewBulkQueue("store_"+string(dataset), sdkos.BulkQueueConfig{
		FlushInterval:  defaultFlushInterval,
		FlushThreshold: defaultFlushThreshold,
		MaxRetries:     defaultMaxRetries,
		RetryDelay:     time.Second,
		OnError: func(failed []sdkos.BulkItem, err error) {
			w.recordFailure(len(failed), err)
			// The queue drops the per-item OpenSearch reason, so the one thing it
			// does hand over is the doc that was rejected: log it, so a failed
			// write says which record, and its offending field, it was.
			for _, it := range failed {
				cat, _ := it.Document.(json.RawMessage)
				catcher.Error("opensearch bulk item failed",
					fmt.Errorf("id=%s", it.DocumentID),
					map[string]any{"index": it.Index, "doc": string(cat)})
			}
		},
	})
	return w, nil
}

type bulkWriter struct {
	driver  *Driver
	dataset store.Dataset
	queue   *sdkos.BulkQueue

	mu       sync.Mutex
	lastErr  error
	lostDocs int
	closed   bool
}

func (w *bulkWriter) Write(s store.Scope, doc []byte) error {
	if s.Tenant == "" {
		return store.ErrNoTenant
	}
	if s.Dataset != w.dataset {
		return fmt.Errorf("opensearch: writer is for %s, got a %s record", w.dataset, s.Dataset)
	}
	if err := w.takeErr(); err != nil {
		return err
	}

	w.mu.Lock()
	closed := w.closed
	w.mu.Unlock()
	if closed {
		return fmt.Errorf("opensearch: bulk writer is closed")
	}

	// The index is dated by the record's own time, not the clock, so an update
	// of an old record lands in the same index the record was created in. A
	// record without a parseable time falls back to the clock: it is new.
	index, err := w.driver.cfg.Layout.WriteIndex(s, docTime(w.driver.now(), w.driver.cfg.TimestampField, doc))
	if err != nil {
		return err
	}

	w.queue.AddItem(newBulkItem(index, doc))
	return nil
}

// docTime picks the instant a record's index is dated by: the record's own
// timestamp, or the clock when the record carries none. A timestamp in a
// shape RFC 3339 does not cover is the record's problem, not the index's, so
// it falls back to the clock like a missing one.
func docTime(now time.Time, field string, doc []byte) time.Time {
	if v := gjson.GetBytes(doc, field); v.Exists() {
		if t, err := time.Parse(time.RFC3339Nano, v.String()); err == nil {
			return t
		}
	}
	return now
}

// newBulkItem is one queued record: a whole-doc replace under the record's own
// id, so an update of a record overwrites it in place instead of duplicating
// it under a generated id.
func newBulkItem(index string, doc []byte) sdkos.BulkItem {
	return sdkos.BulkItem{
		Index:      index,
		Operation:  sdkos.BulkOperationIndex,
		DocumentID: gjson.GetBytes(doc, "id").String(),
		Document:   json.RawMessage(doc),
	}
}

func (w *bulkWriter) Flush(ctx context.Context) error {
	if err := w.queue.Flush(); err != nil {
		return err
	}
	return w.takeErr()
}

func (w *bulkWriter) Close(ctx context.Context) error {
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()

	w.queue.Stop()
	return w.takeErr()
}

func (w *bulkWriter) recordFailure(n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastErr = err
	w.lostDocs += n
}

// takeErr clears the failure as it reports it, so one failed bulk surfaces once
// instead of poisoning every later call.
func (w *bulkWriter) takeErr() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.lastErr == nil {
		return nil
	}
	err := fmt.Errorf("opensearch: bulk write failed for %d document(s): %w", w.lostDocs, w.lastErr)
	w.lastErr, w.lostDocs = nil, 0
	return err
}
