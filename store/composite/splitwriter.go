package composite

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/tidwall/gjson"

	"github.com/threatwinds/go-sdk/catcher"
	"github.com/threatwinds/go-sdk/store"
)

// splitWriter sends each record of a bulk write to whichever store holds it:
// a record older than Cutover goes to the secondary, the rest to the primary.
// The document keeps its own shape; only the scope is adjusted per store.
type splitWriter struct {
	cfg     Config
	dataset store.Dataset
	primary store.BulkWriter

	mu        sync.Mutex
	secondary store.BulkWriter
}

var _ store.BulkWriter = (*splitWriter)(nil)

func newSplitWriter(c *Store, dataset store.Dataset) (*splitWriter, error) {
	p, err := c.cfg.Primary.BulkWriter(dataset)
	if err != nil {
		return nil, err
	}
	return &splitWriter{cfg: c.cfg, dataset: dataset, primary: p}, nil
}

// secondaryHalf returns the secondary's writer, opening it on first use. A
// batch that never routes a record to the secondary never opens it. An open
// error is returned without being kept: a transient outage must not poison the
// secondary's later writes.
func (w *splitWriter) secondaryHalf() (store.BulkWriter, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.secondary == nil {
		h, err := w.cfg.Secondary.BulkWriter(w.dataset)
		if err != nil {
			return nil, err
		}
		w.secondary = h
	}
	return w.secondary, nil
}

func (w *splitWriter) Write(s store.Scope, doc []byte) error {
	if s.Tenant == "" {
		return store.ErrNoTenant
	}
	// A record older than the cutover belongs to the secondary, the rest to the
	// primary; the routing is by the record's own time, not the scope's.
	t, err := w.docTime(doc)
	if err != nil {
		return err
	}

	if w.secondaryHolds(t) {
		// The secondary has no tenant field: the scope is concrete to it, and
		// its end is clamped to Cutover like a read.
		ss := s
		if ss.Tenant == store.AllTenants {
			ss.Tenant = w.cfg.SecondaryTenant
		}
		if ss.To.IsZero() {
			ss.To = w.cfg.Cutover
		}
		if w.cfg.SecondaryWriteDoc != nil {
			doc = w.cfg.SecondaryWriteDoc(json.RawMessage(doc))
		}
		h, err := w.secondaryHalf()
		if err != nil {
			return err
		}
		if err := h.Write(ss, doc); err != nil {
			return fmt.Errorf("composite: secondary bulk write: %w", err)
		}
		return nil
	}

	if err := w.primary.Write(s, doc); err != nil {
		return fmt.Errorf("composite: primary bulk write: %w", err)
	}
	return nil
}

// secondaryHolds answers whether a record at time t belongs to the secondary:
// it must be one the secondary serves, before the cutover, and still open.
func (w *splitWriter) secondaryHolds(t time.Time) bool {
	return t.Before(w.cfg.Cutover)
}

func (w *splitWriter) docTime(doc []byte) (time.Time, error) {
	v := gjson.GetBytes(doc, w.cfg.TimeField)
	if !v.Exists() {
		return time.Time{}, catcher.Error("composite: bulk record has no time to route by",
			fmt.Errorf("%q is missing", w.cfg.TimeField), map[string]any{"dataset": w.dataset})
	}
	if t, err := time.Parse(time.RFC3339Nano, v.String()); err == nil {
		return t, nil
	}
	return time.Time{}, catcher.Error("composite: bulk record time does not parse",
		fmt.Errorf("%q = %q is not RFC 3339", w.cfg.TimeField, v.String()),
		map[string]any{"dataset": w.dataset})
}

// runHalf closes or flushes both opened halves at once. The primary's failure
// wins; the secondary's goes through the tolerance policy.
func (w *splitWriter) runHalf(op string, ctx context.Context, fn func(bw store.BulkWriter, ctx context.Context) error) error {
	w.mu.Lock()
	sec := w.secondary
	w.mu.Unlock()

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs = make(map[string]error, 2)
	)
	record := func(name string, err error) {
		if err != nil {
			mu.Lock()
			errs[name] = err
			mu.Unlock()
		}
	}
	wg.Go(func() {
		record("primary", fn(w.primary, ctx))
	})
	if sec != nil {
		wg.Go(func() {
			record("secondary", fn(sec, ctx))
		})
	}
	wg.Wait()

	if pErr, ok := errs["primary"]; ok {
		return pErr
	}
	if lErr, ok := errs["secondary"]; ok {
		if w.cfg.TolerateSecondary {
			if w.cfg.OnSecondaryError != nil {
				w.cfg.OnSecondaryError(op, lErr)
			}
			return nil
		}
		return fmt.Errorf("composite: secondary %s: %w", op, lErr)
	}
	return nil
}

func (w *splitWriter) Flush(ctx context.Context) error {
	return w.runHalf("bulk flush", ctx, func(bw store.BulkWriter, ctx context.Context) error {
		return bw.Flush(ctx)
	})
}

// Close releases both halves' queues.
func (w *splitWriter) Close(ctx context.Context) error {
	return w.runHalf("bulk close", ctx, func(bw store.BulkWriter, ctx context.Context) error {
		return bw.Close(ctx)
	})
}
