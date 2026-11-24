package plugins

import (
	"strings"
	"sync"
	"testing"
)

func TestCELCacheFastPathSkipsJSONUnmarshal(t *testing.T) {
	c := NewCELCache("test-fastpath")
	raw := `{"dataType":"aws","actionResult":"success","event":{"action":"AssumeRole","ip":"192.0.2.10"}}`

	act, err := c.PrepareActivation(&raw)
	if err != nil {
		t.Fatalf("PrepareActivation: %v", err)
	}
	if act.valuesMap != nil {
		t.Fatalf("expected nil valuesMap before fallback (lazy unmarshal)")
	}

	ok, err := c.EvalWithActivation(`equals("event.action","AssumeRole") && inCIDR("event.ip","192.0.2.0/24")`, act)
	if err != nil || !ok {
		t.Fatalf("fast path eval = (%v, %v), want (true, nil)", ok, err)
	}
	if act.valuesMap != nil {
		t.Fatalf("fast-path expression unexpectedly triggered JSON unmarshal")
	}

	// Fallback expression referencing top-level variable lazily initializes valuesMap once.
	ok2, err := c.EvalWithActivation(`actionResult == "success" && dataType == "aws"`, act)
	if err != nil || !ok2 {
		t.Fatalf("fallback eval = (%v, %v), want (true, nil)", ok2, err)
	}
	if act.valuesMap == nil {
		t.Fatalf("expected valuesMap populated after fallback evaluation")
	}
}

func TestCELCachePrecompileAndLegacyFallback(t *testing.T) {
	c := NewCELCache("test-precompile")

	if err := c.Precompile(`equals("dataType","wineventlog")`); err != nil {
		t.Fatalf("Precompile fast expr failed: %v", err)
	}
	// Legacy top-level variable expression must be recorded as needsFallback without error.
	if err := c.Precompile(`dataType == "meraki" && actionResult == "success"`); err != nil {
		t.Fatalf("Precompile legacy expr failed: %v", err)
	}

	v, ok := c.fastCache.Load(`dataType == "meraki" && actionResult == "success"`)
	if !ok || !v.(*fastCacheEntry).needsFallback {
		t.Fatalf("expected legacy expr cached with needsFallback=true")
	}

	raw := `{"dataType":"meraki","actionResult":"success"}`
	got, err := c.Eval(`dataType == "meraki" && actionResult == "success"`, &raw)
	if err != nil || !got {
		t.Fatalf("Eval legacy expr = (%v, %v), want (true, nil)", got, err)
	}
}

func TestCELCacheConcurrentFastAndFallbackRace(t *testing.T) {
	c := NewCELCache("test-race")
	raw := `{"dataType":"aws","actionResult":"success","event":{"action":"AssumeRole"}}`
	act, err := c.PrepareActivation(&raw)
	if err != nil {
		t.Fatalf("PrepareActivation: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				ok, err := c.EvalWithActivation(`equals("event.action","AssumeRole")`, act)
				if err != nil || !ok {
					t.Errorf("fast eval failed: %v, %v", ok, err)
				}
				ok2, err := c.EvalWithActivation(`actionResult == "success"`, act)
				if err != nil || !ok2 {
					t.Errorf("fallback eval failed: %v, %v", ok2, err)
				}
			}
		}()
	}
	wg.Wait()
}

func TestCELCacheInvalidJSONAndEmptyDataErrors(t *testing.T) {
	c := NewCELCache("test-errors")
	if _, err := c.Eval(`equals("a","b")`, nil); err == nil {
		t.Fatalf("expected error on nil data")
	}
	bad := `{not-json`
	if _, err := c.Eval(`equals("a","b")`, &bad); err == nil {
		t.Fatalf("expected error on malformed JSON")
	}
	good := `{"a":"b"}`
	if _, err := c.Eval(``, &good); err == nil {
		t.Fatalf("expected error on empty expression")
	}
	if _, err := c.Eval(`1 / 0 == 1`, &good); err == nil || !strings.Contains(err.Error(), "failed to evaluate program") {
		t.Fatalf("expected 'failed to evaluate program' error contract, got: %v", err)
	}
}
