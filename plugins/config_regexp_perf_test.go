package plugins

import (
	"sync"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
)

func TestRegexpCacheLiteralFastPathWithoutConfig(t *testing.T) {
	var cache RegexpCache
	re1, err := cache.Get(`^user=(?P<user>\w+)$`)
	if err != nil {
		t.Fatalf("Get literal failed: %v", err)
	}
	re2, err := cache.Get(`^user=(?P<user>\w+)$`)
	if err != nil {
		t.Fatalf("second Get literal failed: %v", err)
	}
	if re1 != re2 {
		t.Fatalf("expected cached *regexp.Regexp pointer reuse")
	}
	if !re1.MatchString("user=alice") {
		t.Fatalf("compiled regexp failed to match")
	}
}

func TestConfigSnapshotImmutableGenerationAndPreParsedPlugins(t *testing.T) {
	prevSnap := cfgSnap.Load()
	t.Cleanup(func() { cfgSnap.Store(prevSnap) })

	val1, err := structpb.NewValue(map[string]any{"enabled": true, "allowlist": []any{"192.0.2.1"}})
	if err != nil {
		t.Fatalf("NewValue: %v", err)
	}
	c1 := &Config{
		Env:      &Env{},
		Patterns: map[string]string{"WORD": `\w+`},
		Plugins:  map[string]*Value{"feeds": val1},
	}
	s1 := buildConfigSnapshot(c1)
	cfgSnap.Store(s1)
	gen1 := ConfigGeneration()
	if gen1 == 0 {
		t.Fatalf("expected non-zero generation")
	}
	if !s1.pluginCfgJSON["feeds"].Get("enabled").Bool() {
		t.Fatalf("expected pre-parsed feeds.enabled=true")
	}
	if got := s1.pluginCfgJSON["feeds"].Get("allowlist.0").String(); got != "192.0.2.1" {
		t.Fatalf("allowlist.0 = %q, want 192.0.2.1", got)
	}

	val2, _ := structpb.NewValue(map[string]any{"enabled": false})
	c2 := &Config{
		Env:      &Env{},
		Patterns: map[string]string{"WORD": `[0-9]+`},
		Plugins:  map[string]*Value{"feeds": val2},
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				snap := cfgSnap.Load()
				_ = snap.cfg.Patterns["WORD"]
				_ = snap.pluginCfgJSON["feeds"].Get("enabled").Bool()
			}
		}()
	}
	cfgSnap.Store(buildConfigSnapshot(c2))
	wg.Wait()

	if ConfigGeneration() <= gen1 {
		t.Fatalf("expected generation to advance on reload: %d <= %d", ConfigGeneration(), gen1)
	}
	if cfgSnap.Load().cfg == c1 {
		t.Fatalf("expected new immutable *Config pointer after reload")
	}
}
