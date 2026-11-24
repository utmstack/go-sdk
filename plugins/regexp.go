package plugins

import (
	"bytes"
	"hash/fnv"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// RegexpCache provides a thread-safe cache for compiled regular expressions.
// Literal patterns (without "{{") bypass config/template lookup completely.
// Template patterns are cached by raw pattern string before text/template
// expansion and invalidated automatically when the configuration generation
// advances.
type RegexpCache struct {
	literalCache  sync.Map // raw pattern (no "{{") -> *regexp.Regexp
	templateCache sync.Map // raw template pattern -> *regexp.Regexp
	templateGen   atomic.Uint64
	templateMu    sync.Mutex

	cache *expirable.LRU[string, *regexp.Regexp]
	once  sync.Once
	locks [1024]sync.Mutex
}

func (c *RegexpCache) getLock(key string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &c.locks[h.Sum32()%1024]
}

// Get retrieves a compiled regular expression from the cache.
// If the pattern is not cached, it is compiled and added to the cache.
// Patterns containing "{{ ... }}" markers are expanded using global patterns
// from configuration and cached by raw pattern until config reloads.
func (c *RegexpCache) Get(pattern string) (*regexp.Regexp, error) {
	// Fast path: patterns without template markers never touch GetCfg or text/template.
	if !strings.Contains(pattern, "{{") {
		if v, ok := c.literalCache.Load(pattern); ok {
			return v.(*regexp.Regexp), nil
		}
		lock := c.getLock(pattern)
		lock.Lock()
		defer lock.Unlock()
		if v, ok := c.literalCache.Load(pattern); ok {
			return v.(*regexp.Regexp), nil
		}
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		c.literalCache.Store(pattern, compiled)
		return compiled, nil
	}

	// Template path: invalidate raw-pattern cache when config generation changes.
	currentCfg := GetCfg("regexp")
	gen := ConfigGeneration()
	if c.templateGen.Load() == gen {
		if v, ok := c.templateCache.Load(pattern); ok {
			return v.(*regexp.Regexp), nil
		}
	} else {
		c.templateMu.Lock()
		if c.templateGen.Load() != gen {
			c.templateCache.Range(func(k, _ any) bool {
				c.templateCache.Delete(k)
				return true
			})
			c.templateGen.Store(gen)
		}
		c.templateMu.Unlock()
	}

	c.once.Do(func() {
		c.cache = expirable.NewLRU[string, *regexp.Regexp](10000, nil, time.Hour*24)
	})

	finalPattern := pattern
	maxDepth := 10
	if currentCfg != nil && len(currentCfg.Patterns) > 0 {
		for i := 0; i < maxDepth && strings.Contains(finalPattern, "{{"); i++ {
			t, err := template.New("pattern").Parse(finalPattern)
			if err != nil {
				break
			}
			var output bytes.Buffer
			if err := t.Execute(&output, currentCfg.Patterns); err != nil {
				break
			}
			newPattern := output.String()
			if newPattern == finalPattern {
				break
			}
			finalPattern = newPattern
		}
	}

	if compiledPattern, ok := c.cache.Get(finalPattern); ok {
		if c.templateGen.Load() == gen {
			c.templateCache.Store(pattern, compiledPattern)
		}
		return compiledPattern, nil
	}

	lock := c.getLock(finalPattern)
	lock.Lock()
	defer lock.Unlock()

	if compiledPattern, ok := c.cache.Get(finalPattern); ok {
		if c.templateGen.Load() == gen {
			c.templateCache.Store(pattern, compiledPattern)
		}
		return compiledPattern, nil
	}

	compiledPattern, err := regexp.Compile(finalPattern)
	if err != nil {
		return nil, err
	}

	c.cache.Add(finalPattern, compiledPattern)
	if c.templateGen.Load() == gen {
		c.templateCache.Store(pattern, compiledPattern)
	}

	return compiledPattern, nil
}
