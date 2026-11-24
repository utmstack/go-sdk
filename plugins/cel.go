package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/interpreter"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/threatwinds/go-sdk/catcher"
	"github.com/threatwinds/go-sdk/utils"
	"github.com/tidwall/gjson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const fastCacheMaxEntries = 8192

type fastCacheEntry struct {
	prg           cel.Program
	needsFallback bool
}

// dataOnlyActivation implements interpreter.Activation exposing only `_data_`
// without allocating a map[string]any per evaluation.
type dataOnlyActivation struct {
	data string
}

func (a *dataOnlyActivation) ResolveName(name string) (any, bool) {
	if name == "_data_" {
		return a.data, true
	}
	return nil, false
}

func (a *dataOnlyActivation) Parent() interpreter.Activation { return nil }

// CELCache provides a thread-safe cache for compiled CEL (Common Expression Language) programs.
// Expressions that only reference `_data_` (all string-keyed overloads such as equals, contains,
// exists, inCIDR, regexMatch, safe, etc.) compile once against a singleton baseEnv and run via a
// bounded concurrent sync.Map fast path with zero JSON unmarshaling, zero map allocation, and
// zero LRU lock contention. Expressions that reference top-level variables fall back transparently
// to a variable-typed LRU cache.
type CELCache struct {
	baseEnvOnce sync.Once
	baseEnv     *cel.Env
	baseEnvErr  error

	fastCache      sync.Map // raw expression -> *fastCacheEntry
	fastCacheCount atomic.Int64
	fastResetMu    sync.Mutex

	cache       *expirable.LRU[string, *cachedProgram]
	once        sync.Once
	locks       [1024]sync.Mutex
	processName string
}

// CELActivation holds the evaluation context for an event.
// On the fast path (expressions using only `_data_` string-keyed overloads),
// PrepareActivation performs zero json.Unmarshal and zero map allocation.
// If any expression evaluated against the activation requires top-level
// variables, the values map and keyMaterial are computed lazily once and reused
// for subsequent fallback evaluations on the same event.
type CELActivation struct {
	jsonData string
	dataAct  dataOnlyActivation

	fallbackOnce sync.Once
	valuesMap    map[string]interface{}
	keyMat       string
	fallbackErr  error
}

// NewCELCache creates and returns a new instance of CELCache for the specified process.
func NewCELCache(processName string) *CELCache {
	return &CELCache{
		processName: processName,
	}
}

func (c *CELCache) getLock(key string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &c.locks[h.Sum32()%1024]
}

func (c *CELCache) baseEnvOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Variable("_data_", cel.StringType),
		c.celExists(),
		c.safe(),
		c.inCIDR(),
		c.equals(),
		c.equalsIgnoreCase(),
		c.contains(),
		c.containsAll(),
		c.oneOf(),
		c.startsWith(),
		c.endsWith(),
		c.regexMatch(),
		c.lessThan(),
		c.greaterThan(),
		c.lessOrEqual(),
		c.greaterOrEqual(),
		c.isHour(),
		c.isMinute(),
		c.isDayOfWeek(),
		c.isWeekend(),
		c.isWorkDay(),
		c.isBetweenTime(),
	}
}

func (c *CELCache) getBaseEnv() (*cel.Env, error) {
	c.baseEnvOnce.Do(func() {
		c.baseEnv, c.baseEnvErr = cel.NewEnv(c.baseEnvOptions()...)
	})
	return c.baseEnv, c.baseEnvErr
}

func (c *CELCache) storeFastEntry(expr string, entry *fastCacheEntry) {
	if _, loaded := c.fastCache.LoadOrStore(expr, entry); loaded {
		return
	}
	if c.fastCacheCount.Add(1) > fastCacheMaxEntries {
		c.fastResetMu.Lock()
		if c.fastCacheCount.Load() > fastCacheMaxEntries {
			c.fastCache.Range(func(k, _ any) bool {
				c.fastCache.Delete(k)
				return true
			})
			c.fastCacheCount.Store(0)
			c.fastCache.Store(expr, entry)
			c.fastCacheCount.Store(1)
		}
		c.fastResetMu.Unlock()
	}
}

// compileFast attempts to resolve or compile expression against the singleton
// `_data_`-only baseEnv. Returns (prg, true, nil) when the expression runs on
// the fast path, or (nil, false, nil) when it requires top-level variables (or
// has a compile error that the fallback path reports with full context).
func (c *CELCache) compileFast(expression string) (cel.Program, bool, error) {
	if expression == "" {
		return nil, false, nil
	}
	if v, ok := c.fastCache.Load(expression); ok {
		entry := v.(*fastCacheEntry)
		if entry.needsFallback {
			return nil, false, nil
		}
		return entry.prg, true, nil
	}

	lock := c.getLock(expression)
	lock.Lock()
	defer lock.Unlock()

	if v, ok := c.fastCache.Load(expression); ok {
		entry := v.(*fastCacheEntry)
		if entry.needsFallback {
			return nil, false, nil
		}
		return entry.prg, true, nil
	}

	env, err := c.getBaseEnv()
	if err != nil {
		return nil, false, catcher.Error("failed to start CEL environment", err, map[string]any{})
	}

	transformedExpr := c.transformExpression(expression)
	ast, issues := env.Compile(transformedExpr)
	if issues != nil && issues.Err() != nil {
		c.storeFastEntry(expression, &fastCacheEntry{needsFallback: true})
		return nil, false, nil
	}

	prg, err := env.Program(ast)
	if err != nil {
		c.storeFastEntry(expression, &fastCacheEntry{needsFallback: true})
		return nil, false, nil
	}

	c.storeFastEntry(expression, &fastCacheEntry{prg: prg})
	return prg, true, nil
}

// Precompile warms the fast-path cache for an expression (e.g. during rule
// loading). Expressions requiring top-level variables are recorded as fallback
// without returning an error so startup never fails on legacy rules.
func (c *CELCache) Precompile(expression string) error {
	_, _, err := c.compileFast(expression)
	return err
}

// Get retrieves a compiled CEL program from the variable-typed LRU cache or
// compiles it if not present. It then executes the program with valuesMap.
func (c *CELCache) Get(cacheKey string, expression string, valuesMap map[string]interface{}, envOption ...cel.EnvOption) (bool, error) {
	c.once.Do(func() {
		c.cache = expirable.NewLRU[string, *cachedProgram](10000, nil, time.Hour*24)
	})

	if cp, ok := c.cache.Get(cacheKey); ok {
		return c.execute(cp.prg, valuesMap)
	}

	// Use a sharded lock to prevent multiple simultaneous compilations of the same expression
	lock := c.getLock(cacheKey)
	lock.Lock()
	defer lock.Unlock()

	// Double-check the cache after acquiring the lock
	if cp, ok := c.cache.Get(cacheKey); ok {
		return c.execute(cp.prg, valuesMap)
	}

	envOptions := c.baseEnvOptions()

	// Add the provided environment options (including cel.Types)
	envOptions = append(envOptions, envOption...)

	for k, v := range valuesMap {
		if k == "_data_" {
			continue
		}
		envOptions = append(envOptions, cel.Variable(k, c.valueToCelType(v)))
	}

	celEnv, err := cel.NewEnv(envOptions...)
	if err != nil {
		return false, catcher.Error("failed to start CEL environment", err, map[string]any{})
	}

	transformedExpr := c.transformExpression(expression)
	ast, issues := celEnv.Compile(transformedExpr)
	if issues != nil && issues.Err() != nil {
		return false, catcher.Error("failed to compile expression", errors.New("consult issues list for more information"), map[string]any{
			"issues":     issues.Errors(),
			"process":    c.processName,
			"expression": expression,
		})
	}

	prg, err := celEnv.Program(ast)
	if err != nil {
		return false, catcher.Error("failed to create program", err, map[string]any{
			"process":    c.processName,
			"expression": expression,
		})
	}

	// Store only the compiled program; do not retain *cel.Env in the LRU heap.
	c.cache.Add(cacheKey, &cachedProgram{prg: prg})

	return c.execute(prg, valuesMap)
}

var rCache = new(RegexpCache)

type cachedProgram struct {
	prg cel.Program
}

// keyMaterial is the sorted "key:Type" join of a values map, used to key the compiled
// program cache. The env declares a variable per top-level key, so the cache must be
// keyed by which keys (and their types) are present — not by their values.
func keyMaterial(valuesMap map[string]interface{}) string {
	keys := make([]string, 0, len(valuesMap))
	for k, v := range valuesMap {
		if k == "_data_" {
			continue
		}
		keys = append(keys, fmt.Sprintf("%s:%T", k, v))
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

func (c *CELCache) getCacheKey(expression, keyMat string) string {
	hash := sha256.New()
	hash.Write([]byte(expression))
	hash.Write([]byte(keyMat))
	return hex.EncodeToString(hash.Sum(nil))
}

func (c *CELCache) transformExpression(expression string) string {
	overloads := []string{
		"exists", "safe", "inCIDR", "equals", "equalsIgnoreCase", "contains",
		"containsAll", "oneOf", "startsWith", "endsWith", "regexMatch",
		"lessThan", "greaterThan", "lessOrEqual", "greaterOrEqual",
		"isHour", "isMinute", "isDayOfWeek", "isWeekend", "isWorkDay", "isBetweenTime",
	}

	for _, f := range overloads {
		oldCall := f + "("
		newCall := f + "(_data_,"
		if strings.Contains(expression, oldCall) {
			expression = strings.ReplaceAll(expression, oldCall, newCall)
		}
	}
	return expression
}

func (a *CELActivation) ensureFallback(processName string) (map[string]interface{}, string, error) {
	a.fallbackOnce.Do(func() {
		if a.valuesMap == nil {
			var m map[string]interface{}
			if err := json.Unmarshal([]byte(a.jsonData), &m); err != nil {
				a.fallbackErr = catcher.Error("failed to unmarshal JSON data", err, map[string]any{
					"process": processName,
				})
				return
			}
			if m == nil {
				m = make(map[string]interface{})
			}
			a.valuesMap = m
		}
		a.keyMat = keyMaterial(a.valuesMap)
		a.valuesMap["_data_"] = a.jsonData
	})
	return a.valuesMap, a.keyMat, a.fallbackErr
}

// Eval evaluates a CEL expression against the provided data.
// The data can be a proto.Message, JSON string, *string, map[string]interface{}, or any struct.
func (c *CELCache) Eval(expression string, data any, envOption ...cel.EnvOption) (bool, error) {
	act, err := c.PrepareActivation(data)
	if err != nil {
		return false, err
	}
	return c.EvalWithActivation(expression, act, envOption...)
}

// PrepareActivation builds a reusable activation for an event.
// For string, *string, and proto.Message inputs, it avoids json.Unmarshal and
// map[string]interface{} allocation entirely unless an evaluated expression
// requires top-level variables.
func (c *CELCache) PrepareActivation(data any) (*CELActivation, error) {
	if data == nil {
		return nil, catcher.Error("failed to evaluate CEL expression", errors.New("required parameter 'data' is nil"), map[string]any{
			"process": c.processName,
		})
	}

	var valuesMap map[string]interface{}
	var jsonData string

	switch v := data.(type) {
	case proto.Message:
		jsonPtr, err := utils.ProtoMessageToString(v)
		if err != nil {
			return nil, catcher.Error("failed to convert proto to string for CEL evaluation", err, map[string]any{
				"process": c.processName,
			})
		}
		jsonData = *jsonPtr
	case *string:
		if v == nil {
			return nil, catcher.Error("failed to evaluate CEL expression", errors.New("data pointer is nil"), map[string]any{
				"process": c.processName,
			})
		}
		jsonData = *v
		if !gjson.Valid(jsonData) {
			return nil, catcher.Error("failed to unmarshal JSON data", errors.New("invalid JSON input"), map[string]any{
				"process": c.processName,
			})
		}
	case string:
		jsonData = v
		if !gjson.Valid(jsonData) {
			return nil, catcher.Error("failed to unmarshal JSON data", errors.New("invalid JSON input"), map[string]any{
				"process": c.processName,
			})
		}
	case map[string]interface{}:
		valuesMap = v
		b, _ := json.Marshal(v)
		jsonData = string(b)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, catcher.Error("failed to marshal data to JSON", err, map[string]any{
				"process": c.processName,
			})
		}
		jsonData = string(b)
	}

	return &CELActivation{
		jsonData:  jsonData,
		dataAct:   dataOnlyActivation{data: jsonData},
		valuesMap: valuesMap,
	}, nil
}

// EvalWithActivation evaluates expression against a pre-prepared activation.
// When envOption is empty and expression only uses `_data_` string-keyed
// overloads, it runs on the zero-unmarshal fast path; otherwise it lazily
// prepares the values map once and evaluates against the variable-typed cache.
func (c *CELCache) EvalWithActivation(expression string, act *CELActivation, envOption ...cel.EnvOption) (bool, error) {
	if act == nil {
		return false, catcher.Error("failed to evaluate CEL expression", errors.New("activation is nil"), map[string]any{
			"process": c.processName,
		})
	}

	if len(envOption) == 0 {
		prg, ok, err := c.compileFast(expression)
		if err != nil {
			return false, err
		}
		if ok {
			return c.executeActivation(prg, &act.dataAct)
		}
	}

	valuesMap, keyMat, err := act.ensureFallback(c.processName)
	if err != nil {
		return false, err
	}

	cacheKey := c.getCacheKey(expression, keyMat)
	return c.Get(cacheKey, expression, valuesMap, envOption...)
}

// Evaluate is a wrapper around Eval for backward compatibility.
// Note: It uses (data, expression) order while Eval uses (expression, data).
func (c *CELCache) Evaluate(data *string, expression string, envOption ...cel.EnvOption) (bool, error) {
	return c.Eval(expression, data, envOption...)
}

// executeActivation evaluates a compiled program with an interpreter.Activation,
// preserving the exact "failed to evaluate program" error message contract.
func (c *CELCache) executeActivation(prg cel.Program, act interpreter.Activation) (bool, error) {
	out, details, err := prg.Eval(act)
	if err != nil {
		return false, catcher.Error("failed to evaluate program", err, map[string]any{
			"details": details,
			"process": c.processName,
		})
	}

	if out.Type() == cel.BoolType {
		return out.Value().(bool), nil
	}

	return false, nil
}

// execute is the internal method that performs the actual CEL program evaluation.
func (c *CELCache) execute(prg cel.Program, valuesMap map[string]interface{}) (bool, error) {
	out, details, err := prg.Eval(valuesMap)
	if err != nil {
		return false, catcher.Error("failed to evaluate program", err, map[string]any{
			"details": details,
			"process": c.processName,
		})
	}

	if out.Type() == cel.BoolType {
		return out.Value().(bool), nil
	}

	return false, nil
}

func (c *CELCache) valueToCelType(value interface{}) *cel.Type {
	switch value.(type) {
	case bool:
		return cel.BoolType
	case string:
		return cel.StringType
	case int, int32, int64:
		return cel.IntType
	case uint, uint32, uint64:
		return cel.UintType
	case float32, float64:
		return cel.DoubleType
	case []byte:
		return cel.BytesType
	case time.Time:
		return cel.TimestampType
	case map[string]interface{}:
		return cel.MapType(cel.StringType, cel.DynType)
	case map[string]*structpb.Value:
		return cel.MapType(cel.StringType, cel.DynType)
	case []interface{}:
		return cel.ListType(cel.DynType)
	case nil:
		return cel.NullType
	case proto.Message:
		return cel.DynType
	default:
		t := reflect.TypeOf(value)
		return cel.ObjectType(t.String())
	}
}
