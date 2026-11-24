package plugins

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/threatwinds/go-sdk/catcher"
	"github.com/threatwinds/go-sdk/utils"

	"github.com/tidwall/gjson"
	"google.golang.org/protobuf/encoding/protojson"
)

type configSnapshot struct {
	cfg           *Config
	generation    uint64
	pluginCfgJSON map[string]gjson.Result
}

var cfgSnap atomic.Pointer[configSnapshot]
var cfgGen atomic.Uint64
var cfgOnce sync.Once
var cfgMutex sync.Mutex

// ConfigGeneration returns the monotonically increasing configuration reload
// generation (0 before the first load). Callers can cache derived indexes
// (such as pipeline maps or expanded regexps) and refresh only when this value
// changes.
func ConfigGeneration() uint64 {
	if snap := cfgSnap.Load(); snap != nil {
		return snap.generation
	}
	return 0
}

func buildConfigSnapshot(c *Config) *configSnapshot {
	parsed := make(map[string]gjson.Result, len(c.Plugins))
	for name, pConfig := range c.Plugins {
		if pConfig == nil {
			continue
		}
		if bJson, err := ProtoMessageToBytes(pConfig); err == nil && bJson != nil {
			parsed[name] = gjson.ParseBytes(*bJson)
		}
	}
	return &configSnapshot{
		cfg:           c,
		generation:    cfgGen.Add(1),
		pluginCfgJSON: parsed,
	}
}

type fileState struct {
	modTime time.Time
	size    int64
}

var lastFileStates map[string]fileState
var statesMutex sync.RWMutex
var playgroundMode bool

// AcquireLock tries to atomically create the lock file, to prevent race
// conditions when loading or modifying configurations. It returns true if
// the lock was acquired successfully, false otherwise. No longer used by
// this package's own config reload (loadCfg's readers never need it, since
// every writer of these files already writes atomically via temp file +
// rename) — kept as a public utility in case other code still depends on it.
func AcquireLock(processName string) (bool, error) {
	pipelinePath, err := utils.MkdirJoin(WorkDir, "pipeline")

	if err != nil {
		return false, catcher.Error("failed to create pipeline folder", err, map[string]any{
			"process": processName,
		})
	}

	lockPath := pipelinePath.FileJoin(lockFile)

	// O_EXCL makes the create-if-absent check atomic — unlike a separate
	// Stat-then-Create, two callers can't both observe "no lock" and both
	// proceed to create it.
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return false, errors.New("lock file already exists")
		}
		return false, catcher.Error("failed to create lock file", err, map[string]any{
			"lockPath": lockPath,
			"process":  processName,
		})
	}
	defer func() {
		_ = file.Close()
	}()

	// Write process ID to lock file for debugging purposes
	_, err = fmt.Fprintf(file, "%d", os.Getpid())
	if err != nil {
		// Try to remove the lock file if we couldn't write to it
		_ = os.Remove(lockPath)
		return false, catcher.Error("failed to write lock file", err, map[string]any{
			"lockPath": lockPath,
			"process":  processName,
		})
	}

	return true, nil
}

// ReleaseLock releases the lock file.
func ReleaseLock() error {
	lockPath := filepath.Join(WorkDir, "pipeline", lockFile)
	return os.Remove(lockPath)
}

// checkLockTimeout monitors the lock file and removes it if it has been locked
// for more than 1 minute, assuming it's a stale lock from a dead process
func checkLockTimeout(processName string) {
	lockPath := filepath.Join(WorkDir, "pipeline", lockFile)

	// Check if lock file exists
	lockInfo, err := os.Stat(lockPath)
	if os.IsNotExist(err) {
		// No lock file exists, nothing to check
		return
	}
	if err != nil {
		_ = catcher.Error("failed to check lock file status", err, map[string]any{
			"lockPath": lockPath,
			"process":  processName,
		})
		return
	}

	// Check if lock has been held for more than 1 minute
	lockAge := time.Since(lockInfo.ModTime())
	if lockAge < time.Minute {
		// Lock is still fresh, no action needed
		return
	}

	// Lock is older than 1 minute, remove it as it's likely stale
	err = os.Remove(lockPath)
	if err != nil {
		if !os.IsNotExist(err) {
			_ = catcher.Error("failed to remove stale lock file", err, map[string]any{
				"lockPath": lockPath,
				"lockAge":  lockAge.String(),
				"process":  processName,
			})
		}
	}
}

// startLockMonitor starts a goroutine that periodically checks for stale lock files
func startLockMonitor(processName string) {
	go func() {
		ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
		defer ticker.Stop()

		for range ticker.C {
			checkLockTimeout(processName)
		}
	}()
}

// loadCfg loads configuration files from the "pipeline" directory within the working directory.
// It reads all .yaml/.yml files, decodes them into Config objects, and merges their contents into the receiver Config object.
// The function updates the Pipeline, DisabledRules, Tenants, Patterns, and Plugins fields of the receiver Config object.
// If an error occurs while reading or unmarshalling a file, the function logs the error and continues with the next file.
func (c *Config) loadCfg(processName string) {
	pipelineFolder, err := utils.MkdirJoin(WorkDir, "pipeline")
	if err != nil {
		_ = catcher.Error("failed to create pipeline folder", err, map[string]any{
			"dir":     pipelineFolder,
			"process": processName,
		})
		return
	}

	if _, err := os.Stat(pipelineFolder.String()); os.IsNotExist(err) {
		_ = catcher.Error("pipeline folder does not exist", nil, map[string]any{
			"dir":     pipelineFolder,
			"process": processName,
		})
		return
	}

	cFiles := utils.ListFiles(pipelineFolder.String(), ".yaml", ".yml")
	for _, cFile := range cFiles {
		var nCfg = new(Config)
		b, err := utils.ReadPbYaml(cFile)
		if err != nil {
			_ = catcher.Error("failed to read YAML file", err, map[string]any{
				"file":    cFile,
				"process": processName,
			})
			continue
		}

		b = splitDisabledRules(b)

		err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(b, nCfg)
		if err != nil {
			_ = catcher.Error("failed to read YAML file", err, map[string]any{
				"file":    cFile,
				"process": processName,
			})
			continue
		}

		identity := pipelineIdentity(cFile)
		for _, p := range nCfg.Pipeline {
			p.Name = identity
		}
		c.Pipeline = append(c.Pipeline, nCfg.Pipeline...)

		c.DisabledRules = append(c.DisabledRules, nCfg.DisabledRules...)
		c.DisabledRuleNames = append(c.DisabledRuleNames, nCfg.DisabledRuleNames...)

		c.Tenants = append(c.Tenants, nCfg.Tenants...)

		for name, pattern := range nCfg.Patterns {
			c.Patterns[name] = pattern
		}

		for name, plugin := range nCfg.Plugins {
			c.Plugins[name] = plugin
		}
	}

	sortPipelinesByOrder(c.Pipeline, processName)

	c.Env = getEnv()
}

func pipelineIdentity(path string) string {
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func sortPipelinesByOrder(pipelines []*Pipeline, processName string) {
	seen := make(map[string]map[int32]bool)
	for _, p := range pipelines {
		for _, dataType := range p.DataTypes {
			if seen[dataType] == nil {
				seen[dataType] = make(map[int32]bool)
			}
			if seen[dataType][p.Order] {
				_ = catcher.Error("duplicate pipeline order for dataType", errors.New("duplicate pipeline order"), map[string]any{
					"dataType": dataType,
					"order":    p.Order,
					"process":  processName,
				})
			}
			seen[dataType][p.Order] = true
		}
	}

	sort.SliceStable(pipelines, func(i, j int) bool {
		return pipelines[i].Order < pipelines[j].Order
	})
}

// RandomDuration returns a random time.Duration between min and max seconds. It panics if max <= 0.
func RandomDuration(min, max int) time.Duration {
	source := rand.NewSource(time.Now().UnixNano())

	r := rand.New(source)

	randomNumber := r.Intn(max)
	if randomNumber < min {
		randomNumber = min
	}

	return time.Duration(randomNumber) * time.Second
}

// getNewStates returns the current state of configuration files and a boolean
// indicating if the state has changed since the last check.
func getNewStates() (map[string]fileState, bool) {
	pipelineFolder, err := utils.MkdirJoin(WorkDir, "pipeline")
	if err != nil {
		return nil, true
	}

	cFiles := utils.ListFiles(pipelineFolder.String(), ".yaml", ".yml")
	newStates := make(map[string]fileState)

	changed := false
	statesMutex.RLock()
	if lastFileStates == nil || len(lastFileStates) != len(cFiles) {
		changed = true
	}
	statesMutex.RUnlock()

	for _, cFile := range cFiles {
		info, err := os.Stat(cFile)
		if err != nil {
			return nil, true
		}
		state := fileState{modTime: info.ModTime(), size: info.Size()}
		newStates[cFile] = state

		if !changed {
			statesMutex.RLock()
			oldState, ok := lastFileStates[cFile]
			if !ok || !oldState.modTime.Equal(state.modTime) || oldState.size != state.size {
				changed = true
			}
			statesMutex.RUnlock()
		}
	}

	return newStates, changed
}

func updateCfg(processName string) {
	newStates, changed := getNewStates()

	if snap := cfgSnap.Load(); snap != nil && snap.cfg != nil && snap.cfg.Env != nil && !changed {
		return
	}

	cfgMutex.Lock()
	defer cfgMutex.Unlock()

	tmpCfg := new(Config)
	tmpCfg.Plugins = make(map[string]*Value)
	tmpCfg.Patterns = make(map[string]string)
	tmpCfg.loadCfg(processName)

	// Resolve the per-tenant view once per load, not once per event.
	buildPipelineIndex(tmpCfg.Pipeline, tmpCfg.Tenants)

	cfgSnap.Store(buildConfigSnapshot(tmpCfg))

	statesMutex.Lock()
	lastFileStates = newStates
	statesMutex.Unlock()
}

// GetCfg initializes the configuration if it hasn't been initialized yet,
// and starts a goroutine to periodically update the configuration every 60 seconds.
// It waits for the initial configuration to be set before returning it.
// The function returns an immutable snapshot pointer to the Config struct.
func GetCfg(processName string) *Config {
	cfgOnce.Do(func() {
		playgroundMode = os.Getenv("MODE") == "playground"

		// Not used by our own reload path anymore, but kept running so any
		// external caller of AcquireLock/ReleaseLock still gets automatic
		// stale-lock cleanup, exactly as before.
		startLockMonitor(processName)

		updateCfg(processName)

		go func() {
			for {
				time.Sleep(60 * time.Second)
				updateCfg(processName)
			}
		}()
	})

	if playgroundMode {
		updateCfg(processName)
	}

	for {
		if snap := cfgSnap.Load(); snap != nil && snap.cfg != nil && snap.cfg.Env != nil {
			return snap.cfg
		}
		time.Sleep(1 * time.Second)
	}
}

// PluginCfg retrieves the pre-parsed JSON configuration for a specified plugin
// by name from the current immutable config snapshot with zero per-call
// protobuf/JSON marshaling.
func PluginCfg(pluginName string) gjson.Result {
	_ = GetCfg(fmt.Sprintf("plugin_%s", pluginName))
	snap := cfgSnap.Load()
	if snap == nil || snap.pluginCfgJSON == nil {
		return gjson.Result{}
	}
	return snap.pluginCfgJSON[pluginName]
}
