package metrics

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const defaultMetricsPath = "/run/platform-sync/metrics.prom"

type state struct {
	Counts       map[string]uint64 `json:"counts"`
	LastDuration float64           `json:"lastDurationSeconds"`
	LastInputs   int               `json:"lastInputsWritten"`
	LastRun      time.Time         `json:"lastRun"`
}

type Recorder struct {
	mu        sync.Mutex
	start     time.Time
	path      string
	statePath string
	state     state
}

func NewRecorder() *Recorder {
	path := strings.TrimSpace(os.Getenv("SYNC_METRICS_PATH"))
	if path == "" {
		path = defaultMetricsPath
	}
	recorder := &Recorder{
		path:      path,
		statePath: path + ".json",
		state:     state{Counts: make(map[string]uint64)},
	}
	data, err := os.ReadFile(recorder.statePath) // #nosec G703 -- operator-configured local state path
	if err == nil {
		var previous state
		if json.Unmarshal(data, &previous) == nil {
			recorder.state = previous
			if recorder.state.Counts == nil {
				recorder.state.Counts = make(map[string]uint64)
			}
		}
	}
	return recorder
}

func (r *Recorder) SetRunStart(start time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.start = start
}

func (r *Recorder) RecordRun(result string, inputsWritten int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state.Counts[result]++
	r.state.LastInputs = inputsWritten
	r.state.LastRun = time.Now().UTC()
	if !r.start.IsZero() {
		r.state.LastDuration = time.Since(r.start).Seconds()
	}
	return r.persist()
}

func (r *Recorder) persist() error {
	stateData, err := json.Marshal(r.state)
	if err != nil {
		return err
	}
	if err := writeAtomic(r.statePath, stateData); err != nil {
		return err
	}
	results := make([]string, 0, len(r.state.Counts))
	for result := range r.state.Counts {
		results = append(results, result)
	}
	sort.Strings(results)
	var output strings.Builder
	output.WriteString("# HELP platform_sync_runs_total Completed platform sync runs by result.\n")
	output.WriteString("# TYPE platform_sync_runs_total counter\n")
	for _, result := range results {
		fmt.Fprintf(&output, "platform_sync_runs_total{result=%q} %d\n", result, r.state.Counts[result])
	}
	output.WriteString("# HELP platform_sync_last_run_duration_seconds Duration of the most recent run.\n")
	output.WriteString("# TYPE platform_sync_last_run_duration_seconds gauge\n")
	fmt.Fprintf(&output, "platform_sync_last_run_duration_seconds %.6f\n", r.state.LastDuration)
	output.WriteString("# HELP platform_sync_last_inputs_written Inputs written by the most recent run.\n")
	output.WriteString("# TYPE platform_sync_last_inputs_written gauge\n")
	fmt.Fprintf(&output, "platform_sync_last_inputs_written %d\n", r.state.LastInputs)
	output.WriteString("# HELP platform_sync_last_run_timestamp_seconds Unix timestamp of the most recent completed run.\n")
	output.WriteString("# TYPE platform_sync_last_run_timestamp_seconds gauge\n")
	fmt.Fprintf(&output, "platform_sync_last_run_timestamp_seconds %d\n", r.state.LastRun.Unix())
	return writeAtomic(r.path, []byte(output.String()))
}

func writeAtomic(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".metrics-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() {
		_ = os.Remove(tempName) //nolint:errcheck // Best-effort cleanup after rename.
	}()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close() //nolint:errcheck // Preserve the primary failure.
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close() //nolint:errcheck // Preserve the primary failure.
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, path)
}
