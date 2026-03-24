package metrics

import (
	"sort"
	"sync"
	"time"
)

// Op records the outcome of a single operation.
type Op struct {
	Scenario  string
	Operation string // "keygen" or "sign"
	StartedAt time.Time
	Latency   time.Duration
	OK        bool
	ErrMsg    string
}

// Collector accumulates Op records from concurrent workers.
type Collector struct {
	mu  sync.Mutex
	ops []Op
}

// Record appends an Op.
func (c *Collector) Record(op Op) {
	c.mu.Lock()
	c.ops = append(c.ops, op)
	c.mu.Unlock()
}

// All returns a copy of all recorded ops.
func (c *Collector) All() []Op {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Op, len(c.ops))
	copy(out, c.ops)
	return out
}

// Summary computes aggregate statistics over all ops matching the scenario.
type Summary struct {
	Scenario   string
	Operation  string
	Total      int
	Successes  int
	Errors     int
	Throughput float64 // ops/sec
	P50        time.Duration
	P95        time.Duration
	P99        time.Duration
	Duration   time.Duration
}

// Summarise computes a Summary for ops matching scenario and operation.
func (c *Collector) Summarise(scenario, operation string, elapsed time.Duration) Summary {
	c.mu.Lock()
	defer c.mu.Unlock()

	var latencies []time.Duration
	var errs int
	for _, op := range c.ops {
		if op.Scenario != scenario || op.Operation != operation {
			continue
		}
		if op.OK {
			latencies = append(latencies, op.Latency)
		} else {
			errs++
		}
	}

	total := len(latencies) + errs
	s := Summary{
		Scenario:  scenario,
		Operation: operation,
		Total:     total,
		Successes: len(latencies),
		Errors:    errs,
		Duration:  elapsed,
	}
	if elapsed > 0 {
		s.Throughput = float64(total) / elapsed.Seconds()
	}
	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		s.P50 = percentile(latencies, 50)
		s.P95 = percentile(latencies, 95)
		s.P99 = percentile(latencies, 99)
	}
	return s
}

func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := (p * len(sorted)) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
