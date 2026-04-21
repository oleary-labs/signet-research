package node

import (
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
)

// debugStats is the response from GET /debug/stats.
type debugStats struct {
	// Go runtime
	Goroutines int    `json:"goroutines"`
	HeapMB     float64 `json:"heap_mb"`
	StackMB    float64 `json:"stack_mb"`
	SysMB      float64 `json:"sys_mb"`
	NumGC      uint32 `json:"num_gc"`

	// Process
	OpenFDs int    `json:"open_fds"`
	Uptime  string `json:"uptime"`

	// libp2p
	PeerCount       int `json:"peer_count"`
	ConnectionCount int `json:"connection_count"`
	StreamCount     int `json:"stream_count"`

	// Per-direction stream breakdown
	InboundStreams  int `json:"inbound_streams"`
	OutboundStreams int `json:"outbound_streams"`

	// Per-peer connection details (optional, only if few peers)
	Peers []peerInfo `json:"peers,omitempty"`
}

type peerInfo struct {
	PeerID      string `json:"peer_id"`
	Connections int    `json:"connections"`
	Streams     int    `json:"streams"`
	Direction   string `json:"direction"` // inbound or outbound
}

// handleDebugStats returns runtime, process, and libp2p diagnostics.
func (n *Node) handleDebugStats(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	h := n.host.LibP2PHost()

	// Count connections and streams.
	var totalConns, totalStreams, inStreams, outStreams int
	var peers []peerInfo

	for _, pid := range h.Network().Peers() {
		conns := h.Network().ConnsToPeer(pid)
		peerConns := len(conns)
		peerStreams := 0
		dir := "unknown"

		for _, conn := range conns {
			streams := conn.GetStreams()
			peerStreams += len(streams)
			for _, s := range streams {
				if s.Stat().Direction == network.DirInbound {
					inStreams++
				} else {
					outStreams++
				}
			}
			if conn.Stat().Direction == network.DirInbound {
				dir = "inbound"
			} else {
				dir = "outbound"
			}
		}
		totalConns += peerConns
		totalStreams += peerStreams

		peers = append(peers, peerInfo{
			PeerID:      pid.String(),
			Connections: peerConns,
			Streams:     peerStreams,
			Direction:   dir,
		})
	}

	stats := debugStats{
		Goroutines: runtime.NumGoroutine(),
		HeapMB:     float64(m.HeapAlloc) / 1024 / 1024,
		StackMB:    float64(m.StackInuse) / 1024 / 1024,
		SysMB:      float64(m.Sys) / 1024 / 1024,
		NumGC:      m.NumGC,

		OpenFDs: countOpenFDs(),
		Uptime:  time.Since(n.startTime).Round(time.Second).String(),

		PeerCount:       len(h.Network().Peers()),
		ConnectionCount: totalConns,
		StreamCount:     totalStreams,
		InboundStreams:   inStreams,
		OutboundStreams:  outStreams,

		Peers: peers,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// countOpenFDs returns the number of open file descriptors for this process.
// Returns -1 on platforms where neither /proc/self/fd nor /dev/fd is available.
func countOpenFDs() int {
	// Linux
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		return len(entries)
	}
	// macOS / BSD
	if entries, err := os.ReadDir("/dev/fd"); err == nil {
		return len(entries)
	}
	return -1
}
