package node

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"go.uber.org/zap"

	"github.com/luxfi/threshold/pkg/party"

	"signet/network"
)

// Node owns a libp2p host and an HTTP API server.
type Node struct {
	cfg    *Config
	host   *network.Host
	server *http.Server
	log    *zap.Logger
	ctx    context.Context
	cancel context.CancelFunc
}

// NodeInfo is returned by the /v1/info endpoint.
type NodeInfo struct {
	PeerID          string   `json:"peer_id"`
	EthereumAddress string   `json:"ethereum_address"`
	Addrs           []string `json:"addrs"`
	NodeType        string   `json:"node_type"`
}

// New creates a Node from cfg: loads/generates the secp256k1 key, starts the
// libp2p host, dials bootstrap peers, and wires up the HTTP server.
func New(cfg *Config, log *zap.Logger) (*Node, error) {
	ctx, cancel := context.WithCancel(context.Background())

	if err := os.MkdirAll(filepath.Dir(cfg.KeyFile), 0700); err != nil {
		cancel()
		return nil, fmt.Errorf("create key dir: %w", err)
	}

	h, err := network.NewHostFromFile(ctx, cfg.KeyFile, cfg.ListenAddr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create host: %w", err)
	}

	// Dial each bootstrap peer; connection failures are non-fatal.
	for _, bpStr := range cfg.BootstrapPeers {
		maddr, err := ma.NewMultiaddr(bpStr)
		if err != nil {
			h.Close()
			cancel()
			return nil, fmt.Errorf("parse bootstrap peer %q: %w", bpStr, err)
		}
		pi, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			h.Close()
			cancel()
			return nil, fmt.Errorf("addr info from %q: %w", bpStr, err)
		}
		if err := h.LibP2PHost().Connect(ctx, *pi); err != nil {
			log.Warn("bootstrap peer unreachable", zap.String("peer", pi.ID.String()), zap.Error(err))
			continue
		}
		h.RegisterPeer(party.ID(pi.ID.String()), pi.ID)
		log.Info("connected to bootstrap peer", zap.String("peer", pi.ID.String()))
	}

	n := &Node{cfg: cfg, host: h, log: log, ctx: ctx, cancel: cancel}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", n.handleHealth)
	mux.HandleFunc("GET /v1/info", n.handleInfo)
	n.server = &http.Server{Addr: cfg.APIAddr, Handler: mux}

	return n, nil
}

// Start begins serving the HTTP API in a background goroutine.
func (n *Node) Start() error {
	n.log.Info("starting HTTP API", zap.String("addr", n.cfg.APIAddr))
	go func() {
		if err := n.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			n.log.Error("HTTP server error", zap.Error(err))
		}
	}()
	return nil
}

// Stop gracefully shuts down the HTTP server and the libp2p host.
func (n *Node) Stop() error {
	n.log.Info("stopping node")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := n.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown HTTP server: %w", err)
	}
	n.host.Close()
	n.cancel()
	n.log.Info("node stopped")
	return nil
}

// Info returns the current node information.
func (n *Node) Info() NodeInfo {
	pid := n.host.PeerID()
	pub := n.host.LibP2PHost().Peerstore().PubKey(pid)

	ethAddr := ""
	if pub != nil {
		addr, err := network.EthereumAddress(pub)
		if err == nil {
			ethAddr = "0x" + hex.EncodeToString(addr[:])
		}
	}

	return NodeInfo{
		PeerID:          pid.String(),
		EthereumAddress: ethAddr,
		Addrs:           n.host.Addrs(),
		NodeType:        n.cfg.NodeType,
	}
}

func (n *Node) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func (n *Node) handleInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(n.Info())
}
