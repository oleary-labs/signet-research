package node

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"go.uber.org/zap"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/protocols/lss"

	"signet/network"
)

// Node owns a libp2p host, an HTTP API server, and threshold signing state.
type Node struct {
	cfg    *Config
	host   *network.Host
	server *http.Server
	log    *zap.Logger
	ctx    context.Context
	cancel context.CancelFunc

	pool    *pool.Pool
	store   *KeyShardStore
	mu      sync.RWMutex
	configs map[string]*lss.Config // in-memory cache: keygen session ID → key config
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

	if _, err := os.Stat(cfg.DataDir); err != nil {
		cancel()
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("data directory does not exist: %s", cfg.DataDir)
		}
		return nil, fmt.Errorf("stat data dir: %w", err)
	}

	keyFile := filepath.Join(cfg.DataDir, "node.key")
	h, err := network.NewHostFromFile(ctx, keyFile, cfg.ListenAddr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create host: %w", err)
	}

	store, err := openKeyShardStore(cfg.DataDir)
	if err != nil {
		h.Close()
		cancel()
		return nil, fmt.Errorf("open key shard store: %w", err)
	}

	// Dial each bootstrap peer; connection failures are non-fatal.
	for _, bpStr := range cfg.BootstrapPeers {
		maddr, err := ma.NewMultiaddr(bpStr)
		if err != nil {
			store.Close()
			h.Close()
			cancel()
			return nil, fmt.Errorf("parse bootstrap peer %q: %w", bpStr, err)
		}
		pi, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			store.Close()
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

	n := &Node{
		cfg:     cfg,
		host:    h,
		log:     log,
		ctx:     ctx,
		cancel:  cancel,
		pool:    pool.NewPool(0),
		store:   store,
		configs: make(map[string]*lss.Config),
	}

	n.registerCoordHandler()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", n.handleHealth)
	mux.HandleFunc("GET /v1/info", n.handleInfo)
	mux.HandleFunc("GET /v1/keys", n.handleListKeys)
	mux.HandleFunc("POST /v1/keygen", n.handleKeygen)
	mux.HandleFunc("POST /v1/sign", n.handleSign)
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

// Stop gracefully shuts down the HTTP server, the libp2p host, the worker pool,
// and the key shard store.
func (n *Node) Stop() error {
	n.log.Info("stopping node")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := n.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown HTTP server: %w", err)
	}
	n.pool.TearDown()
	n.host.Close()
	if err := n.store.Close(); err != nil {
		n.log.Warn("close key shard store", zap.Error(err))
	}
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

// cachedConfig returns a config from the in-memory cache, or loads it from the
// store and caches it. Returns (nil, nil) when the session ID is not found.
func (n *Node) cachedConfig(sessionID string) (*lss.Config, error) {
	n.mu.RLock()
	cfg, ok := n.configs[sessionID]
	n.mu.RUnlock()
	if ok {
		return cfg, nil
	}

	cfg, err := n.store.Get(sessionID)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	n.mu.Lock()
	n.configs[sessionID] = cfg
	n.mu.Unlock()
	return cfg, nil
}

// --- HTTP handlers ---

func (n *Node) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func (n *Node) handleInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(n.Info())
}

// handleListKeys returns public metadata for all persisted keygen configs.
func (n *Node) handleListKeys(w http.ResponseWriter, r *http.Request) {
	type keyEntry struct {
		SessionID       string   `json:"session_id"`
		EthereumAddress string   `json:"ethereum_address"`
		Threshold       int      `json:"threshold"`
		Parties         []string `json:"parties"`
	}

	ids, err := n.store.List()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "list keys: "+err.Error())
		return
	}

	entries := make([]keyEntry, 0, len(ids))
	for _, id := range ids {
		cfg, err := n.cachedConfig(id)
		if err != nil || cfg == nil {
			continue
		}
		ethAddr := ""
		if pub, err := cfg.PublicPoint(); err == nil {
			if addr, err := network.EthereumAddressFromPoint(pub); err == nil {
				ethAddr = "0x" + hex.EncodeToString(addr[:])
			}
		}
		partyIDs := cfg.PartyIDs()
		parties := make([]string, len(partyIDs))
		for i, p := range partyIDs {
			parties[i] = string(p)
		}
		entries = append(entries, keyEntry{
			SessionID:       id,
			EthereumAddress: ethAddr,
			Threshold:       cfg.Threshold,
			Parties:         parties,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// handleKeygen runs a distributed key generation session.
//
// POST /v1/keygen
//
//	{"session_id":"mykey1","parties":["16Uiu2...","16Uiu2...","16Uiu2..."],"threshold":1}
//
// Send to any one node in the parties list. That node coordinates with the others
// automatically; the caller does not need to contact each node separately.
func (n *Node) handleKeygen(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string     `json:"session_id"`
		Parties   []party.ID `json:"parties"`
		Threshold int        `json:"threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if req.SessionID == "" || len(req.Parties) == 0 || req.Threshold <= 0 {
		httpError(w, http.StatusBadRequest, "session_id, parties (non-empty), and threshold (>0) are required")
		return
	}

	// party.NewIDSlice sorts the slice, as required by the LSS protocol.
	sortedParties := party.NewIDSlice(req.Parties)

	n.log.Info("keygen starting",
		zap.String("session_id", req.SessionID),
		zap.Int("n", len(sortedParties)),
		zap.Int("threshold", req.Threshold),
	)

	// Subscribe to the session topic before notifying peers, so we're ready to
	// receive GossipSub messages as soon as the mesh forms.
	sn, err := network.NewSessionNetwork(r.Context(), n.host, req.SessionID, sortedParties)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "session network: "+err.Error())
		return
	}
	defer sn.Close()

	// Tell every other party to join and start.
	if err := n.broadcastCoord(r.Context(), sortedParties, coordMsg{
		Type:      msgKeygen,
		SessionID: req.SessionID,
		Parties:   sortedParties,
		Threshold: req.Threshold,
	}); err != nil {
		httpError(w, http.StatusInternalServerError, "coordinate: "+err.Error())
		return
	}

	cfg, err := runKeygenOn(r.Context(), n.host, sn, req.SessionID, sortedParties, req.Threshold, n.pool)
	if err != nil {
		n.log.Error("keygen failed", zap.String("session_id", req.SessionID), zap.Error(err))
		httpError(w, http.StatusInternalServerError, "keygen: "+err.Error())
		return
	}

	if err := n.store.Put(req.SessionID, cfg); err != nil {
		n.log.Warn("persist shard failed", zap.String("session_id", req.SessionID), zap.Error(err))
	}
	n.mu.Lock()
	n.configs[req.SessionID] = cfg
	n.mu.Unlock()

	pub, err := cfg.PublicPoint()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "public point: "+err.Error())
		return
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "marshal public key: "+err.Error())
		return
	}
	ethAddr, err := network.EthereumAddressFromPoint(pub)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "eth addr: "+err.Error())
		return
	}

	n.log.Info("keygen complete",
		zap.String("session_id", req.SessionID),
		zap.String("eth_addr", "0x"+hex.EncodeToString(ethAddr[:])),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"session_id":       req.SessionID,
		"public_key":       "0x" + hex.EncodeToString(pubBytes),
		"ethereum_address": "0x" + hex.EncodeToString(ethAddr[:]),
	})
}

// handleSign runs a threshold signing session using a previously generated key.
//
// POST /v1/sign
//
//	{
//	  "key_session_id":  "mykey1",
//	  "sign_session_id": "sign-001",
//	  "signers":         ["16Uiu2...","16Uiu2..."],
//	  "message_hash":    "0xdeadbeef..."
//	}
//
// Send to any one node in the signers list. That node coordinates with the others
// automatically; the caller does not need to contact each node separately.
func (n *Node) handleSign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeySessionID  string     `json:"key_session_id"`
		SignSessionID string     `json:"sign_session_id"`
		Signers       []party.ID `json:"signers"`
		MessageHash   string     `json:"message_hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if req.KeySessionID == "" || req.SignSessionID == "" || len(req.Signers) == 0 || req.MessageHash == "" {
		httpError(w, http.StatusBadRequest, "key_session_id, sign_session_id, signers, and message_hash are required")
		return
	}

	msgHash, err := hex.DecodeString(strings.TrimPrefix(req.MessageHash, "0x"))
	if err != nil {
		httpError(w, http.StatusBadRequest, "invalid message_hash: "+err.Error())
		return
	}
	if len(msgHash) != 32 {
		httpError(w, http.StatusBadRequest, "message_hash must be exactly 32 bytes (64 hex chars)")
		return
	}

	cfg, err := n.cachedConfig(req.KeySessionID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "load config: "+err.Error())
		return
	}
	if cfg == nil {
		httpError(w, http.StatusNotFound, "key session not found: "+req.KeySessionID)
		return
	}

	// Validate signer set: sorted, threshold met, no duplicates, self included, all parties known.
	sortedSigners := party.NewIDSlice(req.Signers)
	if !sortedSigners.Valid() || len(sortedSigners) < cfg.Threshold || !sortedSigners.Contains(cfg.ID) {
		httpError(w, http.StatusBadRequest, "invalid signer set: threshold not met, duplicates, or this node not included")
		return
	}
	for _, j := range sortedSigners {
		if _, ok := cfg.Public[j]; !ok {
			httpError(w, http.StatusBadRequest, "invalid signer set: unknown party "+string(j))
			return
		}
	}

	n.log.Info("sign starting",
		zap.String("key_session_id", req.KeySessionID),
		zap.String("sign_session_id", req.SignSessionID),
		zap.Int("signers", len(sortedSigners)),
	)

	sn, err := network.NewSessionNetwork(r.Context(), n.host, req.SignSessionID, sortedSigners)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "session network: "+err.Error())
		return
	}
	defer sn.Close()

	if err := n.broadcastCoord(r.Context(), sortedSigners, coordMsg{
		Type:          msgSign,
		KeySessionID:  req.KeySessionID,
		SignSessionID: req.SignSessionID,
		Signers:       sortedSigners,
		MessageHash:   msgHash,
	}); err != nil {
		httpError(w, http.StatusInternalServerError, "coordinate: "+err.Error())
		return
	}

	sig, err := runSignOn(r.Context(), n.host, sn, req.SignSessionID, cfg, sortedSigners, msgHash, n.pool)
	if err != nil {
		n.log.Error("sign failed", zap.String("sign_session_id", req.SignSessionID), zap.Error(err))
		httpError(w, http.StatusInternalServerError, "sign: "+err.Error())
		return
	}

	ethSig, err := sig.SigEthereum()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "encode signature: "+err.Error())
		return
	}

	n.log.Info("sign complete", zap.String("sign_session_id", req.SignSessionID))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"sign_session_id":    req.SignSessionID,
		"ethereum_signature": "0x" + hex.EncodeToString(ethSig),
	})
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
