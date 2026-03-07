package node

import (
	"context"
	"crypto/rand"
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

// shardKey is the composite cache key for a stored key shard.
type shardKey struct {
	GroupID string
	KeyID   string
}

// GroupInfo holds the resolved membership for a group contract. It is
// populated at startup by the chain client and kept up to date via events.
type GroupInfo struct {
	Threshold int
	Members   []party.ID // libp2p peer IDs of active members, sorted
}

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
	configs map[shardKey]*lss.Config // in-memory cache: (group_id, key_id) → key config

	groupsMu sync.RWMutex
	groups   map[string]*GroupInfo // group contract address → resolved membership

	chain *ChainClient // nil if no eth_rpc configured
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
		configs: make(map[shardKey]*lss.Config),
		groups:  make(map[string]*GroupInfo),
	}

	// Wire the chain client when eth_rpc and factory_address are configured.
	if cfg.EthRPC != "" && cfg.FactoryAddress != "" {
		chain, err := newChainClient(cfg, h, n, log)
		if err != nil {
			store.Close()
			h.Close()
			cancel()
			return nil, fmt.Errorf("chain client: %w", err)
		}
		if err := chain.loadGroups(ctx); err != nil {
			log.Warn("chain: initial group load failed", zap.Error(err))
		}
		chain.start()
		n.chain = chain
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
	if n.chain != nil {
		n.chain.close()
	}
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
// store and caches it. Returns (nil, nil) when the (groupID, keyID) is not found.
func (n *Node) cachedConfig(groupID, keyID string) (*lss.Config, error) {
	k := shardKey{groupID, keyID}

	n.mu.RLock()
	cfg, ok := n.configs[k]
	n.mu.RUnlock()
	if ok {
		return cfg, nil
	}

	cfg, err := n.store.Get(groupID, keyID)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	n.mu.Lock()
	n.configs[k] = cfg
	n.mu.Unlock()
	return cfg, nil
}

// randomNonce returns a short random hex string for sign session disambiguation.
func randomNonce() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
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

// handleListKeys returns public metadata for all persisted key shards.
//
// GET /v1/keys                       — all groups and their keys
// GET /v1/keys?group_id=0xGroupAddr  — keys for a specific group
func (n *Node) handleListKeys(w http.ResponseWriter, r *http.Request) {
	type keyEntry struct {
		GroupID         string   `json:"group_id"`
		KeyID           string   `json:"key_id"`
		EthereumAddress string   `json:"ethereum_address"`
		Threshold       int      `json:"threshold"`
		Parties         []string `json:"parties"`
	}

	filterGroup := r.URL.Query().Get("group_id")

	var groupIDs []string
	if filterGroup != "" {
		groupIDs = []string{filterGroup}
	} else {
		var err error
		groupIDs, err = n.store.ListGroups()
		if err != nil {
			httpError(w, http.StatusInternalServerError, "list groups: "+err.Error())
			return
		}
	}

	entries := make([]keyEntry, 0)
	for _, gid := range groupIDs {
		keyIDs, err := n.store.List(gid)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "list keys: "+err.Error())
			return
		}
		for _, kid := range keyIDs {
			cfg, err := n.cachedConfig(gid, kid)
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
				GroupID:         gid,
				KeyID:           kid,
				EthereumAddress: ethAddr,
				Threshold:       cfg.Threshold,
				Parties:         parties,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// handleKeygen runs a distributed key generation session.
//
// POST /v1/keygen
//
//	{"group_id":"0xGroupAddr","key_id":"primary"}
//
// The key shard is stored under (group_id, key_id). The group members and
// threshold are resolved from the node's in-memory group map. Send to any
// one member of the group; it coordinates with the others automatically.
func (n *Node) handleKeygen(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroupID string `json:"group_id"`
		KeyID   string `json:"key_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if req.GroupID == "" || req.KeyID == "" {
		httpError(w, http.StatusBadRequest, "group_id and key_id are required")
		return
	}

	n.groupsMu.RLock()
	grp, ok := n.groups[req.GroupID]
	n.groupsMu.RUnlock()
	if !ok {
		httpError(w, http.StatusNotFound, "group not found: "+req.GroupID)
		return
	}

	// party.NewIDSlice sorts the slice, as required by the LSS protocol.
	sortedParties := party.NewIDSlice(grp.Members)
	sessID := keygenSessionID(req.GroupID, req.KeyID)

	n.log.Info("keygen starting",
		zap.String("group_id", req.GroupID),
		zap.String("key_id", req.KeyID),
		zap.Int("n", len(sortedParties)),
		zap.Int("threshold", grp.Threshold),
	)

	sn, err := network.NewSessionNetwork(r.Context(), n.host, sessID, sortedParties)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "session network: "+err.Error())
		return
	}
	defer sn.Close()

	if err := n.broadcastCoord(r.Context(), sortedParties, coordMsg{
		Type:      msgKeygen,
		GroupID:   req.GroupID,
		KeyID:     req.KeyID,
		Parties:   sortedParties,
		Threshold: grp.Threshold,
	}); err != nil {
		httpError(w, http.StatusInternalServerError, "coordinate: "+err.Error())
		return
	}

	cfg, err := runKeygenOn(r.Context(), n.host, sn, sessID, sortedParties, grp.Threshold, n.pool)
	if err != nil {
		n.log.Error("keygen failed",
			zap.String("group_id", req.GroupID),
			zap.String("key_id", req.KeyID),
			zap.Error(err))
		httpError(w, http.StatusInternalServerError, "keygen: "+err.Error())
		return
	}

	if err := n.store.Put(req.GroupID, req.KeyID, cfg); err != nil {
		n.log.Warn("persist shard failed",
			zap.String("group_id", req.GroupID),
			zap.String("key_id", req.KeyID),
			zap.Error(err))
	}
	n.mu.Lock()
	n.configs[shardKey{req.GroupID, req.KeyID}] = cfg
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
		zap.String("group_id", req.GroupID),
		zap.String("key_id", req.KeyID),
		zap.String("eth_addr", "0x"+hex.EncodeToString(ethAddr[:])),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"group_id":         req.GroupID,
		"key_id":           req.KeyID,
		"public_key":       "0x" + hex.EncodeToString(pubBytes),
		"ethereum_address": "0x" + hex.EncodeToString(ethAddr[:]),
	})
}

// handleSign runs a threshold signing session using a previously generated key.
//
// POST /v1/sign
//
//	{"group_id":"0xGroupAddr","key_id":"primary","message_hash":"0xdeadbeef..."}
//
// The signing set is all active members of the group, resolved from the
// node's in-memory group map. Send to any one member; it coordinates with
// the others automatically. The sign session is disambiguated internally by a
// random nonce so concurrent sign requests on the same key do not collide.
func (n *Node) handleSign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroupID     string `json:"group_id"`
		KeyID       string `json:"key_id"`
		MessageHash string `json:"message_hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if req.GroupID == "" || req.KeyID == "" || req.MessageHash == "" {
		httpError(w, http.StatusBadRequest, "group_id, key_id, and message_hash are required")
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

	n.groupsMu.RLock()
	grp, ok := n.groups[req.GroupID]
	n.groupsMu.RUnlock()
	if !ok {
		httpError(w, http.StatusNotFound, "group not found: "+req.GroupID)
		return
	}

	cfg, err := n.cachedConfig(req.GroupID, req.KeyID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "load config: "+err.Error())
		return
	}
	if cfg == nil {
		httpError(w, http.StatusNotFound, fmt.Sprintf("key not found: group=%s key=%s", req.GroupID, req.KeyID))
		return
	}

	sortedSigners := party.NewIDSlice(grp.Members)
	if !sortedSigners.Contains(cfg.ID) {
		httpError(w, http.StatusBadRequest, "this node is not a member of group "+req.GroupID)
		return
	}

	nonce, err := randomNonce()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "generate nonce: "+err.Error())
		return
	}
	sessID := signSessionID(req.GroupID, req.KeyID, nonce)

	n.log.Info("sign starting",
		zap.String("group_id", req.GroupID),
		zap.String("key_id", req.KeyID),
		zap.Int("signers", len(sortedSigners)),
	)

	sn, err := network.NewSessionNetwork(r.Context(), n.host, sessID, sortedSigners)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "session network: "+err.Error())
		return
	}
	defer sn.Close()

	if err := n.broadcastCoord(r.Context(), sortedSigners, coordMsg{
		Type:        msgSign,
		GroupID:     req.GroupID,
		KeyID:       req.KeyID,
		SignNonce:   nonce,
		Signers:     sortedSigners,
		MessageHash: msgHash,
	}); err != nil {
		httpError(w, http.StatusInternalServerError, "coordinate: "+err.Error())
		return
	}

	sig, err := runSignOn(r.Context(), n.host, sn, sessID, cfg, sortedSigners, msgHash, n.pool)
	if err != nil {
		n.log.Error("sign failed",
			zap.String("group_id", req.GroupID),
			zap.String("key_id", req.KeyID),
			zap.Error(err))
		httpError(w, http.StatusInternalServerError, "sign: "+err.Error())
		return
	}

	ethSig, err := sig.SigEthereum()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "encode signature: "+err.Error())
		return
	}

	n.log.Info("sign complete",
		zap.String("group_id", req.GroupID),
		zap.String("key_id", req.KeyID),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"group_id":           req.GroupID,
		"key_id":             req.KeyID,
		"ethereum_signature": "0x" + hex.EncodeToString(ethSig),
	})
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
