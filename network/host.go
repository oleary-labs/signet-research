package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	libp2pnet "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"signet/lss"
)

const (
	// maxMessageSize is the maximum size of a length-prefixed message (10MB).
	maxMessageSize = 10 * 1024 * 1024
)

// Host wraps a libp2p host and maintains lss.PartyID <-> peer.ID mappings.
type Host struct {
	h    host.Host
	self lss.PartyID

	mu      sync.RWMutex
	parties map[lss.PartyID]peer.ID // lss.PartyID -> peer.ID
	peers   map[peer.ID]lss.PartyID // peer.ID -> lss.PartyID
}

// NewHost creates a libp2p host listening on the given multiaddr (e.g. "/ip4/127.0.0.1/tcp/0").
// The host's identity is derived from privKey; lss.PartyID == peer.ID.String().
func NewHost(ctx context.Context, privKey crypto.PrivKey, listenAddr string) (*Host, error) {
	self, err := PartyIDFromPrivKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("party ID from key: %w", err)
	}

	h, err := libp2p.New(
		libp2p.Identity(privKey),
		libp2p.ListenAddrStrings(listenAddr),
	)
	if err != nil {
		return nil, fmt.Errorf("libp2p new: %w", err)
	}

	host := &Host{
		h:       h,
		self:    self,
		parties: make(map[lss.PartyID]peer.ID),
		peers:   make(map[peer.ID]lss.PartyID),
	}

	// Register self in the mapping table.
	host.RegisterPeer(self, h.ID())

	// Auto-populate party mappings whenever a peer connects.
	h.Network().Notify(&connectionNotifee{host: host})

	return host, nil
}

// NewHostFromFile loads or generates a persistent key from keyPath, then creates a host.
func NewHostFromFile(ctx context.Context, keyPath, listenAddr string) (*Host, error) {
	priv, err := LoadOrGenerateKey(keyPath)
	if err != nil {
		return nil, err
	}
	return NewHost(ctx, priv, listenAddr)
}

// connectionNotifee implements libp2pnet.Notifiee to auto-register party mappings on connect.
type connectionNotifee struct{ host *Host }

func (n *connectionNotifee) Connected(_ libp2pnet.Network, c libp2pnet.Conn) {
	pid := c.RemotePeer()
	n.host.RegisterPeer(lss.PartyID(pid.String()), pid)
}
func (n *connectionNotifee) Disconnected(_ libp2pnet.Network, _ libp2pnet.Conn) {}
func (n *connectionNotifee) Listen(_ libp2pnet.Network, _ ma.Multiaddr)          {}
func (n *connectionNotifee) ListenClose(_ libp2pnet.Network, _ ma.Multiaddr)     {}

// Self returns the lss.PartyID of this host.
func (h *Host) Self() lss.PartyID { return h.self }

// PeerID returns the libp2p peer.ID of this host.
func (h *Host) PeerID() peer.ID { return h.h.ID() }

// Addrs returns the listen addresses as strings.
func (h *Host) Addrs() []string {
	addrs := h.h.Addrs()
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out
}

// RegisterPeer adds a lss.PartyID <-> peer.ID mapping.
func (h *Host) RegisterPeer(partyID lss.PartyID, peerID peer.ID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.parties[partyID] = peerID
	h.peers[peerID] = partyID
}

// PeerForParty returns the peer.ID for a given lss.PartyID.
func (h *Host) PeerForParty(id lss.PartyID) (peer.ID, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	pid, ok := h.parties[id]
	return pid, ok
}

// LibP2PHost returns the underlying libp2p host (for connect/discovery).
func (h *Host) LibP2PHost() host.Host { return h.h }

// Close shuts down the host.
func (h *Host) Close() error { return h.h.Close() }

// writeMessage writes a length-prefixed (4-byte big-endian) CBOR payload.
func writeMessage(w io.Writer, msg *lss.Message) error {
	data, err := msg.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if len(data) > maxMessageSize {
		return fmt.Errorf("message too large: %d > %d", len(data), maxMessageSize)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// readMessage reads a length-prefixed CBOR message.
func readMessage(r io.Reader) (*lss.Message, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > maxMessageSize {
		return nil, fmt.Errorf("message too large: %d > %d", n, maxMessageSize)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	msg := &lss.Message{}
	if err := msg.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return msg, nil
}
