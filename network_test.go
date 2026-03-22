package signet

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"signet/network"
	"signet/tss"
)

func TestLibp2pKeygen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	const (
		n         = 3
		threshold = 2
	)

	hosts, parties := setupHosts(t, ctx, n)
	defer closeHosts(hosts)

	sessionID := "test-keygen-session"
	sessions := openSessions(t, ctx, hosts, parties, sessionID)
	defer closeSessions(sessions)

	var (
		mu      sync.Mutex
		configs = make(map[tss.PartyID]*tss.Config)
		errs    = make(map[tss.PartyID]error)
		wg      sync.WaitGroup
	)

	for i, pid := range parties {
		i, pid := i, pid
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := tss.Run(ctx, tss.Keygen(pid, parties, threshold), sessions[i])
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs[pid] = err
			} else {
				configs[pid] = result.(*tss.Config)
			}
		}()
	}
	wg.Wait()

	for _, pid := range parties {
		require.NoError(t, errs[pid], "keygen failed for %s", pid)
		require.NotNil(t, configs[pid], "missing config for %s", pid)
		t.Logf("party %s: keygen complete", pid)
	}
}

func TestLibp2pSign(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	const (
		n         = 3
		threshold = 2
	)

	hosts, parties := setupHosts(t, ctx, n)
	defer closeHosts(hosts)

	configs := runKeygen(t, ctx, hosts, parties, threshold)

	hostByParty := make(map[tss.PartyID]*network.Host, n)
	for i, pid := range parties {
		hostByParty[pid] = hosts[i]
	}

	t.Log("--- signing with all 3 parties ---")
	signers := tss.NewPartyIDSlice(parties)

	var messageHash [32]byte
	for i := range messageHash {
		messageHash[i] = byte(i + 1)
	}

	sigs := runSign(t, ctx, hostByParty, signers, configs, messageHash[:])

	var first []byte
	for _, pid := range signers {
		ethSig, err := sigs[pid].SigEthereum()
		require.NoError(t, err, "SigEthereum for %s", pid)
		assert.Len(t, ethSig, 65, "signature must be 65 bytes")
		t.Logf("party %s: signature 0x%x", pid, ethSig)
		if first == nil {
			first = ethSig
		} else {
			assert.Equal(t, first, ethSig, "all signers must produce the same signature")
		}
	}
}

func TestEthereumAddress(t *testing.T) {
	priv, pub, err := crypto.GenerateKeyPair(crypto.Secp256k1, -1)
	require.NoError(t, err)
	_ = priv

	addr, err := network.EthereumAddress(pub)
	require.NoError(t, err)

	var zero [20]byte
	assert.NotEqual(t, zero, addr, "address should not be zero")
	t.Logf("ethereum address: 0x%x", addr)
}

// --- helpers ---

func setupHosts(t *testing.T, ctx context.Context, n int) ([]*network.Host, []tss.PartyID) {
	t.Helper()
	hosts := make([]*network.Host, n)
	parties := make([]tss.PartyID, n)
	for i := 0; i < n; i++ {
		priv, _, err := crypto.GenerateKeyPair(crypto.Secp256k1, -1)
		require.NoError(t, err)
		h, err := network.NewHost(ctx, priv, "/ip4/127.0.0.1/tcp/0")
		require.NoError(t, err)
		hosts[i] = h
		parties[i] = h.Self()
	}
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			require.NoError(t, network.ConnectDirectly(ctx, hosts[i], hosts[j]))
		}
	}
	return hosts, parties
}

func closeHosts(hosts []*network.Host) {
	for _, h := range hosts {
		h.Close()
	}
}

func openSessions(t *testing.T, ctx context.Context, hosts []*network.Host, parties []tss.PartyID, sessionID string) []*network.SessionNetwork {
	t.Helper()
	sessions := make([]*network.SessionNetwork, len(hosts))
	for i, h := range hosts {
		sn, err := network.NewSessionNetwork(ctx, h, sessionID, parties)
		require.NoError(t, err)
		sessions[i] = sn
	}
	return sessions
}

func closeSessions(sessions []*network.SessionNetwork) {
	for _, s := range sessions {
		s.Close()
	}
}

func runKeygen(t *testing.T, ctx context.Context, hosts []*network.Host, parties []tss.PartyID, threshold int) map[tss.PartyID]*tss.Config {
	t.Helper()
	sessions := openSessions(t, ctx, hosts, parties, "test-keygen")
	defer closeSessions(sessions)

	var mu sync.Mutex
	configs := make(map[tss.PartyID]*tss.Config)
	errs := make(map[tss.PartyID]error)
	var wg sync.WaitGroup

	for i, pid := range parties {
		i, pid := i, pid
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := tss.Run(ctx, tss.Keygen(pid, parties, threshold), sessions[i])
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs[pid] = err
			} else {
				configs[pid] = result.(*tss.Config)
			}
		}()
	}
	wg.Wait()

	for _, pid := range parties {
		require.NoError(t, errs[pid], "keygen failed for %s", pid)
		require.NotNil(t, configs[pid], "missing config for %s", pid)
		t.Logf("keygen: party %s complete", pid)
	}
	return configs
}

func runSign(t *testing.T, ctx context.Context, hostByParty map[tss.PartyID]*network.Host, signers tss.PartyIDSlice, configs map[tss.PartyID]*tss.Config, messageHash []byte) map[tss.PartyID]*tss.Signature {
	t.Helper()
	sessions := make(map[tss.PartyID]*network.SessionNetwork, len(signers))
	for _, pid := range signers {
		sn, err := network.NewSessionNetwork(ctx, hostByParty[pid], "test-sign", signers)
		require.NoError(t, err)
		sessions[pid] = sn
	}
	defer func() {
		for _, s := range sessions {
			s.Close()
		}
	}()

	var mu sync.Mutex
	sigs := make(map[tss.PartyID]*tss.Signature)
	errs := make(map[tss.PartyID]error)
	var wg sync.WaitGroup

	for _, pid := range signers {
		pid := pid
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := tss.Run(ctx, tss.Sign(configs[pid], signers, messageHash), sessions[pid])
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs[pid] = err
			} else {
				sigs[pid] = result.(*tss.Signature)
			}
		}()
	}
	wg.Wait()

	for _, pid := range signers {
		require.NoError(t, errs[pid], "sign failed for %s", pid)
		t.Logf("sign: party %s complete", pid)
	}
	return sigs
}
