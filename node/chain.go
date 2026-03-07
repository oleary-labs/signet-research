package node

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"go.uber.org/zap"

	"github.com/luxfi/threshold/pkg/party"
	"signet/network"
)

const (
	factoryABIJSON = `[
		{"name":"getNodeGroups","type":"function","inputs":[{"name":"node","type":"address"}],"outputs":[{"name":"","type":"address[]"}],"stateMutability":"view"},
		{"name":"getNodePubkey","type":"function","inputs":[{"name":"node","type":"address"}],"outputs":[{"name":"","type":"bytes"}],"stateMutability":"view"},
		{"name":"NodeActivatedInGroup","type":"event","inputs":[{"name":"node","type":"address","indexed":true},{"name":"group","type":"address","indexed":true}],"anonymous":false},
		{"name":"NodeDeactivatedInGroup","type":"event","inputs":[{"name":"node","type":"address","indexed":true},{"name":"group","type":"address","indexed":true}],"anonymous":false}
	]`

	groupABIJSON = `[
		{"name":"getActiveNodes","type":"function","inputs":[],"outputs":[{"name":"","type":"address[]"}],"stateMutability":"view"},
		{"name":"threshold","type":"function","inputs":[],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
		{"name":"NodeJoined","type":"event","inputs":[{"name":"node","type":"address","indexed":true}],"anonymous":false},
		{"name":"NodeRemoved","type":"event","inputs":[{"name":"node","type":"address","indexed":true}],"anonymous":false}
	]`

	pollInterval = 2 * time.Second
)

// ChainClient watches the factory and group contracts for membership changes
// and keeps n.groups up to date.
type ChainClient struct {
	eth     *ethclient.Client
	factory common.Address
	myAddr  common.Address
	factABI abi.ABI
	grpABI  abi.ABI
	log     *zap.Logger
	n       *Node

	lastBlock uint64
	stopCh    chan struct{}
}

// newChainClient dials the Ethereum RPC and initialises the chain client.
func newChainClient(cfg *Config, h *network.Host, n *Node, log *zap.Logger) (*ChainClient, error) {
	eth, err := ethclient.Dial(cfg.EthRPC)
	if err != nil {
		return nil, fmt.Errorf("dial eth rpc %s: %w", cfg.EthRPC, err)
	}

	factABI, err := abi.JSON(strings.NewReader(factoryABIJSON))
	if err != nil {
		eth.Close()
		return nil, fmt.Errorf("parse factory ABI: %w", err)
	}
	grpABI, err := abi.JSON(strings.NewReader(groupABIJSON))
	if err != nil {
		eth.Close()
		return nil, fmt.Errorf("parse group ABI: %w", err)
	}

	pub := h.LibP2PHost().Peerstore().PubKey(h.PeerID())
	addr, err := network.EthereumAddress(pub)
	if err != nil {
		eth.Close()
		return nil, fmt.Errorf("derive eth address: %w", err)
	}

	return &ChainClient{
		eth:     eth,
		factory: common.HexToAddress(cfg.FactoryAddress),
		myAddr:  common.Address(addr),
		factABI: factABI,
		grpABI:  grpABI,
		log:     log,
		n:       n,
		stopCh:  make(chan struct{}),
	}, nil
}

// loadGroups queries the factory for all groups this node is active in and
// populates n.groups. Records the current block number so polling starts
// from the next block.
func (c *ChainClient) loadGroups(ctx context.Context) error {
	block, err := c.eth.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("get block number: %w", err)
	}
	c.lastBlock = block

	groups, err := c.callGetNodeGroups(ctx, c.myAddr)
	if err != nil {
		return fmt.Errorf("getNodeGroups: %w", err)
	}
	c.log.Info("chain: loading groups", zap.Int("count", len(groups)))

	for _, grpAddr := range groups {
		info, err := c.buildGroupInfo(ctx, grpAddr)
		if err != nil {
			c.log.Warn("chain: build group info",
				zap.String("group", grpAddr.Hex()), zap.Error(err))
			continue
		}
		c.n.groupsMu.Lock()
		c.n.groups[grpAddr.Hex()] = info
		c.n.groupsMu.Unlock()
		c.log.Info("chain: loaded group",
			zap.String("group", grpAddr.Hex()),
			zap.Int("members", len(info.Members)),
			zap.Int("threshold", info.Threshold),
		)
	}
	return nil
}

// buildGroupInfo fetches active nodes and threshold for a group, resolving
// each member's Ethereum address to a libp2p party.ID.
func (c *ChainClient) buildGroupInfo(ctx context.Context, grpAddr common.Address) (*GroupInfo, error) {
	members, err := c.callGetActiveNodes(ctx, grpAddr)
	if err != nil {
		return nil, fmt.Errorf("getActiveNodes: %w", err)
	}
	thresh, err := c.callThreshold(ctx, grpAddr)
	if err != nil {
		return nil, fmt.Errorf("threshold: %w", err)
	}

	ids := make([]party.ID, 0, len(members))
	for _, memberAddr := range members {
		pid, err := c.resolvePartyID(ctx, memberAddr)
		if err != nil {
			c.log.Warn("chain: resolve party ID",
				zap.String("addr", memberAddr.Hex()), zap.Error(err))
			continue
		}
		ids = append(ids, pid)
	}

	return &GroupInfo{
		Threshold: int(thresh.Int64()),
		Members:   ids,
	}, nil
}

// resolvePartyID fetches the node's pubkey from the factory and derives its party.ID.
func (c *ChainClient) resolvePartyID(ctx context.Context, nodeAddr common.Address) (party.ID, error) {
	pubkey, err := c.callGetNodePubkey(ctx, nodeAddr)
	if err != nil {
		return "", fmt.Errorf("getNodePubkey %s: %w", nodeAddr.Hex(), err)
	}
	if len(pubkey) == 0 {
		return "", fmt.Errorf("empty pubkey for %s", nodeAddr.Hex())
	}
	peerID, err := network.PeerIDFromUncompressedPubkey(pubkey)
	if err != nil {
		return "", fmt.Errorf("peer ID from pubkey: %w", err)
	}
	return party.ID(peerID.String()), nil
}

// start launches the event-polling goroutine.
func (c *ChainClient) start() {
	go c.watchLoop()
}

// close stops the polling loop and releases the eth client.
func (c *ChainClient) close() {
	close(c.stopCh)
	c.eth.Close()
}

func (c *ChainClient) watchLoop() {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := c.poll(ctx); err != nil {
				c.log.Warn("chain: poll error", zap.Error(err))
			}
			cancel()
		}
	}
}

func (c *ChainClient) poll(ctx context.Context) error {
	current, err := c.eth.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("block number: %w", err)
	}
	if current <= c.lastBlock {
		return nil
	}
	from := c.lastBlock + 1
	to := current

	if err := c.pollFactoryEvents(ctx, from, to); err != nil {
		c.log.Warn("chain: factory events", zap.Error(err))
	}

	c.n.groupsMu.RLock()
	groupAddrs := make([]common.Address, 0, len(c.n.groups))
	for hexAddr := range c.n.groups {
		groupAddrs = append(groupAddrs, common.HexToAddress(hexAddr))
	}
	c.n.groupsMu.RUnlock()

	for _, grpAddr := range groupAddrs {
		if err := c.pollGroupEvents(ctx, grpAddr, from, to); err != nil {
			c.log.Warn("chain: group events",
				zap.String("group", grpAddr.Hex()), zap.Error(err))
		}
	}

	c.lastBlock = to
	return nil
}

func (c *ChainClient) pollFactoryEvents(ctx context.Context, from, to uint64) error {
	activatedID := c.factABI.Events["NodeActivatedInGroup"].ID
	deactivatedID := c.factABI.Events["NodeDeactivatedInGroup"].ID

	query := ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(from),
		ToBlock:   new(big.Int).SetUint64(to),
		Addresses: []common.Address{c.factory},
		Topics: [][]common.Hash{
			{activatedID, deactivatedID},
			{common.BytesToHash(c.myAddr.Bytes())},
		},
	}
	logs, err := c.eth.FilterLogs(ctx, query)
	if err != nil {
		return fmt.Errorf("filter factory logs: %w", err)
	}

	for _, lg := range logs {
		if len(lg.Topics) < 3 {
			continue
		}
		grpAddr := common.BytesToAddress(lg.Topics[2].Bytes())
		switch lg.Topics[0] {
		case activatedID:
			c.n.groupsMu.RLock()
			_, exists := c.n.groups[grpAddr.Hex()]
			c.n.groupsMu.RUnlock()
			if exists {
				continue
			}
			info, err := c.buildGroupInfo(ctx, grpAddr)
			if err != nil {
				c.log.Warn("chain: build group info on activation",
					zap.String("group", grpAddr.Hex()), zap.Error(err))
				continue
			}
			c.n.groupsMu.Lock()
			c.n.groups[grpAddr.Hex()] = info
			c.n.groupsMu.Unlock()
			c.log.Info("chain: joined group", zap.String("group", grpAddr.Hex()),
				zap.Int("members", len(info.Members)))

		case deactivatedID:
			c.n.groupsMu.Lock()
			delete(c.n.groups, grpAddr.Hex())
			c.n.groupsMu.Unlock()
			c.log.Info("chain: left group", zap.String("group", grpAddr.Hex()))
		}
	}
	return nil
}

func (c *ChainClient) pollGroupEvents(ctx context.Context, grpAddr common.Address, from, to uint64) error {
	joinedID := c.grpABI.Events["NodeJoined"].ID
	removedID := c.grpABI.Events["NodeRemoved"].ID

	query := ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(from),
		ToBlock:   new(big.Int).SetUint64(to),
		Addresses: []common.Address{grpAddr},
		Topics:    [][]common.Hash{{joinedID, removedID}},
	}
	logs, err := c.eth.FilterLogs(ctx, query)
	if err != nil {
		return fmt.Errorf("filter group logs: %w", err)
	}

	for _, lg := range logs {
		if len(lg.Topics) < 2 {
			continue
		}
		nodeAddr := common.BytesToAddress(lg.Topics[1].Bytes())
		pid, err := c.resolvePartyID(ctx, nodeAddr)
		if err != nil {
			c.log.Warn("chain: resolve party on group event",
				zap.String("addr", nodeAddr.Hex()), zap.Error(err))
			continue
		}

		hexGrp := grpAddr.Hex()
		c.n.groupsMu.Lock()
		grp, ok := c.n.groups[hexGrp]
		if ok {
			switch lg.Topics[0] {
			case joinedID:
				if !containsParty(grp.Members, pid) {
					grp.Members = append(grp.Members, pid)
				}
			case removedID:
				grp.Members = removeParty(grp.Members, pid)
			}
		}
		c.n.groupsMu.Unlock()
	}
	return nil
}

// --- ABI call helpers ---

func (c *ChainClient) callGetNodeGroups(ctx context.Context, node common.Address) ([]common.Address, error) {
	data, err := c.factABI.Pack("getNodeGroups", node)
	if err != nil {
		return nil, err
	}
	result, err := c.eth.CallContract(ctx, ethereum.CallMsg{To: &c.factory, Data: data}, nil)
	if err != nil {
		return nil, err
	}
	results, err := c.factABI.Unpack("getNodeGroups", result)
	if err != nil {
		return nil, err
	}
	return results[0].([]common.Address), nil
}

func (c *ChainClient) callGetNodePubkey(ctx context.Context, node common.Address) ([]byte, error) {
	data, err := c.factABI.Pack("getNodePubkey", node)
	if err != nil {
		return nil, err
	}
	result, err := c.eth.CallContract(ctx, ethereum.CallMsg{To: &c.factory, Data: data}, nil)
	if err != nil {
		return nil, err
	}
	results, err := c.factABI.Unpack("getNodePubkey", result)
	if err != nil {
		return nil, err
	}
	return results[0].([]byte), nil
}

func (c *ChainClient) callGetActiveNodes(ctx context.Context, grpAddr common.Address) ([]common.Address, error) {
	data, err := c.grpABI.Pack("getActiveNodes")
	if err != nil {
		return nil, err
	}
	result, err := c.eth.CallContract(ctx, ethereum.CallMsg{To: &grpAddr, Data: data}, nil)
	if err != nil {
		return nil, err
	}
	results, err := c.grpABI.Unpack("getActiveNodes", result)
	if err != nil {
		return nil, err
	}
	return results[0].([]common.Address), nil
}

func (c *ChainClient) callThreshold(ctx context.Context, grpAddr common.Address) (*big.Int, error) {
	data, err := c.grpABI.Pack("threshold")
	if err != nil {
		return nil, err
	}
	result, err := c.eth.CallContract(ctx, ethereum.CallMsg{To: &grpAddr, Data: data}, nil)
	if err != nil {
		return nil, err
	}
	results, err := c.grpABI.Unpack("threshold", result)
	if err != nil {
		return nil, err
	}
	return results[0].(*big.Int), nil
}

// --- Slice helpers ---

func containsParty(slice []party.ID, id party.ID) bool {
	for _, v := range slice {
		if v == id {
			return true
		}
	}
	return false
}

func removeParty(slice []party.ID, id party.ID) []party.ID {
	for i, v := range slice {
		if v == id {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}
