#!/usr/bin/env bash
# testnet/scripts/create-local-group.sh — Create a new Sepolia group for
# single-region (multi-AZ) nodes and write .env-local for the harness.
#
# Usage:
#   SEPOLIA_RPC_URL=https://... DEPLOYER_PK=0x... testnet/scripts/create-local-group.sh

set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
TESTNET="$REPO/testnet"
NODES_JSON="$TESTNET/data/nodes.json"
HOSTS_FILE="$TESTNET/.hosts-local"
ENV_FILE="$TESTNET/.env-local"

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

[[ -z "${SEPOLIA_RPC_URL:-}" ]] && die "SEPOLIA_RPC_URL not set"
[[ -z "${DEPLOYER_PK:-}" ]] && die "DEPLOYER_PK not set"
[[ -f "$NODES_JSON" ]] || die "nodes.json not found — run init-nodes.sh first"

command -v cast >/dev/null 2>&1 || die "'cast' not found — install Foundry"
command -v jq >/dev/null 2>&1 || die "'jq' not found"

RPC="$SEPOLIA_RPC_URL"

# Read factory address from existing .env
[[ -f "$TESTNET/.env" ]] || die "testnet/.env not found — run deploy-contracts.sh first"
FACTORY=$(grep '^FACTORY_ADDRESS=' "$TESTNET/.env" | cut -d= -f2)
[[ -z "$FACTORY" ]] && die "FACTORY_ADDRESS not found in .env"

NUM_NODES=$(jq '.nodes | length' "$NODES_JSON")

# Build address list
ADDR_LIST=""
for i in $(seq 0 $((NUM_NODES - 1))); do
    ADDR=$(jq -r ".nodes[$i].eth_address" "$NODES_JSON")
    if [[ -n "$ADDR_LIST" ]]; then
        ADDR_LIST="${ADDR_LIST},${ADDR}"
    else
        ADDR_LIST="${ADDR}"
    fi
done

info "Factory: $FACTORY"
info "Nodes:   $ADDR_LIST"
info "Creating new group (threshold=2, $NUM_NODES nodes)..."

GROUP_CREATED_TOPIC=$(cast keccak "GroupCreated(address,address,uint256)")

CREATE_RECEIPT=$(cast send --private-key "$DEPLOYER_PK" --rpc-url "$RPC" "$FACTORY" "createGroup(address[],uint256,uint256,uint256,uint256,(string,string[])[],uint256,uint256,bytes[])" "[$ADDR_LIST]" 2 86400 86400 86400 "[]" 86400 86400 "[]" --json)

GROUP_RAW=$(echo "$CREATE_RECEIPT" | jq -r --arg topic "$GROUP_CREATED_TOPIC" '.logs[] | select(.topics[0] == $topic) | .topics[1]')
GROUP="0x${GROUP_RAW: -40}"

[[ -z "$GROUP" || "$GROUP" == "0x" ]] && die "Could not parse group address from receipt"

info "Group: $GROUP"

# Write .env-local
info "Writing $ENV_FILE..."
{
    echo "RPC_URL=${RPC}"
    echo "FACTORY_ADDRESS=${FACTORY}"
    echo "GROUP_ADDRESS=${GROUP}"
    echo "USE_KMS=false"
    echo ""

    for i in $(seq 0 $((NUM_NODES - 1))); do
        n=$((i + 1))
        ADDR=$(jq -r ".nodes[$i].eth_address" "$NODES_JSON")
        PEER=$(jq -r ".nodes[$i].peer_id" "$NODES_JSON")

        echo "NODE${n}_ETH=${ADDR}"
        echo "NODE${n}_PEER=${PEER}"

        if [[ -f "$HOSTS_FILE" ]]; then
            IP=$(grep "^node${n}=" "$HOSTS_FILE" | cut -d= -f2)
            echo "NODE${n}_API=http://${IP}:8080"
        else
            echo "NODE${n}_API=http://FILL_IP:8080"
        fi
    done

    echo ""
    echo "NODE1_REGION=us-east-1a"
    echo "NODE2_REGION=us-east-1b"
    echo "NODE3_REGION=us-east-1c"
    echo "NODE4_REGION=us-east-1d"
    echo "NODE5_REGION=us-east-1f"
} > "$ENV_FILE"

info "Done! Env: $ENV_FILE"
info "Next: ./build/harness -env testnet/.env-local correctness"
