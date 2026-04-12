# Signet Testnet Deployment

Deploy a 5-node Signet cluster across AWS US regions with contracts on Sepolia.

## Architecture

| Node  | Region       |
|-------|-------------|
| node1 | us-east-1    |
| node2 | us-east-2    |
| node3 | us-west-1    |
| node4 | us-west-2    |
| node5 | ca-central-1 |

- Instance type: t3.medium (2 vCPU, 4 GB)
- Signing group: 3-of-5 (threshold=2)
- Chain: Sepolia
- KMS: disabled (in-process Go FROST)

## Prerequisites

- AWS CLI configured with credentials that can launch EC2 instances
- Ansible 2.14+ with `amazon.aws` collection
- Python boto3
- Foundry (forge, cast)
- Go 1.22+
- jq
- An SSH key pair named `signet-testnet` created in each target region
- A funded Sepolia deployer key
- An Alchemy (or similar) Sepolia RPC URL

### macOS install steps

```bash
# Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# AWS CLI
brew install awscli
aws configure  # enter your access key, secret, default region

# Python + Ansible + boto3
brew install python
pip3 install ansible boto3
ansible-galaxy collection install amazon.aws

# Foundry (forge, cast, anvil)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Go
brew install go

# jq
brew install jq

# SSH key pair — create in each target region
aws ec2 create-key-pair --key-name signet-testnet --region us-east-1 \
  --query 'KeyMaterial' --output text > ~/.ssh/signet-testnet.pem
chmod 600 ~/.ssh/signet-testnet.pem
# Repeat for us-east-2, us-west-1, us-west-2, ca-central-1:
for region in us-east-2 us-west-1 us-west-2 ca-central-1; do
  aws ec2 import-key-pair --key-name signet-testnet --region $region \
    --public-key-material fileb://<(ssh-keygen -y -f ~/.ssh/signet-testnet.pem)
done
```

## Setup Flow

### 1. Generate node identities

```bash
testnet/scripts/init-nodes.sh
```

Creates key material under `testnet/data/node{1..5}/` and writes
Ansible host_vars with peer IDs and Ethereum addresses.

### 2. Provision EC2 instances

```bash
cd testnet/ansible
ansible-playbook provision.yml -e ssh_key_name=signet-testnet
```

Launches 5 t3.medium instances. Writes public IPs to `testnet/.hosts`.
Update `inventory.yml` with the IPs (or the deploy playbook reads `.hosts`).

### 3. Deploy contracts to Sepolia

```bash
SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY \
DEPLOYER_PK=0xYOUR_PRIVATE_KEY \
testnet/scripts/deploy-contracts.sh
```

Deploys SignetFactory, registers all 5 nodes, creates a 3-of-5 group.
Writes `testnet/.env` with all addresses and node metadata.

### 4. Cross-compile and deploy nodes

```bash
# Build linux binary
GOOS=linux GOARCH=amd64 go build -o build/signetd-linux-amd64 ./cmd/signetd

# Deploy to all nodes
cd testnet/ansible
FACTORY_ADDRESS=0x... \
SEPOLIA_RPC_URL=https://... \
ansible-playbook deploy.yml
```

Uploads the binary, writes config, installs systemd unit, starts signetd.

### 5. Verify

```bash
# Build harness
go build -o build/harness ./cmd/harness

# Smoke test
./build/harness -env testnet/.env correctness
```

## Management

All management via Ansible from `testnet/ansible/`:

```bash
# Check status
ansible-playbook manage.yml -e action=status

# View recent logs (default 50 lines)
ansible-playbook manage.yml -e action=logs
ansible-playbook manage.yml -e action=logs -e log_lines=200

# Stop / start / restart
ansible-playbook manage.yml -e action=stop
ansible-playbook manage.yml -e action=start
ansible-playbook manage.yml -e action=restart

# Wipe node data (stops node, removes data dir, recreates empty)
ansible-playbook manage.yml -e action=clean
```

Target a single node: `ansible-playbook manage.yml -e action=logs -l node3`

## Stress Testing

```bash
# Performance — 10 concurrent workers, 5 min
./build/harness -env testnet/.env perf -concurrency 10 -duration 300s -pool 100 -out results.jsonl

# Scalability — sweep concurrency 5 → 50
./build/harness -env testnet/.env scale -max-concurrency 50 -step 5 -duration 60s -pool 50

# Bulk keygen — use perf mode with high concurrency and long duration
./build/harness -env testnet/.env perf -concurrency 50 -duration 3600s -pool 0
```

### Reshare testing

After generating keys, test membership change + reshare:

1. Remove a node on-chain (via cast or a script)
2. Observe reshare auto-trigger in node logs
3. Re-run harness to verify signing still works
4. Add a new node on-chain, verify reshare includes it

## Teardown

```bash
cd testnet/ansible
ansible-playbook teardown.yml
```

Terminates all EC2 instances. Contracts on Sepolia are permanent.

## Directory Structure

```
testnet/
  README.md
  .env                          # generated: node APIs, contract addresses
  .hosts                        # generated: node IPs from provisioning
  data/                         # generated: node keys and identities
    nodes.json
    node{1..5}/node.key
  scripts/
    init-nodes.sh               # generate node identities
    deploy-contracts.sh         # deploy to Sepolia + register + create group
  ansible/
    ansible.cfg
    inventory.yml               # node hosts, regions, connection vars
    provision.yml               # launch EC2 instances
    deploy.yml                  # upload binary + config, start systemd
    manage.yml                  # stop/start/restart/status/logs/clean
    teardown.yml                # terminate EC2 instances
    group_vars/
      signet_nodes.yml
    host_vars/
      node{1..5}.yml            # generated: peer_id, eth_address, etc.
    roles/
      signetd/
        tasks/main.yml
        templates/
          config.yaml.j2
          signetd.service.j2
        handlers/main.yml
```
