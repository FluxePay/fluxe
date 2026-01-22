# FLUXE Operations Runbook

## Common Operations

### Deploying New Version

```bash
# 1. Build new version
cargo build --release -p fluxe-sequencer

# 2. Run tests
cargo test --all

# 3. Stop sequencer gracefully
systemctl stop fluxe-sequencer

# 4. Backup current binary
cp /usr/local/bin/fluxe-sequencer /usr/local/bin/fluxe-sequencer.bak

# 5. Deploy new binary
cp target/release/fluxe-sequencer /usr/local/bin/

# 6. Start sequencer
systemctl start fluxe-sequencer

# 7. Verify health
curl http://localhost:8080/health
```

### Adding New Asset

```bash
# 1. Register on Ethereum bridge
cast send $BRIDGE_ADDRESS "registerAsset(uint32,address,uint256,uint256)" \
  $ASSET_TYPE $TOKEN_ADDRESS $MIN_DEPOSIT $MAX_DEPOSIT \
  --private-key $ADMIN_KEY --rpc-url $ETH_RPC

# 2. Register on Solana bridge
solana program invoke $BRIDGE_PROGRAM_ID register_asset \
  --args $ASSET_TYPE $TOKEN_MINT $MIN_DEPOSIT $MAX_DEPOSIT \
  --keypair $ADMIN_KEYPAIR

# 3. Update config
# Edit config/chains.toml to add asset

# 4. Restart sequencer to pick up config
systemctl restart fluxe-sequencer
```

### Pausing/Resuming Bridge

```bash
# PAUSE Ethereum
cast send $BRIDGE_ADDRESS "pause()" --private-key $ADMIN_KEY --rpc-url $ETH_RPC
cast send $ROLLUP_ADDRESS "pause()" --private-key $ADMIN_KEY --rpc-url $ETH_RPC

# PAUSE Solana
solana program invoke $BRIDGE_PROGRAM_ID pause --keypair $ADMIN_KEYPAIR

# RESUME Ethereum
cast send $BRIDGE_ADDRESS "unpause()" --private-key $ADMIN_KEY --rpc-url $ETH_RPC
cast send $ROLLUP_ADDRESS "unpause()" --private-key $ADMIN_KEY --rpc-url $ETH_RPC

# RESUME Solana
solana program invoke $BRIDGE_PROGRAM_ID unpause --keypair $ADMIN_KEYPAIR
```

### Rotating Sequencer Keys

```bash
# 1. Generate new keypair
cast wallet new > new_sequencer_key.txt

# 2. Initiate transfer on Ethereum
cast send $ROLLUP_ADDRESS "initiateSequencerTransfer(address)" $NEW_ADDRESS \
  --private-key $ADMIN_KEY --rpc-url $ETH_RPC

# 3. Accept with new key
cast send $ROLLUP_ADDRESS "acceptSequencer()" \
  --private-key $NEW_KEY --rpc-url $ETH_RPC

# 4. Update Solana
solana program invoke $BRIDGE_PROGRAM_ID update_sequencer \
  --args $NEW_PUBKEY --keypair $ADMIN_KEYPAIR

# 5. Update sequencer config
# Edit .env with new key
# Restart sequencer
```

### Database Backup/Restore

```bash
# BACKUP
systemctl stop fluxe-sequencer
tar -czf /backups/fluxe-state-$(date +%Y%m%d-%H%M%S).tar.gz /var/fluxe/data
aws s3 cp /backups/fluxe-state-*.tar.gz s3://fluxe-backups/
systemctl start fluxe-sequencer

# RESTORE
systemctl stop fluxe-sequencer
rm -rf /var/fluxe/data/*
aws s3 cp s3://fluxe-backups/fluxe-state-$TIMESTAMP.tar.gz /tmp/
tar -xzf /tmp/fluxe-state-*.tar.gz -C /
systemctl start fluxe-sequencer
```

---

## Troubleshooting

### Sequencer Not Producing Batches

**Symptoms:**
- No new batches for > 5 minutes
- `batch_creation_duration` metric increasing
- Pending transactions accumulating

**Diagnosis:**
```bash
# Check sequencer status
systemctl status fluxe-sequencer

# Check logs
journalctl -u fluxe-sequencer -n 500 | grep -i error

# Check RPC connectivity
curl -X POST $ETH_RPC -H "Content-Type: application/json" \
  -d '{"method":"eth_blockNumber","params":[],"id":1,"jsonrpc":"2.0"}'

# Check disk space
df -h /var/fluxe

# Check memory
free -m
```

**Resolution:**
1. If RPC issue: Switch to backup RPC
2. If disk full: Clean old logs/data
3. If memory issue: Restart sequencer
4. If proof generation failing: Check circuit keys

### Deposits Not Appearing

**Symptoms:**
- User deposited but no commitment visible
- Deposit event emitted on L1

**Diagnosis:**
```bash
# Check if deposit event was processed
curl http://localhost:8080/deposits/status/$INGRESS_HASH

# Check deposit monitor logs
journalctl -u fluxe-sequencer | grep "deposit"

# Verify on L1
cast call $BRIDGE_ADDRESS "processedDeposits(bytes32)" $INGRESS_HASH
```

**Resolution:**
1. If event missed: Rescan blocks from deposit block
2. If processing error: Check beneficiary commitment format
3. If chain disconnected: Restore RPC connection

### Withdrawals Stuck

**Symptoms:**
- Exit receipt in batch but withdrawal failing on L1
- Merkle proof verification failing

**Diagnosis:**
```bash
# Get withdrawal proof
curl http://localhost:8080/chain/1/withdrawal/proof/$EXIT_HASH

# Verify batch is finalized
cast call $ROLLUP_ADDRESS "lastFinalizedBatchId()"

# Check exit root
cast call $ROLLUP_ADDRESS "finalizedBatches(uint64)" $BATCH_ID

# Verify Merkle proof locally
# Use fluxe-cli verify-proof command
```

**Resolution:**
1. If batch not finalized: Wait for proof submission
2. If proof invalid: Regenerate proof from state
3. If root mismatch: Check for state corruption

### High Memory/CPU Usage

**Symptoms:**
- Sequencer using > 80% memory
- CPU consistently > 90%
- Slow response times

**Diagnosis:**
```bash
# Check process stats
top -p $(pgrep fluxe)

# Check Merkle tree size
curl http://localhost:8080/debug/tree_stats

# Profile memory
# Start sequencer with MALLOC_CONF=prof:true
```

**Resolution:**
1. Increase memory limits
2. Optimize batch size configuration
3. Add rate limiting
4. Scale horizontally

### Disk Space Issues

**Symptoms:**
- "No space left on device" errors
- RocksDB write failures

**Diagnosis:**
```bash
# Check usage
df -h /var/fluxe
du -sh /var/fluxe/data/*

# Find large files
find /var/fluxe -type f -size +100M
```

**Resolution:**
1. Clean old logs: `journalctl --vacuum-time=7d`
2. Compact RocksDB: `ldb --db=/var/fluxe/data compact`
3. Archive old batches to cold storage
4. Expand disk

---

## Monitoring Alerts Response

### HighPendingTransactions

**Threshold:** > 1000 pending

**Actions:**
1. Check batch production rate
2. Verify proof generation working
3. Consider increasing batch frequency
4. Check for stuck transactions

### LowPoolBalance

**Threshold:** < configured minimum per asset

**Actions:**
1. Check recent withdrawal volume
2. Alert treasury team
3. Consider pausing withdrawals for asset
4. Plan rebalancing if cross-chain imbalance

### ProofVerificationFailure

**Threshold:** Any failure

**Actions:**
1. Check proof inputs
2. Verify VK matches
3. Check witness generation
4. Escalate if repeated

### SequencerBehind

**Threshold:** > 100 blocks behind L1

**Actions:**
1. Check RPC connectivity
2. Check batch processing speed
3. Verify no chain reorg
4. Consider pausing deposits

### ChainDisconnected

**Threshold:** > 60 seconds no response

**Actions:**
1. Switch to backup RPC
2. Check network connectivity
3. Verify chain is operational
4. Pause chain-specific operations

### HighRpcLatency

**Threshold:** > 5000ms

**Actions:**
1. Check RPC provider status
2. Consider switching provider
3. Check network path
4. Alert if persistent

### StorageNearCapacity

**Threshold:** > 80% used

**Actions:**
1. Clean old data
2. Compress/archive
3. Plan disk expansion
4. Set up auto-cleanup

---

## Useful Commands

### Query State

```bash
# Get current roots
curl http://localhost:8080/state/global/roots | jq

# Get chain supply
curl http://localhost:8080/chain/1/state/supply/1 | jq

# Get batch status
curl http://localhost:8080/chain/1/batch/status/123 | jq

# Get pool balances
curl http://localhost:8080/pools | jq
```

### Check Contracts

```bash
# Ethereum bridge state
cast call $BRIDGE_ADDRESS "paused()" --rpc-url $ETH_RPC
cast call $BRIDGE_ADDRESS "poolBalances(uint32)" 1 --rpc-url $ETH_RPC

# Ethereum rollup state
cast call $ROLLUP_ADDRESS "lastFinalizedBatchId()" --rpc-url $ETH_RPC
cast call $ROLLUP_ADDRESS "sequencer()" --rpc-url $ETH_RPC
```

### Debug Commands

```bash
# Enable debug logging
export RUST_LOG=fluxe=debug
systemctl restart fluxe-sequencer

# Get heap profile
curl http://localhost:8080/debug/heap > heap.prof

# Dump state
curl http://localhost:8080/debug/dump_state > state.json
```
