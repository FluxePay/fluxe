# FLUXE Disaster Recovery Plan

## Overview

This document outlines backup strategies, recovery procedures, and business continuity plans for the FLUXE multi-chain L2 system.

---

## Backup Strategy

### What's Backed Up

| Component | Data | Frequency | Retention |
|-----------|------|-----------|-----------|
| State Database | RocksDB (commitments, nullifiers, trees) | Every batch | 90 days |
| Configuration | chains.toml, .env | On change | 1 year |
| Keys | Encrypted sequencer keys | On change | Permanent |
| Logs | Application logs | Hourly | 30 days |
| Metrics | Prometheus data | Every 15 min | 90 days |

### Backup Locations

| Tier | Location | Purpose | RTO |
|------|----------|---------|-----|
| Hot | Local disk | Immediate recovery | < 5 min |
| Warm | S3 (same region) | Regional recovery | < 30 min |
| Cold | S3 (cross-region) | Disaster recovery | < 4 hours |

### Automated Backup Script

```bash
#!/bin/bash
# /opt/fluxe/scripts/backup.sh

set -e

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR=/var/fluxe/backups
S3_BUCKET=s3://fluxe-backups

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup state (hot copy while running)
ldb --db=/var/fluxe/data backup --backup_dir=$BACKUP_DIR/state-$TIMESTAMP

# Compress
tar -czf $BACKUP_DIR/state-$TIMESTAMP.tar.gz -C $BACKUP_DIR state-$TIMESTAMP
rm -rf $BACKUP_DIR/state-$TIMESTAMP

# Upload to S3
aws s3 cp $BACKUP_DIR/state-$TIMESTAMP.tar.gz $S3_BUCKET/daily/

# Cross-region replication handled by S3 config

# Cleanup local (keep 24 hours)
find $BACKUP_DIR -name "state-*.tar.gz" -mtime +1 -delete

echo "Backup completed: state-$TIMESTAMP.tar.gz"
```

### Backup Verification

Weekly verification procedure:
1. Download random backup from S3
2. Restore to test environment
3. Verify state integrity checksums
4. Run validation queries
5. Document results

---

## Recovery Procedures

### Full System Recovery

**Scenario:** Complete system failure, need fresh deployment.

**Prerequisites:**
- Access to AWS/infrastructure
- Backup access credentials
- Admin key materials

**Procedure:**

```bash
# 1. Provision new infrastructure
terraform apply -var-file=prod.tfvars

# 2. Install dependencies
ansible-playbook -i inventory/prod setup.yml

# 3. Restore latest backup
LATEST_BACKUP=$(aws s3 ls s3://fluxe-backups/daily/ | sort | tail -1 | awk '{print $4}')
aws s3 cp s3://fluxe-backups/daily/$LATEST_BACKUP /tmp/
tar -xzf /tmp/$LATEST_BACKUP -C /var/fluxe/

# 4. Restore configuration
aws s3 cp s3://fluxe-backups/config/chains.toml /etc/fluxe/
aws s3 cp s3://fluxe-backups/config/.env /etc/fluxe/

# 5. Restore keys (from secure vault)
vault read -field=key secret/fluxe/sequencer > /etc/fluxe/sequencer.key
chmod 600 /etc/fluxe/sequencer.key

# 6. Verify L1 state
# Check last finalized batch on Ethereum
LAST_BATCH=$(cast call $ROLLUP_ADDRESS "lastFinalizedBatchId()" --rpc-url $ETH_RPC)
# Check backup state matches
BACKUP_BATCH=$(cat /var/fluxe/data/BATCH_ID)

if [ "$LAST_BATCH" != "$BACKUP_BATCH" ]; then
    echo "WARNING: State mismatch. L1: $LAST_BATCH, Backup: $BACKUP_BATCH"
    # May need to sync from L1 events
fi

# 7. Start sequencer
systemctl start fluxe-sequencer

# 8. Verify health
curl http://localhost:8080/health

# 9. Resume operations
# Unpause bridges if paused
```

**Estimated RTO:** 2-4 hours

### Partial State Recovery

**Scenario:** State corruption, need to restore specific components.

```bash
# 1. Stop sequencer
systemctl stop fluxe-sequencer

# 2. Identify corrupted component
ldb --db=/var/fluxe/data scan

# 3. Restore specific column family
# Example: Restore just the commitment tree
ldb --db=/var/fluxe/data restore_cf --cf=commitments \
    --backup_dir=/var/fluxe/backups/state-$GOOD_TIMESTAMP

# 4. Verify integrity
ldb --db=/var/fluxe/data checkconsistency

# 5. Restart
systemctl start fluxe-sequencer
```

### Cross-Chain Sync Recovery

**Scenario:** State divergence between chains or sequencer.

```bash
# 1. Pause all operations
cast send $BRIDGE_ADDRESS "pause()" --private-key $ADMIN_KEY --rpc-url $ETH_RPC

# 2. Get authoritative state from L1
LAST_ETH_BATCH=$(cast call $ROLLUP_ADDRESS "lastFinalizedBatchId()" --rpc-url $ETH_RPC)
ETH_ROOTS=$(cast call $ROLLUP_ADDRESS "finalizedBatches(uint64)" $LAST_ETH_BATCH --rpc-url $ETH_RPC)

# 3. Get Solana state
# solana program accounts $BRIDGE_PROGRAM_ID

# 4. Identify divergence point
# Compare batch IDs and roots

# 5. Resync from earliest divergence
# Either replay from L1 events or restore from backup

# 6. Verify consistency
curl http://localhost:8080/debug/verify_sync

# 7. Resume operations
cast send $BRIDGE_ADDRESS "unpause()" --private-key $ADMIN_KEY --rpc-url $ETH_RPC
```

---

## Business Continuity

### Failover Procedures

#### Primary Sequencer Failover

```
[Primary Region: us-east-1]
         │
         │ Health Check Failure
         ▼
[Route 53 DNS Failover]
         │
         ▼
[Secondary Region: us-west-2]
```

**Automatic failover triggers:**
- Health check fails 3 consecutive times (90 seconds)
- Memory > 95% for 5 minutes
- No batches for 10 minutes

**Manual failover:**
```bash
# 1. Promote secondary
aws route53 change-resource-record-sets \
  --hosted-zone-id $ZONE_ID \
  --change-batch file://failover.json

# 2. Verify DNS propagation
dig sequencer.fluxe.io

# 3. Verify secondary health
curl https://sequencer-secondary.fluxe.io/health
```

### Geographic Redundancy

| Component | Primary | Secondary | Sync Method |
|-----------|---------|-----------|-------------|
| Sequencer | us-east-1 | us-west-2 | State backup every batch |
| RPC (ETH) | Alchemy | Infura | Automatic failover |
| RPC (SOL) | Helius | QuickNode | Automatic failover |
| Database | us-east-1a | us-east-1b | Synchronous replication |
| Backups | us-east-1 | eu-west-1 | S3 cross-region replication |

### Communication Plan

**Internal:**
- PagerDuty for on-call alerts
- Slack #incident-response for coordination
- Zoom for war room

**External:**
- status.fluxe.io for user-facing status
- Twitter @fluxe_status for announcements
- Discord for community updates

**Templates:**

```
[Status Page - Service Disruption]
We are experiencing service disruption affecting [describe impact].
We are actively working to restore service.
ETR: [time if known, otherwise "investigating"]
Updates every [15/30/60] minutes.
```

```
[Twitter - Major Incident]
🚨 FLUXE Service Alert

We are aware of issues affecting [brief description].
Our team is actively investigating.

Status: https://status.fluxe.io

We will provide updates as available.
```

---

## Recovery Time Objectives

| Scenario | RTO | RPO | Notes |
|----------|-----|-----|-------|
| Single component failure | < 15 min | 0 | Automatic recovery |
| Regional failure | < 30 min | < 1 batch | Failover to secondary |
| Complete system failure | < 4 hours | < 1 hour | Full restore from backup |
| Multi-region disaster | < 24 hours | < 4 hours | Cold backup restore |

---

## Testing Schedule

| Test Type | Frequency | Last Tested | Next Scheduled |
|-----------|-----------|-------------|----------------|
| Backup verification | Weekly | [date] | [date] |
| Failover drill | Monthly | [date] | [date] |
| Full recovery test | Quarterly | [date] | [date] |
| Disaster simulation | Annually | [date] | [date] |

### Test Procedures

**Backup Verification (Weekly):**
1. Select random backup from past week
2. Restore to isolated test environment
3. Run integrity checks
4. Document any issues

**Failover Drill (Monthly):**
1. Announce maintenance window
2. Simulate primary failure
3. Verify automatic failover
4. Verify no data loss
5. Failback to primary
6. Document timings

**Full Recovery Test (Quarterly):**
1. Provision fresh infrastructure
2. Execute full recovery procedure
3. Verify all functionality
4. Measure actual RTO/RPO
5. Update procedures based on findings

---

## Contacts

| Role | Name | Phone | Email |
|------|------|-------|-------|
| Incident Commander | [Name] | [Phone] | [Email] |
| Security Lead | [Name] | [Phone] | [Email] |
| Ops Lead | [Name] | [Phone] | [Email] |
| CTO | [Name] | [Phone] | [Email] |
| AWS Support | - | - | [Support case] |

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-22 | FLUXE Team | Initial version |
