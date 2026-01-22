# FLUXE Incident Response Plan

## Overview

This document outlines procedures for responding to incidents affecting the FLUXE multi-chain L2 system. All team members should be familiar with these procedures.

---

## Incident Classification

### P0 - Critical (Immediate Response Required)

| Incident Type | Description | Response Time |
|--------------|-------------|---------------|
| Bridge Exploit | Unauthorized fund movement or theft | < 5 minutes |
| Proof System Bypass | Invalid proofs accepted | < 5 minutes |
| Double-Spend Detected | Same nullifier used twice | < 5 minutes |
| Private Key Compromise | Sequencer or admin key leaked | < 5 minutes |
| Smart Contract Vulnerability | Exploitable bug discovered | < 15 minutes |

**Immediate Actions:**
1. Pause all bridges (Ethereum + Solana)
2. Alert all on-call personnel
3. Begin incident war room
4. Notify legal/compliance if applicable

### P1 - High (Response Within 1 Hour)

| Incident Type | Description | Response Time |
|--------------|-------------|---------------|
| Sequencer Down | No batches being produced | < 30 minutes |
| Chain Disconnect | RPC connection lost > 5 minutes | < 30 minutes |
| Significant Balance Discrepancy | Pool balance mismatch > 1% | < 1 hour |
| Proof Generation Failure | Batch proofs failing consistently | < 1 hour |
| Storage Failure | RocksDB unavailable | < 1 hour |

### P2 - Medium (Response Within 4 Hours)

| Incident Type | Description | Response Time |
|--------------|-------------|---------------|
| Slow Processing | Batches > 10 minutes delayed | < 4 hours |
| High Fees | Dynamic fees > 5x baseline | < 4 hours |
| Single Chain Degraded | One chain partially operational | < 4 hours |
| Monitoring Gaps | Metrics not reporting | < 4 hours |

### P3 - Low (Response Within 24 Hours)

| Incident Type | Description | Response Time |
|--------------|-------------|---------------|
| Minor Bugs | Non-critical functionality issues | < 24 hours |
| Documentation Gaps | Missing or incorrect docs | < 24 hours |
| Performance Degradation | Slower than expected but operational | < 24 hours |

---

## Response Procedures

### P0 Critical Response

```
1. IMMEDIATE (0-5 minutes)
   ├── Trigger PagerDuty alert
   ├── Join #incident-response Slack channel
   ├── Execute emergency pause:
   │   • Ethereum: FluxeBridge.pause() + FluxeRollup.pause()
   │   • Solana: fluxe_bridge::pause
   └── Notify: CTO, Security Lead, Ops Lead

2. TRIAGE (5-30 minutes)
   ├── Identify affected components
   ├── Estimate impact (users, funds)
   ├── Collect initial evidence
   └── Assign incident commander

3. INVESTIGATE (30-120 minutes)
   ├── Root cause analysis
   ├── Determine scope of compromise
   ├── Identify remediation steps
   └── Prepare public communication

4. REMEDIATE (as needed)
   ├── Deploy fix if applicable
   ├── Coordinate with auditors
   ├── Resume operations (staged)
   └── Post-incident review
```

### P1 High Response

```
1. ALERT (0-15 minutes)
   ├── Check monitoring dashboards
   ├── Verify alert is not false positive
   └── Notify on-call engineer

2. DIAGNOSE (15-45 minutes)
   ├── Check sequencer logs
   ├── Check RPC connectivity
   ├── Check storage health
   └── Identify root cause

3. RESOLVE (45-90 minutes)
   ├── Apply fix or workaround
   ├── Verify resolution
   └── Document findings
```

---

## Playbooks

### Playbook: Bridge Pause Procedure

**When to use:** Any suspected exploit, significant anomaly, or P0 incident.

```bash
# 1. Pause Ethereum Bridge
cast send $BRIDGE_ADDRESS "pause()" --private-key $ADMIN_KEY --rpc-url $ETH_RPC

# 2. Pause Ethereum Rollup
cast send $ROLLUP_ADDRESS "pause()" --private-key $ADMIN_KEY --rpc-url $ETH_RPC

# 3. Pause Solana Bridge
solana program invoke $BRIDGE_PROGRAM_ID pause --keypair $ADMIN_KEYPAIR

# 4. Verify paused state
cast call $BRIDGE_ADDRESS "paused()" --rpc-url $ETH_RPC
# Should return: true
```

**Post-pause actions:**
1. Notify users via status page
2. Disable deposit UI
3. Monitor for any in-flight transactions

### Playbook: Sequencer Restart

**When to use:** Sequencer unresponsive or crashed.

```bash
# 1. Check sequencer status
systemctl status fluxe-sequencer

# 2. Check logs for errors
journalctl -u fluxe-sequencer -n 100

# 3. Restart sequencer
systemctl restart fluxe-sequencer

# 4. Verify recovery
curl http://localhost:8080/health
# Should return: {"status": "healthy"}

# 5. Check batch production
curl http://localhost:8080/batch/status
```

**If restart fails:**
1. Check disk space: `df -h`
2. Check memory: `free -m`
3. Check RocksDB corruption: `ldb --db=/var/fluxe/data repair`
4. Restore from backup if needed

### Playbook: State Recovery from Backup

**When to use:** Data corruption or need to revert to known-good state.

```bash
# 1. Stop sequencer
systemctl stop fluxe-sequencer

# 2. Backup current state
mv /var/fluxe/data /var/fluxe/data.corrupt.$(date +%s)

# 3. Restore from backup
aws s3 cp s3://fluxe-backups/state-$BATCH_ID.tar.gz /tmp/
tar -xzf /tmp/state-$BATCH_ID.tar.gz -C /var/fluxe/

# 4. Verify restoration
ls -la /var/fluxe/data/

# 5. Start sequencer
systemctl start fluxe-sequencer

# 6. Verify sync
curl http://localhost:8080/batch/status
```

### Playbook: Reorg Handling

**When to use:** L1 blockchain reorganization detected.

```
1. DETECT
   - Alert: "ReorgDetected" from monitoring
   - Check depth of reorg

2. ASSESS
   - If depth < finality threshold: Auto-recovery expected
   - If depth >= finality threshold: Manual intervention needed

3. FOR DEEP REORG:
   a. Pause bridge
   b. Identify affected batches
   c. Revert to last confirmed state
   d. Re-process affected transactions
   e. Resume operations
```

### Playbook: Invalid Proof Response

**When to use:** Proof verification fails on-chain or off-chain.

```
1. IMMEDIATE
   - Stop accepting new transactions
   - Identify failing batch

2. DIAGNOSE
   - Check proof inputs match expected
   - Verify VK matches circuit
   - Check for witness generation errors

3. IF CIRCUIT BUG:
   - Pause bridge
   - Notify security team
   - Assess if exploit possible
   - Plan VK rotation if needed

4. IF TRANSIENT ERROR:
   - Re-generate proof
   - Verify before submission
   - Resume operations
```

### Playbook: Supply Imbalance Resolution

**When to use:** Pool balance discrepancy between chains.

```
1. DETECT
   - Alert: "SupplyImbalance" from monitoring
   - Check: Global supply != Sum of chain pools

2. INVESTIGATE
   - Query all deposit events
   - Query all withdrawal events
   - Compare with state manager records

3. IF ACCOUNTING ERROR:
   - Identify missing/duplicate entries
   - Apply correction to state
   - Verify invariant restored

4. IF ACTUAL IMBALANCE (Cross-chain withdrawals > deposits):
   - Check if within tolerance
   - Plan rebalancing if needed
   - Monitor liquidity levels
```

### Playbook: Hot Wallet Compromise

**When to use:** Sequencer private key suspected compromised.

```
1. IMMEDIATE (P0 Response)
   - Pause all bridges
   - Revoke compromised key permissions
   - Generate new keypair

2. ASSESS DAMAGE
   - Check for unauthorized transactions
   - Identify any stolen funds
   - Document timeline

3. RECOVER
   - Deploy new sequencer with new keys
   - Update on-chain sequencer address
   - Resume operations with new key

4. POST-INCIDENT
   - Root cause analysis
   - Improve key management
   - Consider HSM deployment
```

---

## Communication

### Internal Communication

| Channel | Purpose | Participants |
|---------|---------|--------------|
| #incident-response | Active incident coordination | All responders |
| #ops-alerts | Automated monitoring alerts | Ops team |
| PagerDuty | On-call escalation | On-call rotation |
| Video call | War room for P0/P1 | Incident commander + team |

### External Communication

| Audience | Channel | Timing |
|----------|---------|--------|
| Users | Status page | Within 15 min of P0/P1 |
| Users | Twitter | Within 30 min of P0/P1 |
| Affected users | Email | Within 1 hour if funds impacted |
| Community | Discord | Regular updates during incident |

### Communication Templates

**Status Page - Investigating:**
```
[Investigating] - FLUXE Service Disruption
We are investigating reports of [brief description].
Operations may be temporarily affected.
Last updated: [timestamp]
```

**Status Page - Identified:**
```
[Identified] - FLUXE Service Disruption
We have identified the issue: [brief description].
We are working on a fix. ETA: [if known]
Last updated: [timestamp]
```

**Status Page - Resolved:**
```
[Resolved] - FLUXE Service Disruption
The issue has been resolved. [Brief explanation]
Normal operations have resumed.
Last updated: [timestamp]
```

---

## Post-Incident

### Root Cause Analysis Template

```markdown
# Incident Report: [INCIDENT-YYYY-MM-DD-#]

## Summary
- **Severity:** P0/P1/P2/P3
- **Duration:** [start time] - [end time] ([duration])
- **Impact:** [users affected, funds at risk, etc.]
- **Status:** Resolved / Ongoing

## Timeline
| Time (UTC) | Event |
|------------|-------|
| HH:MM | Initial alert triggered |
| HH:MM | On-call paged |
| ... | ... |
| HH:MM | Resolution confirmed |

## Root Cause
[Detailed technical explanation]

## Resolution
[What was done to fix the issue]

## Impact Assessment
- Users affected: [number]
- Transactions affected: [number]
- Financial impact: [if any]

## Action Items
- [ ] [Preventive measure 1]
- [ ] [Preventive measure 2]
- [ ] [Documentation update]

## Lessons Learned
[What we learned and how to prevent recurrence]
```

### Retrospective Process

1. **Schedule:** Within 48 hours of resolution
2. **Attendees:** All incident responders + relevant stakeholders
3. **Agenda:**
   - Timeline review (blameless)
   - What went well
   - What could be improved
   - Action items assignment
4. **Output:** Published incident report

---

## Escalation Matrix

| Severity | Initial Responder | Escalate To (15 min) | Escalate To (1 hr) |
|----------|-------------------|---------------------|-------------------|
| P0 | On-call engineer | Security Lead + CTO | CEO + Legal |
| P1 | On-call engineer | Ops Lead | CTO |
| P2 | On-call engineer | Ops Lead | - |
| P3 | On-call engineer | - | - |

---

## On-Call Rotation

### Schedule
- Primary: 24/7 coverage, 1-week rotations
- Secondary: Backup for escalation
- Manager: Available for P0/P1

### Responsibilities
- Acknowledge alerts within 5 minutes
- Begin triage immediately
- Escalate if beyond expertise
- Document all actions taken

### Handoff Procedure
1. Review active incidents
2. Check pending alerts
3. Verify monitoring health
4. Update handoff notes
