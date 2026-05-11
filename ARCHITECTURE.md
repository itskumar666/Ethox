# Ethox Architecture

## System Overview

```
User's Safe Wallet (Ethereum Smart Contract)
    ↓
    ├─→ PolicyGuard (checks policy before execution)
    │      ↓
    │   PolicyEngine (evaluates: is this tx safe?)
    │      ↓
    │   PolicyStorage (fetches account's policies)
    │
    ├─→ DelayModule (queues risky txs for later)
    │      ↓
    │   (24-hour cooldown)
    │      ↓
    │   Guardian Module (requires approval)
    │
    └─→ Regular execution if all policies pass
```

**Key concept:** The Safe is the boss. We just add checks before it executes transactions.

---

## Data Flow: A Normal Transaction

```
1. User signs a Safe transaction
2. Safe.execTransaction() is called
3. Safe calls PolicyGuard.checkTransaction()
   └─→ PolicyGuard calls PolicyEngine.evaluate()
       └─→ PolicyEngine fetches policy from PolicyStorage
       └─→ PolicyEngine checks: is tx valid?
           ├─ YES → returns Allow
           └─ NO → returns RequireDelay or Block
4. If Allow: transaction executes normally
5. If RequireDelay: Safe transaction REVERTS, user must use DelayModule instead
6. If Block: transaction REVERTS, cannot proceed
```

---

## Data Flow: A Risky Transaction (Delayed)

```
1. User tries to send 10 ETH (threshold is 1 ETH)
2. Safe.execTransaction() → PolicyGuard.checkTransaction() → REVERT
3. User is informed: "This violates your policy. Use 24h delay?"
4. User calls DelayModule.queue(tx)
5. DelayModule stores tx with unlockAt = block.timestamp + 24 hours
6. User waits 24 hours
7. Anyone can call DelayModule.execute(txId)
8. DelayModule re-checks policy (in case it changed)
9. If still valid, DelayModule executes via Safe.execTransactionFromModule()
10. Transaction executes
```

**Critical:** Policies are re-checked at execution time. Prevents attackers from weakening policy mid-delay.

---

## The Three Layers of Code

### Layer 1: On-Chain Storage (PolicyStorage.sol)

**Purpose:** Store what rules apply to each account.

**What it stores:**
- Spending threshold (max ETH per tx)
- Drain protection % (max % of balance)
- First-interaction flag (is this contract known?)
- Cooldown duration
- Guardian addresses

**Key property:** Changes have a **24-hour timelock**. Cannot be instantly disabled.

**Who can change it:** The Safe itself (through its own multi-sig process).

### Layer 2: On-Chain Evaluation (PolicyEngine.sol)

**Purpose:** Decide if a transaction is allowed, blocked, or requires delay.

**Input:** A transaction context (to, value, data, operation) + the account's policy.

**Output:** `Decision` (Allow / Block / RequireDelay) + reason code.

**Why it's separate:** We can upgrade evaluation logic without touching stored policies.

### Layer 3: Safe Integration (PolicyGuard.sol)

**Purpose:** Intercept Safe transactions and enforce policies.

**How:** Safe has a "Guard" hook. Before `execTransaction()`, Safe calls Guard.

**What it does:**
1. Extract transaction details
2. Call PolicyEngine.evaluate()
3. If Allow: do nothing (let it execute)
4. If RequireDelay or Block: revert (transaction fails)

**Why this works:** A Guard that reverts prevents the entire transaction.

---

## The Two Paths Through a Safe

### Direct Path (Fast)
```
User signs → Safe.execTransaction() → Guard checks → Allow → Executes
```

**When:** Low-risk transactions that pass all policies.

**Time:** Instant.

### Delayed Path (Safe)
```
User signs → Safe.execTransaction() → Guard checks → RequireDelay → REVERT
                                                           ↓
                                                    User calls
                                                    DelayModule.queue()
                                                           ↓
                                                       Waits 24h
                                                           ↓
                                                  DelayModule.execute()
                                                           ↓
                                                     Executes safely
```

**When:** High-risk transactions (over threshold, large balance drain, etc.)

**Time:** 24 hours + ability to cancel anytime.

---

## Trust Model

### What Ethox Protects
- Your funds from unauthorized drains
- Your tokens from malicious approvals
- Your wallet from phishing contracts

### What Ethox Does NOT Protect
- If your Safe owner keys are compromised, attacker has 24h before full control (because of timelock)
- If your Safe itself has a bug, Ethox can't save you (audits fix this)
- If you manually disable the Guard, protection is gone (you chose to)

### The Invariant
**No single person/contract can instantly drain your wallet** (assuming Guard is active and policy is sensible).

---

## On-Chain vs Off-Chain

### On-Chain (Contracts)
- Hard rules: threshold, drain %, cooldown
- Cannot be bypassed
- Gas costs (small, optimized)
- Deterministic

### Off-Chain (Backend)
- Advisory warnings
- Risk scoring (heuristics)
- Contract labeling (is this address a scam?)
- User-friendly policies
- Can be bypassed if user ignores warnings

**Why split?**
- Hard rules MUST be on-chain or they're theater
- Heuristics are too complex for on-chain
- User experience requires a backend

---

## Feature Layering

Each feature builds on the previous:

```
Feature 1: Spending Threshold
    └─→ Blocks if tx.value > limit

Feature 2: Wallet Drain Protection
    └─→ Blocks if (tx.value / balance) > threshold

Feature 3: Unknown Contract Warning
    └─→ Blocks first interaction with unknown contract

Feature 4: Rapid Transaction Detection
    └─→ Locks down if 3+ txs in 60 seconds

Feature 5: Approval Monitoring
    └─→ Blocks unlimited token approvals

Feature 6: Cooldown / Time-Lock
    └─→ DelayModule queues & executes after delay

Feature 7: Guardian System
    └─→ Guardian can approve/veto risky transactions
```

Each adds more data to PolicyStorage, more logic to PolicyEngine.

---

## Attack Surface

### Threat 1: Owner Key Compromise
**Attack:** Attacker steals owner key, tries to immediately drain.
**Ethox defense:** 24h timelock on policy changes. Attacker can weaken policy, but must wait. You see it, cancel.

### Threat 2: Phishing Approval
**Attack:** User signs malicious `approve(attacker, MAX_INT)` for fake token.
**Ethox defense:** Feature 5 flags unlimited approvals. Feature 3 flags unknown contracts.

### Threat 3: Rapid Drain via Batched Txs
**Attack:** Attacker calls 3 separate transactions in 10 seconds to bypass per-tx limits.
**Ethox defense:** Feature 4 detects rapid-tx pattern and locks down.

### Threat 4: Guard Removal
**Attack:** Owner calls `Safe.setGuard(address(0))` to remove all protection.
**Ethox defense:** None (this is a Safe-level limitation). But events alert the backend, which alerts the user.

### Threat 5: Reentrancy
**Attack:** During Guard.checkTransaction, a malicious contract re-enters and manipulates state.
**Ethox defense:** No state writes in checkTransaction. All state writes in checkAfterExecution.

---

## Gas Efficiency

PolicyGuard runs on EVERY Safe transaction. It must be cheap.

**Current cost (Feature 1):**
- Read policy from storage: ~2200 gas
- Policy evaluation (threshold check): ~100 gas
- **Total: ~2300 gas per transaction**

This is negligible. A typical Safe tx is 50k-200k gas.

---

## Deployment Model

### Phase 1: Testnet (Base Sepolia)
- Deploy contracts
- Test end-to-end
- User feedback

### Phase 2: Mainnet
- Deploy on Base L2 (low gas, good UX)
- Support from frontend SDK

### Future
- Cross-chain support
- Mobile wallet integration
- Guardian-as-a-Service business model

---

## How Policies Work

A policy is a struct:

```solidity
struct Policy {
    uint256 spendingThreshold;  // max ETH per tx
    uint16 drainBps;            // max % of balance
    uint32 cooldownSeconds;     // delay on risky txs
    uint16 rapidTxLimit;        // max txs in window
    uint32 rapidTxWindow;       // time window for rapid-tx detection
    bool blockUnknownContracts; // require first-interaction delay
    bool active;                // is protection on?
}
```

**PolicyStorage** holds one per account.

**PolicyEngine** reads it and evaluates transactions.

**Changes are timelocked** — 24 hours before taking effect.

---

## Code Organization

```
contracts/src/
│
├── core/                        # Policy management
│   ├── PolicyStorage.sol        # Store policies, handle timelocks
│   └── PolicyEngine.sol         # Evaluate transactions
│
├── safe/                        # Safe integration
│   ├── PolicyGuard.sol          # Pre-execution guard
│   ├── DelayModule.sol          # Delayed execution + cooldowns
│   └── GuardianModule.sol       # Multi-sig guardian approval
│
├── interfaces/                  # External interfaces
│   └── (coming)
│
└── libraries/                   # Shared utilities
    └── (coming)

contracts/test/
│
└── unit/
    ├── PolicyStorage.t.sol      # Policy storage tests
    ├── PolicyEngine.t.sol       # Evaluation logic tests
    └── PolicyGuard.t.sol        # Safe integration tests
```

Each contract has a **single responsibility**:
- PolicyStorage: store & timelock
- PolicyEngine: evaluate
- PolicyGuard: intercept

---

## The Why Behind Design Choices

### Why is timelock 24 hours?
- Long enough to notice an attack
- Short enough for legitimate policy changes
- Standard in DeFi (Aave, Compound, others)

### Why separate storage from evaluation?
- Evaluation logic can be upgraded without migrating policies
- Audit surface is smaller
- More flexible for future features

### Why block DelegateCall?
- Delegatecall lets a contract run as your Safe
- This is a privilege escalation
- Almost never needed for normal operations

### Why re-check policy at execution time?
- Attacker compromises key, schedules weak policy change
- Schedules a risky tx for after the 24h window
- Sets policy back to normal before 24h expires
- Without re-check, the risky tx still executes (oops)

---

## Next Steps

1. **Understand the code:** Read the contracts in `contracts/src/`
2. **Run the tests:** `forge test -vv`
3. **Build Feature 2:** Read docs/FEATURE_2.md

---

Last updated: 2026-05-11
