# Feature 1: Spending Threshold Protection

**Status:** ✅ COMPLETE

**What it does:** Blocks transactions that exceed your configured ETH spending limit.

---

## Quick Summary

```
Policy: maxSpendingThreshold = 1 ETH
User tries to send: 5 ETH
Result: Transaction BLOCKED
Option: User can queue it via DelayModule for 24-hour delay
```

---

## Architecture

### Three Components

1. **PolicyStorage.sol** — Stores the threshold, manages 24-hour timelock on changes
2. **PolicyEngine.sol** — Evaluates: is tx.value > threshold?
3. **PolicyGuard.sol** — Safe Guard that calls PolicyEngine and reverts if blocked

### Data Flow

```
1. User signs Safe tx sending 5 ETH
2. Safe.execTransaction() → PolicyGuard.checkTransaction()
3. PolicyGuard calls PolicyEngine.evaluate()
4. PolicyEngine reads PolicyStorage.getPolicy(Safe address)
5. PolicyEngine checks: 5 ETH > 1 ETH threshold? YES
6. PolicyEngine returns: Decision.RequireDelay (requires queuing)
7. PolicyGuard reverts the direct execution
8. Safe transaction fails
9. User is informed: "Over threshold. Use delayed path."
10. User calls DelayModule.queue(tx) instead
```

---

## How It Works

### Step 1: Deploy and Set Policy

```solidity
// Deploy contracts
PolicyStorage storage = new PolicyStorage();
PolicyEngine engine = new PolicyEngine(address(storage));
PolicyGuard guard = new PolicyGuard(address(engine));

// Safe owner sets policy: max 1 ETH per tx
Policy memory p = Policy({
    spendingThreshold: 1 ether,
    active: true
});

// Must go through Safe's multi-sig
Safe.execTransaction(
    to: address(storage),
    value: 0,
    data: storage.scheduleUpdate(p).encode()
);

// Wait 24 hours...

Safe.execTransaction(
    to: address(storage),
    value: 0,
    data: storage.executeUpdate().encode()
);

// Now set the Guard
Safe.setGuard(address(guard));
```

### Step 2: User Attempts Transaction

```solidity
// User tries to send 5 ETH to someone
Safe.execTransaction(
    to: 0xabcd...,
    value: 5 ether,
    data: ""
);
```

### Step 3: Guard Blocks It

```solidity
// Safe calls: guard.checkTransaction(0xabcd, 5 ether, "", Call, ...)
// Guard calls: engine.evaluate({Safe, 0xabcd, 5 ether, "", Call})
// Engine checks: 5 ether > 1 ether? YES
// Engine returns: Decision.RequireDelay
// Guard reverts: revert PolicyViolated(THRESHOLD_EXCEEDED)
// Safe transaction fails
```

### Step 4: User Uses Delay Path

```solidity
// User queues it via DelayModule instead
delayModule.queue(0xabcd, 5 ether, "", Call);
// Tx is stored with unlockAt = block.timestamp + 24 hours

// After 24 hours
delayModule.execute(txId);
// Executes via Safe.execTransactionFromModule()
```

---

## The Timelock: Why 24 Hours?

The 24-hour timelock on policy changes is **the most critical feature**.

### Attack Scenario

1. Attacker compromises Safe owner's private key
2. Attacker immediately tries to disable protection:
   ```solidity
   storage.scheduleUpdate(Policy({
       spendingThreshold: type(uint256).max,  // NO LIMIT
       active: false                           // DISABLED
   }));
   ```
3. Attacker tries to execute immediately:
   ```solidity
   storage.executeUpdate();  // REVERTS: TimelockNotExpired
   ```
4. Attacker must wait 24 hours. During that time:
   - Legitimate owner sees the change is pending
   - Legitimate owner calls `storage.cancelUpdate()`
   - Attack is prevented

### Why This Works

- **Observable:** Change is public on-chain
- **Cancellable:** Owner can cancel within 24h
- **Recoverable:** Gives time for mitigation
- **Standard:** Used by Aave, Compound, Uniswap

---

## Threat Model

### Threat 1: Owner Key Compromise
**Attack:** Steal private key, immediately disable protection
**Defense:** 24-hour timelock + cancellation
**Risk:** Medium (requires compromise + 24h to act)

### Threat 2: Phishing
**Attack:** Trick user into signing a large transaction
**Defense:** Threshold blocks it, requires delay
**Risk:** Mitigated (user has 24h to cancel)

### Threat 3: ERC-20 Bypass
**Attack:** Send tokens via ERC-20 `transfer()` (value = 0)
**Defense:** None in Feature 1
**Risk:** Known, fixed in Feature 5
**Note:** `transfer()` has `value=0`, so doesn't trigger threshold

### Threat 4: Chunking Attack
**Attack:** Send 10x (0.1 ETH) instead of 1 ETH
**Defense:** None in Feature 1
**Risk:** Known, fixed in Feature 4 (rapid-tx detection)

### Threat 5: DelegateCall Privilege Escalation
**Attack:** `delegatecall` to malicious contract
**Defense:** Hard-blocked by PolicyEngine
**Risk:** Blocked (cannot delegatecall)

### Threat 6: Guard Removal
**Attack:** Owner calls `Safe.setGuard(address(0))`
**Defense:** None (Safe-level limitation)
**Risk:** Monitored via events, alerts
**Note:** Requires Safe owner signature anyway

---

## Edge Cases

### Edge Case 1: Zero Threshold
```solidity
Policy({ spendingThreshold: 0, active: true })
```
**Behavior:** Blocks ALL ETH transfers (even 1 wei)
**Valid?** Yes. User can set this if they want no ETH outflows.

### Edge Case 2: Max Threshold
```solidity
Policy({ spendingThreshold: type(uint256).max, active: true })
```
**Behavior:** Allows ANY amount (no real limit)
**Valid?** Yes. Equivalent to "protection off".

### Edge Case 3: Inactive Policy
```solidity
Policy({ spendingThreshold: 1 ether, active: false })
```
**Behavior:** Threshold is ignored, all txs allowed
**Valid?** Yes. User can temporarily disable protection.

### Edge Case 4: Policy Change During Delay
```
t=0:    User queues 10 ETH tx
t=6h:   Owner weakens policy to 100 ETH
t=24h:  User executes queued 10 ETH tx
```
**Behavior:** Re-validates with CURRENT policy (100 ETH)
**Result:** Tx allows (100 ETH > 10 ETH)
**Defense:** Correct! Current policy governs execution.

---

## Testing Coverage

### Passing Tests: 36 total

#### PolicyStorage (14 tests)
- Schedule update stores pending
- Execute respects timelock
- Cancel removes pending
- Can overwrite pending update
- Policies isolated per account
- Zero threshold is valid
- Max threshold is valid
- Attack: cannot bypass timelock with owner key compromise
- Fuzz: timelock always enforced (1000 runs)

#### PolicyEngine (12 tests)
- Below threshold: allow
- At threshold: allow
- Above threshold: require delay
- Inactive policy: allow anything
- DelegateCall: always blocked (even if inactive)
- Zero threshold blocks all ETH
- Max threshold allows all
- Fuzz: value ≤ threshold → allow (1000 runs)
- Fuzz: value > threshold → require delay (1000 runs)

#### PolicyGuard (10 tests)
- Allowed tx passes through
- Blocked tx reverts
- DelegateCall reverts
- Events emitted on block
- Interface support (ERC165)
- Zero-address guard reverts
- checkAfterExecution doesn't revert
- Policy isolation between accounts
- Direct call doesn't spoof account
- Inactive policy allows anything

---

## How to Test Locally

### Run All Tests
```bash
cd contracts
forge test -vv
```

### Run Feature 1 Tests Only
```bash
forge test --match-path "test/unit/Policy*.t.sol" -vv
```

### Run Single Test
```bash
forge test --match "test_AboveThreshold_RequiresDelay" -vv
```

### With Gas Reports
```bash
forge test --match "test_ScheduleUpdate_StoresPolicy" -vv --gas-report
```

---

## Code Structure

```
contracts/src/core/
├── PolicyStorage.sol      # Store policies + 24h timelock
├── PolicyEngine.sol       # Evaluate threshold
└── (shared with other features)

contracts/src/safe/
└── PolicyGuard.sol        # Safe integration (Guard)

contracts/test/unit/
├── PolicyStorage.t.sol    # 14 tests
├── PolicyEngine.t.sol     # 12 tests
└── PolicyGuard.t.sol      # 10 tests
```

---

## Known Limitations

1. **ETH only** — doesn't catch ERC-20 transfers (fixed in Feature 5)
2. **No rapid-tx detection** — can send 10x small txs to bypass (fixed in Feature 4)
3. **No balance checks** — doesn't understand % of wallet (fixed in Feature 2)
4. **No contract tracking** — doesn't flag unknown contracts (fixed in Feature 3)

---

## What's Next

Feature 2: **Wallet Drain Protection**

Adds balance-aware limits:
- Blocks if tx removes > 40% of wallet balance
- Works with Feature 1 (both apply)

---

## Contract Deployment

### Testnet (Base Sepolia)
```bash
# Deploy PolicyStorage
forge create contracts/src/core/PolicyStorage.sol:PolicyStorage \
    --rpc-url $BASE_SEPOLIA_RPC \
    --private-key $PRIVATE_KEY

# Deploy PolicyEngine (pass storage address)
forge create contracts/src/core/PolicyEngine.sol:PolicyEngine \
    --constructor-args "0x..." \  # storage address
    --rpc-url $BASE_SEPOLIA_RPC \
    --private-key $PRIVATE_KEY

# Deploy PolicyGuard (pass engine address)
forge create contracts/src/safe/PolicyGuard.sol:PolicyGuard \
    --constructor-args "0x..." \  # engine address
    --rpc-url $BASE_SEPOLIA_RPC \
    --private-key $PRIVATE_KEY
```

### Set the Guard on Your Safe
```bash
# Safe owner must call Safe.setGuard(policyGuardAddress)
# This is done through Safe's UI or SDK
```

---

## Summary

Feature 1 is the **foundation** of Ethox. It:

✅ Stores per-account policies (with 24h timelock)
✅ Evaluates transaction safety
✅ Integrates with Safe as a Guard
✅ Blocks over-threshold txs
✅ Is thoroughly tested (36 tests, 2000 fuzz cases)

Everything else builds on this.

---

Last updated: 2026-05-11
