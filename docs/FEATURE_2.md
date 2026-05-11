# Feature 2: Wallet Drain Protection

**Status:** 📋 NOT STARTED

**What it does:** Blocks transactions that would drain more than X% of your wallet balance.

---

## Quick Summary

```
Policy: drainBps = 4000 (40%)
Wallet balance: 100 ETH
User tries to send: 60 ETH
Result: BLOCKED (60% > 40% limit)
```

---

## The Problem Feature 1 Doesn't Solve

Feature 1 has a hard limit: "max 1 ETH per tx"

But this doesn't scale:
- Rich wallet: 1,000 ETH → 1 ETH limit is too restrictive
- Poor wallet: 1 ETH → 1 ETH limit is too restrictive

**Feature 2 solves this:** Limits based on percentage of balance.

---

## Architecture

### What Changes

```
Before (Feature 1):
PolicyStorage.Policy {
    uint256 spendingThreshold;  // absolute limit
    bool active;
}

After (Feature 1 + 2):
PolicyStorage.Policy {
    uint256 spendingThreshold;  // absolute limit
    uint16 drainBps;            // NEW: percentage limit (in basis points)
    bool active;
}
```

**Basis points:** 1 bps = 0.01%. 10,000 bps = 100%.
- 4000 bps = 40%
- 5000 bps = 50%
- 10000 bps = 100% (no real limit)

### Data Flow

```
1. User tries to send 60 ETH (wallet has 100 ETH)
2. Guard calls PolicyEngine.evaluate()
3. Engine reads both policies:
   - spendingThreshold: 1 ETH
   - drainBps: 4000 (40%)
4. Engine checks threshold: 60 > 1? YES → RequireDelay (this alone blocks it)
5. Engine also checks drain:
   - balance: 100 ETH
   - maxAllowed: (100 * 4000) / 10000 = 40 ETH
   - sending: 60 ETH > 40 ETH? YES → RequireDelay
6. Either policy blocks → requires delay
```

---

## Implementation Plan

### Step 1: Update PolicyStorage.Policy

Add `drainBps` field:
```solidity
struct Policy {
    uint256 spendingThreshold;     // Feature 1
    uint16 drainBps;               // Feature 2: basis points
    bool active;
}
```

### Step 2: Update PolicyEngine.evaluate()

Add drain check after threshold check:
```solidity
// NEW: Drain check
uint256 balance = ctx.account.balance;
uint256 maxDrain = (balance * policy.drainBps) / 10000;
if (ctx.value > maxDrain) {
    return (Decision.RequireDelay, keccak256("DRAIN_LIMIT_EXCEEDED"));
}
```

### Step 3: Write Tests

See "Testing" section below.

---

## Threat Model

### Threat 1: Rounding Errors
**Attack:** Use integer division to bypass limits
**Defense:** Rounding is conservative (in wallet's favor)
**Risk:** Low

### Threat 2: Balance Changes Mid-TX
**Attack:** Drain happens between policy check and execution
**Defense:** Safe is single-tx, checks at execution time
**Risk:** None

### Threat 3: Zero Balance
```
balance = 0 ETH
drainBps = 4000
maxDrain = 0
→ Any send is blocked
```
**Behavior:** Correct (can't drain empty wallet)

---

## Testing Checklist

For Feature 2, create these tests:

**Unit Tests (8-10):**
- [ ] Below drain limit → Allow
- [ ] Above drain limit → RequireDelay
- [ ] Exactly at drain limit → Allow
- [ ] Zero balance → blocks any send
- [ ] Very small percentage (rounding) → correct
- [ ] Both threshold AND drain trigger → blocked
- [ ] Inactive policy → allow anything
- [ ] Different accounts have isolated drainBps

**Fuzz Tests (2):**
- [ ] testFuzz_WithinDrainLimit (1000 runs)
- [ ] testFuzz_ExceedsDrainLimit (1000 runs)

**Attack Tests (2):**
- [ ] Cannot bypass with rounding tricks
- [ ] Cannot use chunking (Feature 4 catches it)

---

## Code Changes Summary

```
contracts/src/core/PolicyStorage.sol
  - Add drainBps: uint16 to Policy struct
  - Update scheduleUpdate() / executeUpdate()

contracts/src/core/PolicyEngine.sol
  - Add drain percentage check in evaluate()
  - Return DRAIN_LIMIT_EXCEEDED reason code

contracts/test/unit/PolicyEngine.t.sol
  - Add 10-12 new tests for drain logic
```

No changes needed to PolicyGuard or SafeIntegration.

---

## Estimated Effort

- Code: 2-3 hours
- Tests: 2-3 hours  
- Total: 4-6 hours

---

## Success Criteria

✅ All tests pass (50+ total)
✅ Drain limit enforced correctly
✅ Edge cases handled properly
✅ Rounding is conservative
✅ Code is clean

---

Last updated: 2026-05-11
