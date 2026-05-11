# Ethox: 7 Features in 7 Phases

This document breaks down all 7 features, what each does, and the order to build them.

---

## The Sequence

Build features in this order. Each builds on the previous.

```
Phase 1: Spending Threshold
    ↓ (base: PolicyStorage + PolicyEngine + PolicyGuard)
Phase 2: Wallet Drain Protection
    ↓ (adds: balance-aware evaluation)
Phase 3: Unknown Contract Warning
    ↓ (adds: contract tracking)
Phase 4: Rapid Transaction Detection
    ↓ (adds: time-window sliding counter)
Phase 5: Approval Monitoring
    ↓ (adds: calldata decoding for approve() calls)
Phase 6: Cooldown / Time-Lock
    ↓ (adds: DelayModule for queuing)
Phase 7: Guardian System
    ↓ (adds: GuardianModule + multi-sig)
```

---

## Phase 1: Spending Threshold ✅ DONE

**Status:** Complete. 36 tests passing.

**What it does:**
Blocks transactions that send more ETH than your configured limit.

**Example:**
- Your threshold: 1 ETH
- You try to send: 5 ETH
- Ethox: "Blocked. Use 24-hour delay to override."

**Contracts:**
- `PolicyStorage.sol` — stores threshold + manages 24h timelock on changes
- `PolicyEngine.sol` — evaluates: is value > threshold?
- `PolicyGuard.sol` — Safe Guard that intercepts txs

**Tests:**
- 14 tests for PolicyStorage (schedule, execute, cancel, timelock)
- 12 tests for PolicyEngine (threshold logic, edge cases, fuzz)
- 10 tests for PolicyGuard (Safe integration, events)

**Threat model:**
- Owner key compromise: 24h timelock prevents instant disable
- ERC-20 bypass: known limitation (fixed in Phase 5)
- Chunking attack: fixed in Phase 4

**Next:** Feature 2

---

## Phase 2: Wallet Drain Protection

**What it does:**
Blocks transactions that would remove more than X% of your wallet balance.

**Example:**
- Your wallet: 100 ETH
- Drain threshold: 40%
- You try to send: 60 ETH
- Ethox: "Blocked. This removes 60% of your balance."

**Why it's different from threshold:**
- Threshold is absolute (1 ETH limit)
- Drain % is relative (40% of whatever you have)
- Prevents drains on wealthy accounts

**Contracts:**
- Modify `PolicyStorage.sol` to add `drainBps` field
- Modify `PolicyEngine.sol` to evaluate drain %
- `PolicyGuard.sol` stays the same

**Data flow:**
1. User tries tx sending 60 ETH from 100 ETH wallet
2. Guard calls `PolicyEngine.evaluate()`
3. Engine reads policy: `drainBps = 4000` (40%)
4. Engine calculates: `60 / 100 = 60% > 40%`
5. Engine returns: `RequireDelay`
6. Guard reverts the direct tx
7. User must use DelayModule path instead

**Tests needed:**
- Evaluate drain % correctly
- Edge cases: wallet balance = 0, single wei left
- Fuzz: random balance + tx amount

**Threat model:**
- Rounding errors (use basis points, not percentages)
- Flash loan attack (not applicable here, we check at tx time)
- Balance read race condition (Safe is single-threaded)

**Next:** Feature 3

---

## Phase 3: Unknown Contract Warning

**What it does:**
Requires a delay before first interaction with a new contract.

**Example:**
- You've never interacted with contract address 0x1234..
- You try to send ETH to it
- Ethox: "Unknown contract. Requires 24-hour delay."
- You wait 24h, then it executes

**Why this helps:**
- Phishing attacks use new/spoofed contracts
- First interaction is your first moment to notice something's wrong

**Contracts:**
- Modify `PolicyStorage.sol` to add contract interaction tracking
- Modify `PolicyEngine.sol` to check: is this contract known?
- Add new mapping: `mapping(address account => mapping(address contract => bool seen))`

**Data flow:**
1. User tries to interact with contract 0x1234
2. Guard calls `PolicyEngine.evaluate()`
3. Engine checks: `is 0x1234 in Safe's known contracts?`
4. If NO: return `RequireDelay`
5. If YES: continue evaluation (thresholds, drains, etc.)

**Tests needed:**
- First interaction blocks/delays
- Second interaction allows (if other policies pass)
- Multiple contracts tracked separately
- Fuzz: random contract addresses

**Threat model:**
- Attacker spoofs a known contract address (Ethox can't prevent, but UI shows warnings)
- User disabled feature (protection is off)

**Next:** Feature 4

---

## Phase 4: Rapid Transaction Detection

**What it does:**
Locks down wallet if 3+ transactions occur within a short time window.

**Example:**
- Cooldown window: 60 seconds
- Rapid tx limit: 3 transactions
- Attacker sends 5 txs in 30 seconds
- Ethox: "Rapid activity detected. Lock for 1 hour."

**Why this helps:**
- Drains often batch multiple txs quickly
- Sliding window catches patterns

**Contracts:**
- Modify `PolicyStorage.sol` to add rapid-tx tracking state
- Modify `PolicyEngine.sol` to evaluate rapid-tx pattern
- Use `checkAfterExecution()` to increment counters (post-execution)

**Data flow:**
1. Safe tx executes (passes all other policies)
2. Guard calls `checkAfterExecution()`
3. Guard reads last `txTimestamp` and `txCount` in window
4. If `block.timestamp - lastTx < window`: increment count
5. If count > limit: set `lockedUntil = now + 1 hour`
6. On next tx: check if `block.timestamp < lockedUntil`, if yes revert

**Tests needed:**
- Three txs in window triggers lock
- Two txs in window doesn't lock
- Time passes, lock expires, txs allowed
- Fuzz: random timestamps, counts

**Threat model:**
- Reentrancy in `checkAfterExecution()` (mitigated by using post-execution hook)
- Race condition on counter (Safe is single-threaded, not possible)

**Next:** Feature 5

---

## Phase 5: Approval Monitoring

**What it does:**
Flags and optionally blocks unlimited token approvals.

**Example:**
- You sign `approve(spender, MAX_INT)` for fake token
- Ethox: "Unlimited approval to unknown contract. Requires confirmation."
- You can confirm (if you trust the contract) or cancel

**Why this is critical:**
- Most token drains start with unlimited approval
- Users don't understand what they're approving

**Contracts:**
- Modify `PolicyEngine.sol` to decode ERC-20 calldata
- Check for `approve()` selector
- Extract spender + amount
- Block if amount == MAX_INT AND contract unknown

**Data flow:**
1. User signs tx to token contract with `approve(spender, big_amount)`
2. Guard extracts calldata
3. Guard decodes: identifies this is an `approve()` call
4. Guard reads: spender, amount
5. If amount >= threshold AND spender unknown: `RequireDelay`
6. User must confirm after delay

**Tests needed:**
- Decode `approve()` correctly
- Extract spender + amount
- Recognize MAX_INT approvals
- Edge cases: partial approvals (still high), low approvals
- Fuzz: random spender addresses, amounts

**Threat model:**
- Calldata parsing bugs (be very careful with parsing)
- Different token standards (ERC-20 primary, ERC-721 similar)

**Next:** Feature 6

---

## Phase 6: Cooldown / Time-Lock

**What it does:**
Queues risky transactions and requires a 24-hour wait before execution.

**Example:**
- You try to send 10 ETH (above 1 ETH limit)
- Direct execution reverts
- You call `DelayModule.queue(tx)` instead
- You wait 24 hours
- You (or anyone) call `DelayModule.execute(txId)`
- Transaction executes

**Why this is powerful:**
- Turns "instant + irreversible" into "24h reversible window"
- You have time to notice something's wrong
- You can cancel anytime before execution

**Contracts:**
- New contract: `DelayModule.sol` (Safe Module)
- Stores queued txs with `unlockAt` timestamp
- Re-validates policy at execution time
- Allows cancellation before execution

**Data flow:**
1. User signs Safe tx
2. Direct execution → PolicyGuard blocks (RequireDelay)
3. User creates new tx calling `DelayModule.queue(tx)`
4. DelayModule stores: `txId → {tx, unlockAt: now + 24h, executor}`
5. User waits 24h
6. Anyone calls `DelayModule.execute(txId)`
7. Module checks: is unlockAt in past?
8. Module re-validates: does policy still allow this?
9. Module executes via Safe.execTransactionFromModule()

**Tests needed:**
- Queue stores tx properly
- Execute reverts before timelock expires
- Execute succeeds after timelock
- Policy re-checked at execution time
- Cancel removes queued tx
- Multiple txs queued independently

**Threat model:**
- Attacker weakens policy during delay window, then executes
  - Mitigated: re-check at execution time
- Attacker cancels user's queued tx
  - Mitigated: only Safe owner can call cancel
- Gas griefing (very large tx queued)
  - Mitigated: gas limits in execute

**Next:** Feature 7

---

## Phase 7: Guardian System

**What it does:**
A trusted person (or entity) can approve or veto suspicious transactions.

**Example:**
- You set guardian = your trusted friend's wallet
- Risky tx is detected
- Guardian is notified
- Guardian approves: tx executes
- Or guardian vetoes: tx is rejected

**Why this is important:**
- Adds human judgment to automation
- Useful for enterprise wallets
- Foundation for "Guardian-as-a-Service" business model

**Contracts:**
- New contract: `GuardianModule.sol`
- Stores: `mapping(address => address[] guardians)`
- Stores: `mapping(address => uint8 threshold)` (M-of-N)
- Guardian can sign off-chain, module verifies signature

**Data flow:**
1. Risky tx detected → queued in DelayModule
2. Guardian is notified off-chain (backend service)
3. Guardian signs approval using their key
4. User/bot calls `GuardianModule.approve(txId, signature)`
5. Module verifies: signature is valid, signer is a guardian
6. Module records: guardian approved this tx
7. If M-of-N guardians approved: auto-execute or allow execution
8. If not enough approvals: wait for more guardians

**Tests needed:**
- Guardian signatures verified correctly
- M-of-N logic (1-of-1, 2-of-3, etc.)
- Only valid guardians can approve
- Signature replay protection
- Guardian can be added/removed (with timelock)

**Threat model:**
- Guardian key compromise (mitigated: M-of-N, not 1-of-1)
- Signature replay (use nonce + chainId)
- Guardian veto/approval can be delayed/intercepted (use off-chain service for notifications)

---

## Building Order Rationale

**Why this sequence?**

1. **Phase 1 (Threshold)**: Foundation. Everything else depends on PolicyEngine.
2. **Phase 2 (Drain %)**: Natural extension of Phase 1. Same data structure.
3. **Phase 3 (Unknown)**: Tracking contracts. Enables smarter decisions.
4. **Phase 4 (Rapid)**: Time-based detection. Foundation for Phase 6.
5. **Phase 5 (Approval)**: Calldata parsing. Enables token protection.
6. **Phase 6 (Cooldown)**: Queuing system. Major architectural addition.
7. **Phase 7 (Guardian)**: Human oversight. Built on top of queuing.

---

## Feature Interdependencies

```
Phase 1 (Threshold)
    ↓
Phase 2 (Drain)
    ↓
Phase 3 (Unknown)
    ↓
Phase 4 (Rapid) ← Phase 6 (Cooldown) depends on this
    ↓
Phase 5 (Approval)
    ↓
Phase 6 (Cooldown)
    ↓
Phase 7 (Guardian)
```

**You can't skip phases.** Each builds on the previous.

---

## Testing Strategy

For each phase:

1. **Unit tests** for each contract
2. **Integration tests** (Guard + Storage + Engine)
3. **Attack simulations** (how would an attacker exploit this?)
4. **Fuzz tests** (1000+ random inputs)
5. **Edge case tests** (boundary conditions)

---

## MVP Definition

**MVP = Phases 1-4 (+ tests)**

This gives you:
- Spending thresholds ✅
- Drain protection ✅
- Unknown contract warnings ✅
- Rapid transaction detection ✅
- Ability to extend with Phases 5-7

**Everything else is Phase 2+ work.**

---

Last updated: 2026-05-11
