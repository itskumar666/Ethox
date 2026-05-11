# Contributing to Ethox

This guide explains how to write code, where to put it, how to test it, and what your role is.

---

## Your Role

You are the **developer**. Your job is to:

1. **Read the feature documentation** — understand what you're building
2. **Understand the threat model** — what attacks are we defending against?
3. **Write contracts** — secure, clean Solidity code
4. **Write tests** — comprehensive Foundry tests
5. **Think like an attacker** — try to break your own code
6. **Document decisions** — why code is written this way

You are NOT:
- Deciding product features (those are decided)
- Optimizing for production scale yet
- Building UIs (that's Phase 3)
- Writing backend code yet (that's Phase 2)

---

## Where Code Lives

```
contracts/src/
├── core/                  # Policy storage & evaluation
│   ├── PolicyStorage.sol
│   ├── PolicyEngine.sol
│   └── ...new features here
│
├── safe/                  # Safe integration
│   ├── PolicyGuard.sol
│   ├── DelayModule.sol
│   └── GuardianModule.sol
│
├── interfaces/            # External interfaces (future)
│   └── ...
│
└── libraries/             # Shared utilities (future)
    └── ...

contracts/test/unit/
├── PolicyStorage.t.sol
├── PolicyEngine.t.sol
├── PolicyGuard.t.sol
└── ...new tests here
```

**Rule:** Every contract gets its own test file with the same name.

---

## Before You Write Code

### Step 1: Read the Feature Doc
Example: `docs/FEATURE_2.md`

It explains:
- What the feature does
- How it works (data flow)
- What attacks it defends against
- What edge cases exist

### Step 2: Understand the Threat Model
Ask yourself: **What could go wrong?**

Example for Feature 1:
- Can I bypass the threshold by sending multiple small txs? (Caught by Feature 4)
- Can I change the policy instantly? (No, 24h timelock)
- Can I delegatecall to steal funds? (No, blocked)

### Step 3: Design the Code
Think about:
- Where does data live? (contracts/src/)
- How do I evaluate policies? (PolicyEngine)
- How do I test edge cases? (contracts/test/unit/)

---

## Writing Contracts

### Style Rules

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title FeatureName
 * @notice One-line description of what it does.
 *
 * Longer description if needed.
 * Explain why it's designed this way.
 * Mention attack surfaces.
 */
contract FeatureName {
    // ─── Constants ────────────────────────────────────────────────────────
    uint256 public constant SOME_DURATION = 24 hours;

    // ─── Types ────────────────────────────────────────────────────────────
    struct MyStruct {
        uint256 field1;
        address field2;
    }

    // ─── Storage ──────────────────────────────────────────────────────────
    mapping(address => MyStruct) private _storage;

    // ─── Events ───────────────────────────────────────────────────────────
    event ActionPerformed(address indexed user, uint256 value);

    // ─── Errors ───────────────────────────────────────────────────────────
    error InvalidInput();
    error UnauthorizedAccess();

    // ─── Constructor ──────────────────────────────────────────────────────
    constructor() {}

    // ─── External functions ───────────────────────────────────────────────
    function publicAction() external {
        // Implementation
    }

    // ─── View functions ───────────────────────────────────────────────────
    function getState() external view returns (MyStruct memory) {
        return _storage[msg.sender];
    }
}
```

### Naming Conventions

```solidity
// Constants: SCREAMING_SNAKE_CASE
uint256 public constant MAX_THRESHOLD = 1000 ether;

// Immutables: SCREAMING_SNAKE_CASE
address public immutable POLICY_STORAGE;

// Private state: _leadingUnderscore
mapping(address => Policy) private _policies;

// Functions: camelCase
function evaluatePolicy() external {}

// Local variables: camelCase
uint256 rewardAmount = 100;
```

### Custom Errors, Not Reverts

```solidity
// ❌ BAD
require(value > 0, "Value must be positive");

// ✅ GOOD
error ZeroValue();

if (value == 0) revert ZeroValue();
```

### Events for Important State Changes

```solidity
event PolicyUpdated(address indexed account, uint256 newThreshold);

function setPolicy(uint256 threshold) external {
    _policies[msg.sender] = threshold;
    emit PolicyUpdated(msg.sender, threshold);
}
```

### No Magic Numbers

```solidity
// ❌ BAD
if (tx.value > 1000000000000000000) revert();

// ✅ GOOD
uint256 constant MAX_AMOUNT = 1 ether;
if (tx.value > MAX_AMOUNT) revert();
```

### Comments Only When Non-Obvious

```solidity
// ❌ BAD - obvious what it does
// Check if value is positive
if (value > 0) {}

// ✅ GOOD - explains why
// Prevent accumulation attack: re-check policy at execution time
// in case attacker weakened policy during the cooldown window
if (block.timestamp < pendingUpdate.executeAfter) revert();
```

---

## Writing Tests

Every contract feature must have tests. Structure:

```solidity
contract PolicyStorageTest is Test {
    PolicyStorage public store;
    address constant SAFE = address(0xBEEF);

    function setUp() public {
        store = new PolicyStorage();
    }

    // ─── Normal operation ─────────────────────────────────────────────────
    function test_ScheduleUpdate_StoresPolicy() public {
        // Arrange: set up initial state
        PolicyStorage.Policy memory p = PolicyStorage.Policy({...});

        // Act: call the function
        vm.prank(SAFE);
        store.scheduleUpdate(p);

        // Assert: verify the result
        assertEq(store.getPending(SAFE).policy.threshold, p.threshold);
    }

    // ─── Edge cases ───────────────────────────────────────────────────────
    function test_ZeroThreshold_IsValid() public {
        // Edge case: threshold = 0 should be allowed
    }

    // ─── Error cases ──────────────────────────────────────────────────────
    function test_ExecuteBeforeTimelock_Reverts() public {
        vm.expectRevert(PolicyStorage.TimelockNotExpired.selector);
        store.executeUpdate();
    }

    // ─── Attack simulation ────────────────────────────────────────────────
    function test_Attack_CannotBypassTimelock() public {
        // Simulate: attacker compromises key, tries to disable protection
    }

    // ─── Fuzz testing ─────────────────────────────────────────────────────
    function testFuzz_ThresholdAlwaysEnforced(uint256 randomValue) public {
        vm.assume(randomValue < type(uint256).max);
        // Test with random inputs
    }
}
```

### Test Naming

- `test_FeatureName_ExpectedBehavior()` — normal operation
- `test_EdgeCase_Description()` — boundary conditions
- `test_Attack_Description()` — security-focused
- `testFuzz_Description(...)` — randomized

### Test Organization

Group by category:

```solidity
// ─── Normal operation ─────────────────────────────────────────────────

// ─── Edge cases ───────────────────────────────────────────────────────

// ─── Error cases ──────────────────────────────────────────────────────

// ─── Attack simulation ────────────────────────────────────────────────

// ─── Fuzz ─────────────────────────────────────────────────────────────
```

### Assert vs Expect

```solidity
// For state checks
assert(value > 0, "Value must be positive");

// For reverts
vm.expectRevert(SomeError.selector);
doSomething();

// For events
vm.expectEmit(true, false, false, true);
emit SomeEvent(value);
doSomething();
```

### Use vm Cheatcodes

```solidity
vm.prank(address);              // Set msg.sender
vm.startPrank(address);         // Set msg.sender (persistent)
vm.stopPrank();                 // Reset msg.sender

vm.warp(timestamp);             // Jump to timestamp
vm.roll(blockNumber);           // Jump to block number

vm.expectRevert(Error.selector); // Expect a specific revert
vm.expectEmit(...);             // Expect an event

vm.assume(condition);           // Fuzz: only run if true
```

---

## The Testing Checklist

For every feature, test:

- [ ] **Normal operation** — happy path works
- [ ] **Boundary conditions** — minimum, maximum, zero
- [ ] **Inactive state** — feature disabled, should allow everything
- [ ] **State isolation** — one account's policy doesn't affect another
- [ ] **Time-based logic** — before/after timelock
- [ ] **Revert conditions** — proper error when invalid
- [ ] **Attack scenarios** — attacker tries to bypass
- [ ] **Fuzz runs** — 1000 random inputs

---

## Running Tests

```bash
# Run all tests
forge test

# Verbose output
forge test -vv

# Very verbose (show all logs)
forge test -vvv

# Single test file
forge test --match-path "test/unit/PolicyStorage.t.sol"

# Single test
forge test --match "test_ScheduleUpdate_StoresPolicy"

# With coverage (coming)
forge coverage
```

---

## Code Review Checklist

Before committing, ask:

- [ ] Does the code do what the feature doc says?
- [ ] Are all edge cases tested?
- [ ] Is the code readable? (good naming, clear structure)
- [ ] Are there comments where needed? (only non-obvious)
- [ ] Are there any vulnerabilities? (reentrancy, overflow, etc.)
- [ ] Are all tests passing?
- [ ] Is the threat model addressed?

---

## Git Workflow

```bash
# Create a branch for the feature
git checkout -b feature/feature-2-drain-protection

# Write code + tests
# ... edit contracts, edit tests ...

# Run tests
forge test -vv

# Commit
git add contracts/
git commit -m "Feature 2: Wallet drain protection"

# Push
git push origin feature/feature-2-drain-protection
```

### Commit Message Format

```
Feature 2: Wallet drain protection

- Implement drain percentage check in PolicyEngine
- Add drain-related tests (normal, edge, attack)
- 42 tests passing
```

---

## How to Know You're Done

✅ Feature code is written
✅ All tests pass (`forge test -vv`)
✅ Edge cases are tested
✅ Attack scenarios are considered
✅ Code is clean and readable
✅ Threat model is addressed
✅ Changes are committed

---

## Common Mistakes

❌ **Writing tests without understanding the feature**
→ Read the feature doc first

❌ **Not testing edge cases (zero, max, negative)**
→ Every boundary gets a test

❌ **Magic numbers in code**
→ Use constants with names

❌ **Expecting code to be perfect on first try**
→ Write, test, refactor, test again

❌ **Skipping attack simulation**
→ Think like an attacker

---

## Your First Feature

If you're building Feature 2 (Wallet Drain):

1. Read `docs/FEATURE_2.md` (architecture + threat model)
2. Design the code:
   - Where does drain % live? (PolicyStorage)
   - How do I calculate balance? (Policy evaluator)
   - How do I test it? (unit tests)
3. Write `contracts/src/core/PolicyEngine.sol` (add drain logic)
4. Write `contracts/test/unit/PolicyEngine.t.sol` (add drain tests)
5. Run `forge test -vv`
6. Commit

---

Last updated: 2026-05-11
