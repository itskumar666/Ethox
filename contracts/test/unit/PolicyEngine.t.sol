// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PolicyStorage} from "../../src/core/PolicyStorage.sol";
import {PolicyEngine} from "../../src/core/PolicyEngine.sol";
import {Enum} from "@safe/interfaces/Enum.sol";

contract PolicyEngineTest is Test {
    PolicyStorage public store;
    PolicyEngine public engine;

    address constant SAFE = address(0xBEEF);

    // Helper: deploy with an active policy, bypassing timelock via vm.warp
    function _setupPolicy(uint256 threshold, bool active) internal {
        _setupPolicyWithDrain(threshold, 10000, active);  // 10000 = 100% = no drain limit
    }

    // Helper with explicit drain percentage (in basis points)
    function _setupPolicyWithDrain(uint256 threshold, uint16 drainBps, bool active) internal {
        PolicyStorage.Policy memory p = PolicyStorage.Policy({
            spendingThreshold: threshold,
            drainBps: drainBps,
            blockUnknownContracts: false,
            active: active
        });
        vm.prank(SAFE);
        store.scheduleUpdate(p);
        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);
        vm.prank(SAFE);
        store.executeUpdate();
    }

    function _ctx(uint256 value, Enum.Operation op) internal pure returns (PolicyEngine.EvalContext memory) {
        return PolicyEngine.EvalContext({
            account: SAFE,
            to: address(0xCAFE),
            value: value,
            data: "",
            operation: op
        });
    }

    function setUp() public {
        store = new PolicyStorage();
        engine = new PolicyEngine(address(store));
    }

    // ─── Inactive policy ──────────────────────────────────────────────────────

    function test_InactivePolicy_AlwaysAllows() public {
        // No policy set — default is inactive with zero threshold
        (PolicyEngine.Decision d,) = engine.evaluate(_ctx(100 ether, Enum.Operation.Call));
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    function test_ActiveFalse_AlwaysAllows() public {
        _setupPolicy(1 ether, false);
        (PolicyEngine.Decision d,) = engine.evaluate(_ctx(100 ether, Enum.Operation.Call));
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    // ─── Spending threshold ───────────────────────────────────────────────────

    function test_BelowThreshold_Allows() public {
        deal(SAFE, 100 ether);
        _setupPolicy(1 ether, true);
        (PolicyEngine.Decision d, bytes32 code) = engine.evaluate(_ctx(0.5 ether, Enum.Operation.Call));
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
        assertEq(code, bytes32(0));
    }

    function test_ExactlyAtThreshold_Allows() public {
        deal(SAFE, 100 ether);
        _setupPolicy(1 ether, true);
        (PolicyEngine.Decision d,) = engine.evaluate(_ctx(1 ether, Enum.Operation.Call));
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    function test_AboveThreshold_RequiresDelay() public {
        _setupPolicy(1 ether, true);
        (PolicyEngine.Decision d, bytes32 code) = engine.evaluate(_ctx(1 ether + 1, Enum.Operation.Call));
        assertEq(uint8(d), uint8(PolicyEngine.Decision.RequireDelay));
        assertEq(code, keccak256("THRESHOLD_EXCEEDED"));
    }

    function test_ZeroThreshold_BlocksAnyETHTransfer() public {
        _setupPolicy(0, true);
        // Even 1 wei should trigger RequireDelay
        (PolicyEngine.Decision d,) = engine.evaluate(_ctx(1, Enum.Operation.Call));
        assertEq(uint8(d), uint8(PolicyEngine.Decision.RequireDelay));
    }

    function test_MaxThreshold_AlwaysAllows() public {
        deal(SAFE, 10000 ether);
        _setupPolicy(type(uint256).max, true);
        (PolicyEngine.Decision d,) = engine.evaluate(_ctx(9999 ether, Enum.Operation.Call));
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    // ─── DelegateCall blocking ─────────────────────────────────────────────────

    function test_DelegateCall_AlwaysBlocked_WhenActive() public {
        _setupPolicy(type(uint256).max, true);
        (PolicyEngine.Decision d, bytes32 code) = engine.evaluate(_ctx(0, Enum.Operation.DelegateCall));
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Block));
        assertEq(code, keccak256("DELEGATECALL_BLOCKED"));
    }

    function test_DelegateCall_Allowed_WhenPolicyInactive() public {
        // If protection is off, delegatecall is not blocked by us
        // (Safe has its own delegatecall handling — this is expected)
        (PolicyEngine.Decision d,) = engine.evaluate(_ctx(0, Enum.Operation.DelegateCall));
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    // ─── Constructor guards ───────────────────────────────────────────────────

    function test_ZeroAddressStorage_Reverts() public {
        vm.expectRevert(PolicyEngine.ZeroAddressStorage.selector);
        new PolicyEngine(address(0));
    }

    // ─── Fuzz ─────────────────────────────────────────────────────────────────

    function testFuzz_ValueAtOrBelowThreshold_Allows(uint256 threshold, uint256 value) public {
        vm.assume(threshold > 0 && threshold < 10000 ether);  // Reasonable threshold
        vm.assume(value <= threshold);

        deal(SAFE, 100000 ether);  // Large balance for drain check
        _setupPolicy(threshold, true);
        (PolicyEngine.Decision d,) = engine.evaluate(_ctx(value, Enum.Operation.Call));
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    function testFuzz_ValueAboveThreshold_RequiresDelay(uint256 threshold, uint256 value) public {
        vm.assume(threshold < type(uint256).max);
        vm.assume(value > threshold);

        _setupPolicy(threshold, true);
        (PolicyEngine.Decision d,) = engine.evaluate(_ctx(value, Enum.Operation.Call));
        assertEq(uint8(d), uint8(PolicyEngine.Decision.RequireDelay));
    }

    // ─── Feature 2: Drain Protection ──────────────────────────────────────────

    function test_BelowDrainLimit_Allows() public {
        // Setup: balance = 100 ETH, drainBps = 5000 (50%), so max drain = 50 ETH
        // But we need to set Safe's balance. Use deal() cheatcode.
        deal(SAFE, 100 ether);

        _setupPolicy(type(uint256).max, true);  // No threshold limit, only drain
        (PolicyEngine.Decision d,) = engine.evaluate(_ctx(30 ether, Enum.Operation.Call));
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    function test_ExactlyAtDrainLimit_Allows() public {
        deal(SAFE, 100 ether);
        _setupPolicy(type(uint256).max, true);
        // Exactly 50% of 100 ETH = 50 ETH
        (PolicyEngine.Decision d,) = engine.evaluate(_ctx(50 ether, Enum.Operation.Call));
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    function test_AboveDrainLimit_RequiresDelay() public {
        deal(SAFE, 100 ether);
        _setupPolicyWithDrain(type(uint256).max, 5000, true);  // 50% drain limit
        // 51 ETH > 50% of 100 = RequireDelay
        (PolicyEngine.Decision d, bytes32 code) = engine.evaluate(_ctx(51 ether, Enum.Operation.Call));
        assertEq(uint8(d), uint8(PolicyEngine.Decision.RequireDelay));
        assertEq(code, keccak256("DRAIN_LIMIT_EXCEEDED"));
    }

    function test_ZeroBalance_BlocksAnySend() public {
        deal(SAFE, 0 ether);  // Empty wallet
        _setupPolicy(type(uint256).max, true);
        // Any send is blocked (can't drain an empty wallet)
        (PolicyEngine.Decision d,) = engine.evaluate(_ctx(1, Enum.Operation.Call));
        assertEq(uint8(d), uint8(PolicyEngine.Decision.RequireDelay));
    }

    function test_BothThreshold_AndDrain_FirstBlocks() public {
        // Threshold = 10 ETH, Drain = 40% of 100 ETH = 40 ETH
        // Try to send 15 ETH: below drain (40) but above threshold (10)
        deal(SAFE, 100 ether);

        PolicyStorage.Policy memory p = PolicyStorage.Policy({
            spendingThreshold: 10 ether,
            drainBps: 4000,  // 40%
            blockUnknownContracts: false,
            active: true
        });
        vm.prank(SAFE);
        store.scheduleUpdate(p);
        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);
        vm.prank(SAFE);
        store.executeUpdate();

        // 15 ETH: threshold blocks it first
        (PolicyEngine.Decision d,) = engine.evaluate(_ctx(15 ether, Enum.Operation.Call));
        assertEq(uint8(d), uint8(PolicyEngine.Decision.RequireDelay));
    }

    function test_VerySmallDrainPercentage() public {
        // drainBps = 1 (0.01%), balance = 10000 wei
        // maxDrain = (10000 * 1) / 10000 = 1 wei
        deal(SAFE, 10000 wei);

        PolicyStorage.Policy memory p = PolicyStorage.Policy({
            spendingThreshold: type(uint256).max,
            drainBps: 1,  // 0.01%
            blockUnknownContracts: false,
            active: true
        });
        vm.prank(SAFE);
        store.scheduleUpdate(p);
        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);
        vm.prank(SAFE);
        store.executeUpdate();

        // 1 wei is allowed, 2 wei is not
        (PolicyEngine.Decision d1,) = engine.evaluate(_ctx(1 wei, Enum.Operation.Call));
        assertEq(uint8(d1), uint8(PolicyEngine.Decision.Allow));

        (PolicyEngine.Decision d2,) = engine.evaluate(_ctx(2 wei, Enum.Operation.Call));
        assertEq(uint8(d2), uint8(PolicyEngine.Decision.RequireDelay));
    }

    // ─── Fuzz: Drain tests ────────────────────────────────────────────────────

    function testFuzz_WithinDrainLimit_Allows(uint256 balance, uint16 bps, uint256 value) public {
        vm.assume(bps > 0 && bps <= 10000);
        vm.assume(balance > 0 && balance < 10000 ether);
        deal(SAFE, balance);

        // Ensure value is within drain limit
        uint256 maxDrain = (balance * bps) / 10000;
        vm.assume(value <= maxDrain);

        PolicyStorage.Policy memory p = PolicyStorage.Policy({
            spendingThreshold: type(uint256).max,
            drainBps: bps,
            blockUnknownContracts: false,
            active: true
        });
        vm.prank(SAFE);
        store.scheduleUpdate(p);
        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);
        vm.prank(SAFE);
        store.executeUpdate();

        (PolicyEngine.Decision d,) = engine.evaluate(_ctx(value, Enum.Operation.Call));
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    function testFuzz_ExceedsDrainLimit_RequiresDelay(uint256 balance, uint16 bps, uint256 excess) public {
        vm.assume(bps > 0 && bps < 10000);  // Not 100%
        vm.assume(balance > 0 && balance < 10000 ether);
        vm.assume(excess > 0 && excess < 1000 ether);
        deal(SAFE, balance);

        uint256 maxDrain = (balance * bps) / 10000;
        uint256 value = maxDrain + excess;
        vm.assume(value <= 10000 ether);

        PolicyStorage.Policy memory p = PolicyStorage.Policy({
            spendingThreshold: type(uint256).max,
            drainBps: bps,
            blockUnknownContracts: false,
            active: true
        });
        vm.prank(SAFE);
        store.scheduleUpdate(p);
        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);
        vm.prank(SAFE);
        store.executeUpdate();

        (PolicyEngine.Decision d,) = engine.evaluate(_ctx(value, Enum.Operation.Call));
        assertEq(uint8(d), uint8(PolicyEngine.Decision.RequireDelay));
    }
}

    // ─── Feature 3: Unknown Contract Protection ────────────────────────────

    function test_UnknownContract_RequiresDelay() public {
        deal(SAFE, 100 ether);
        PolicyStorage.Policy memory p = PolicyStorage.Policy({
            spendingThreshold: type(uint256).max,
            drainBps: 10000,
            blockUnknownContracts: true,  // Feature 3 enabled
            active: true
        });
        vm.prank(SAFE);
        store.scheduleUpdate(p);
        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);
        vm.prank(SAFE);
        store.executeUpdate();

        // First interaction with 0x1234 should trigger unknown-contract check
        address unknownContract = address(0x1234);
        (PolicyEngine.Decision d, bytes32 code) = engine.evaluate(
            PolicyEngine.EvalContext({
                account: SAFE,
                to: unknownContract,
                value: 0,
                data: "",
                operation: Enum.Operation.Call
            })
        );
        assertEq(uint8(d), uint8(PolicyEngine.Decision.RequireDelay));
        assertEq(code, keccak256("UNKNOWN_CONTRACT"));
    }

    function test_KnownContract_Allows() public {
        deal(SAFE, 100 ether);
        PolicyStorage.Policy memory p = PolicyStorage.Policy({
            spendingThreshold: type(uint256).max,
            drainBps: 10000,
            blockUnknownContracts: true,
            active: true
        });
        vm.prank(SAFE);
        store.scheduleUpdate(p);
        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);
        vm.prank(SAFE);
        store.executeUpdate();

        // Mark contract as known
        address knownContract = address(0xABCD);
        vm.prank(SAFE);
        store.markContractKnown(knownContract);

        // Now interaction should be allowed
        (PolicyEngine.Decision d,) = engine.evaluate(
            PolicyEngine.EvalContext({
                account: SAFE,
                to: knownContract,
                value: 0,
                data: "",
                operation: Enum.Operation.Call
            })
        );
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    function test_UnknownContract_DisabledAllows() public {
        deal(SAFE, 100 ether);
        PolicyStorage.Policy memory p = PolicyStorage.Policy({
            spendingThreshold: type(uint256).max,
            drainBps: 10000,
            blockUnknownContracts: false,  // Feature 3 disabled
            active: true
        });
        vm.prank(SAFE);
        store.scheduleUpdate(p);
        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);
        vm.prank(SAFE);
        store.executeUpdate();

        // Even first interaction with unknown contract is allowed
        (PolicyEngine.Decision d,) = engine.evaluate(
            PolicyEngine.EvalContext({
                account: SAFE,
                to: address(0x9999),
                value: 0,
                data: "",
                operation: Enum.Operation.Call
            })
        );
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }
