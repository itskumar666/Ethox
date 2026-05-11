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
        PolicyStorage.Policy memory p = PolicyStorage.Policy({
            spendingThreshold: threshold,
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
        _setupPolicy(1 ether, true);
        (PolicyEngine.Decision d, bytes32 code) = engine.evaluate(_ctx(0.5 ether, Enum.Operation.Call));
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
        assertEq(code, bytes32(0));
    }

    function test_ExactlyAtThreshold_Allows() public {
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
        _setupPolicy(type(uint256).max, true);
        (PolicyEngine.Decision d,) = engine.evaluate(_ctx(type(uint256).max, Enum.Operation.Call));
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
        vm.assume(threshold > 0 && threshold < type(uint256).max);
        vm.assume(value <= threshold);

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
}
