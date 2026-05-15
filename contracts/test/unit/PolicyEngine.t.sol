// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PolicyStorage} from "../../src/core/PolicyStorage.sol";
import {PolicyEngine} from "../../src/core/PolicyEngine.sol";
import {PolicyGuard} from "../../src/safe/PolicyGuard.sol";
import {Enum} from "@safe/interfaces/Enum.sol";

contract EmptyTarget {}

contract PolicyEngineTest is Test {
    PolicyStorage public store;
    PolicyEngine public engine;
    PolicyGuard public guard;

    address constant SAFE = address(0xBEEF);

    function _defaults() internal pure returns (PolicyStorage.Policy memory p) {
        p.spendingThreshold = type(uint256).max;
        p.drainBps = 10000;
        p.blockUnknownContracts = false;
        p.monitorRiskyApprovals = false;
        p.rapidTxProtectionEnabled = false;
        p.rapidWindowSeconds = 0;
        p.rapidMaxTxsInWindow = 0;
        p.rapidLockDurationSeconds = 0;
        p.active = true;
    }

    function _commitPolicy(PolicyStorage.Policy memory p) internal {
        vm.prank(SAFE);
        store.scheduleUpdate(p);
        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);
        vm.prank(SAFE);
        store.executeUpdate();
    }

    function _setupPolicy(uint256 threshold, bool active) internal {
        PolicyStorage.Policy memory p = _defaults();
        p.spendingThreshold = threshold;
        p.active = active;
        _commitPolicy(p);
    }

    function _setupPolicyWithDrain(uint256 threshold, uint16 drainBps, bool active) internal {
        PolicyStorage.Policy memory p = _defaults();
        p.spendingThreshold = threshold;
        p.drainBps = drainBps;
        p.active = active;
        _commitPolicy(p);
    }

    /// @dev Standard `to` for threshold/drain tests (EOA — no unknown-contract rule)
    function _eval(uint256 value, Enum.Operation op) internal view returns (PolicyEngine.Decision, bytes32) {
        return engine.evaluate(SAFE, address(0xCAFE), value, "", op);
    }

    function setUp() public {
        store = new PolicyStorage();
        engine = new PolicyEngine(address(store));
        guard = new PolicyGuard(address(engine), address(store));
        vm.prank(address(this));
        store.setPolicyGuard(address(guard));
    }

    // ─── Inactive policy ──────────────────────────────────────────────────────

    function test_InactivePolicy_AlwaysAllows() public {
        (PolicyEngine.Decision d,) = _eval(100 ether, Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    function test_ActiveFalse_AlwaysAllows() public {
        _setupPolicy(1 ether, false);
        (PolicyEngine.Decision d,) = _eval(100 ether, Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    // ─── Spending threshold ───────────────────────────────────────────────────

    function test_BelowThreshold_Allows() public {
        deal(SAFE, 100 ether);
        _setupPolicy(1 ether, true);
        (PolicyEngine.Decision d, bytes32 code) = _eval(0.5 ether, Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
        assertEq(code, bytes32(0));
    }

    function test_ExactlyAtThreshold_Allows() public {
        deal(SAFE, 100 ether);
        _setupPolicy(1 ether, true);
        (PolicyEngine.Decision d,) = _eval(1 ether, Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    function test_AboveThreshold_RequiresDelay() public {
        _setupPolicy(1 ether, true);
        (PolicyEngine.Decision d, bytes32 code) = _eval(1 ether + 1, Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.RequireDelay));
        assertEq(code, keccak256("THRESHOLD_EXCEEDED"));
    }

    function test_ZeroThreshold_BlocksAnyETHTransfer() public {
        _setupPolicy(0, true);
        (PolicyEngine.Decision d,) = _eval(1, Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.RequireDelay));
    }

    function test_MaxThreshold_AlwaysAllows() public {
        deal(SAFE, 10000 ether);
        _setupPolicy(type(uint256).max, true);
        (PolicyEngine.Decision d,) = _eval(9999 ether, Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    // ─── DelegateCall blocking ─────────────────────────────────────────────────

    function test_DelegateCall_AlwaysBlocked_WhenActive() public {
        _setupPolicy(type(uint256).max, true);
        (PolicyEngine.Decision d, bytes32 code) = _eval(0, Enum.Operation.DelegateCall);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Block));
        assertEq(code, keccak256("DELEGATECALL_BLOCKED"));
    }

    function test_DelegateCall_Allowed_WhenPolicyInactive() public {
        (PolicyEngine.Decision d,) = _eval(0, Enum.Operation.DelegateCall);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    function test_ZeroAddressStorage_Reverts() public {
        vm.expectRevert(PolicyEngine.ZeroAddressStorage.selector);
        new PolicyEngine(address(0));
    }

    // ─── Fuzz ─────────────────────────────────────────────────────────────────

    function testFuzz_ValueAtOrBelowThreshold_Allows(uint256 threshold, uint256 value) public {
        vm.assume(threshold > 0 && threshold < 10000 ether);
        vm.assume(value <= threshold);

        deal(SAFE, 100000 ether);
        _setupPolicy(threshold, true);
        (PolicyEngine.Decision d,) = _eval(value, Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    function testFuzz_ValueAboveThreshold_RequiresDelay(uint256 threshold, uint256 value) public {
        vm.assume(threshold < type(uint256).max);
        vm.assume(value > threshold);

        _setupPolicy(threshold, true);
        (PolicyEngine.Decision d,) = _eval(value, Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.RequireDelay));
    }

    // ─── Feature 2: Drain Protection ──────────────────────────────────────────

    function test_BelowDrainLimit_Allows() public {
        deal(SAFE, 100 ether);
        _setupPolicy(type(uint256).max, true);
        (PolicyEngine.Decision d,) = _eval(30 ether, Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    function test_ExactlyAtDrainLimit_Allows() public {
        deal(SAFE, 100 ether);
        _setupPolicy(type(uint256).max, true);
        (PolicyEngine.Decision d,) = _eval(50 ether, Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    function test_AboveDrainLimit_RequiresDelay() public {
        deal(SAFE, 100 ether);
        _setupPolicyWithDrain(type(uint256).max, 5000, true);
        (PolicyEngine.Decision d, bytes32 code) = _eval(51 ether, Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.RequireDelay));
        assertEq(code, keccak256("DRAIN_LIMIT_EXCEEDED"));
    }

    function test_ZeroBalance_BlocksAnySend() public {
        deal(SAFE, 0 ether);
        _setupPolicy(type(uint256).max, true);
        (PolicyEngine.Decision d,) = _eval(1, Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.RequireDelay));
    }

    function test_BothThreshold_AndDrain_FirstBlocks() public {
        deal(SAFE, 100 ether);

        PolicyStorage.Policy memory p = _defaults();
        p.spendingThreshold = 10 ether;
        p.drainBps = 4000;
        _commitPolicy(p);

        (PolicyEngine.Decision d,) = _eval(15 ether, Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.RequireDelay));
    }

    function test_VerySmallDrainPercentage() public {
        deal(SAFE, 10000 wei);

        PolicyStorage.Policy memory p = _defaults();
        p.spendingThreshold = type(uint256).max;
        p.drainBps = 1;
        _commitPolicy(p);

        (PolicyEngine.Decision d1,) = _eval(1 wei, Enum.Operation.Call);
        assertEq(uint8(d1), uint8(PolicyEngine.Decision.Allow));

        (PolicyEngine.Decision d2,) = _eval(2 wei, Enum.Operation.Call);
        assertEq(uint8(d2), uint8(PolicyEngine.Decision.RequireDelay));
    }

    function testFuzz_WithinDrainLimit_Allows(uint256 balance, uint16 bps, uint256 value) public {
        vm.assume(bps > 0 && bps <= 10000);
        vm.assume(balance > 0 && balance < 10000 ether);
        deal(SAFE, balance);

        uint256 maxDrain = (balance * bps) / 10000;
        vm.assume(value <= maxDrain);

        PolicyStorage.Policy memory p = _defaults();
        p.spendingThreshold = type(uint256).max;
        p.drainBps = bps;
        _commitPolicy(p);

        (PolicyEngine.Decision d,) = _eval(value, Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    function testFuzz_ExceedsDrainLimit_RequiresDelay(uint256 balance, uint16 bps, uint256 excess) public {
        vm.assume(bps > 0 && bps < 10000);
        vm.assume(balance > 0 && balance < 10000 ether);
        vm.assume(excess > 0 && excess < 1000 ether);
        deal(SAFE, balance);

        uint256 maxDrain = (balance * bps) / 10000;
        uint256 value = maxDrain + excess;
        vm.assume(value <= 10000 ether);

        PolicyStorage.Policy memory p = _defaults();
        p.spendingThreshold = type(uint256).max;
        p.drainBps = bps;
        _commitPolicy(p);

        (PolicyEngine.Decision d,) = _eval(value, Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.RequireDelay));
    }

    // ─── Feature 3: Unknown Contract Protection ───────────────────────────────

    function test_UnknownContract_RequiresDelay() public {
        deal(SAFE, 100 ether);
        PolicyStorage.Policy memory p = _defaults();
        p.blockUnknownContracts = true;
        _commitPolicy(p);

        address unknownContract = address(new EmptyTarget());
        (PolicyEngine.Decision d, bytes32 code) =
            engine.evaluate(SAFE, unknownContract, 0, "", Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.RequireDelay));
        assertEq(code, keccak256("UNKNOWN_CONTRACT"));
    }

    function test_UnknownContract_EOA_Allows() public {
        deal(SAFE, 100 ether);
        PolicyStorage.Policy memory p = _defaults();
        p.blockUnknownContracts = true;
        _commitPolicy(p);

        address eoa = address(0x1111);
        (PolicyEngine.Decision d,) = engine.evaluate(SAFE, eoa, 0, "", Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    function test_KnownContract_Allows() public {
        deal(SAFE, 100 ether);
        PolicyStorage.Policy memory p = _defaults();
        p.blockUnknownContracts = true;
        _commitPolicy(p);

        address knownContract = address(new EmptyTarget());
        vm.prank(address(guard));
        store.guardAfterSuccess(SAFE, knownContract, "");

        (PolicyEngine.Decision d,) = engine.evaluate(SAFE, knownContract, 0, "", Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    function test_UnknownContract_DisabledAllows() public {
        deal(SAFE, 100 ether);
        PolicyStorage.Policy memory p = _defaults();
        p.blockUnknownContracts = false;
        _commitPolicy(p);

        address unknownContract = address(new EmptyTarget());
        (PolicyEngine.Decision d,) = engine.evaluate(SAFE, unknownContract, 0, "", Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    // ─── Feature 4: Rapid transaction lock ─────────────────────────────────────

    function test_RapidLock_BlocksAllTxsUntilExpiry() public {
        deal(SAFE, 100 ether);
        PolicyStorage.Policy memory p = _defaults();
        p.rapidTxProtectionEnabled = true;
        p.rapidWindowSeconds = 3600;
        p.rapidMaxTxsInWindow = 2;
        p.rapidLockDurationSeconds = 7200;
        _commitPolicy(p);

        address a1 = address(new EmptyTarget());
        address a2 = address(new EmptyTarget());
        address a3 = address(new EmptyTarget());

        vm.prank(address(guard));
        store.guardAfterSuccess(SAFE, a1, "");
        vm.prank(address(guard));
        store.guardAfterSuccess(SAFE, a2, "");
        vm.prank(address(guard));
        store.guardAfterSuccess(SAFE, a3, "");

        (PolicyEngine.Decision d, bytes32 code) = _eval(0, Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Block));
        assertEq(code, keccak256("RAPID_TX_LOCKOUT"));

        vm.warp(block.timestamp + 7201);
        (PolicyEngine.Decision d2,) = _eval(0, Enum.Operation.Call);
        assertEq(uint8(d2), uint8(PolicyEngine.Decision.Allow));
    }

    // ─── Feature 5: Risky approval ────────────────────────────────────────────

    function test_InfiniteApproveUnknownSpender_RequiresDelay() public {
        deal(SAFE, 100 ether);
        PolicyStorage.Policy memory p = _defaults();
        p.monitorRiskyApprovals = true;
        _commitPolicy(p);

        address token = address(new EmptyTarget());
        address unknownSpender = address(0xACE);
        bytes memory data = abi.encodeWithSelector(bytes4(0x095ea7b3), unknownSpender, type(uint256).max);

        (PolicyEngine.Decision d, bytes32 code) = engine.evaluate(SAFE, token, 0, data, Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.RequireDelay));
        assertEq(code, keccak256("RISKY_APPROVAL_UNKNOWN_SPENDER"));
    }

    function test_InfiniteApproveKnownSpender_Allows() public {
        deal(SAFE, 100 ether);
        PolicyStorage.Policy memory p = _defaults();
        p.monitorRiskyApprovals = true;
        _commitPolicy(p);

        address token = address(new EmptyTarget());
        address spender = address(new EmptyTarget());
        vm.prank(address(guard));
        store.guardAfterSuccess(SAFE, spender, "");

        bytes memory data = abi.encodeWithSelector(bytes4(0x095ea7b3), spender, type(uint256).max);
        (PolicyEngine.Decision d,) = engine.evaluate(SAFE, token, 0, data, Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }

    function test_BoundedApproveUnknownSpender_Allows() public {
        deal(SAFE, 100 ether);
        PolicyStorage.Policy memory p = _defaults();
        p.monitorRiskyApprovals = true;
        _commitPolicy(p);

        address token = address(new EmptyTarget());
        bytes memory data = abi.encodeWithSelector(bytes4(0x095ea7b3), address(0xACE), uint256(1000 ether));

        (PolicyEngine.Decision d,) = engine.evaluate(SAFE, token, 0, data, Enum.Operation.Call);
        assertEq(uint8(d), uint8(PolicyEngine.Decision.Allow));
    }
}
