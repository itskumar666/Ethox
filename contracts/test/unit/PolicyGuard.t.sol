// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PolicyStorage} from "../../src/core/PolicyStorage.sol";
import {PolicyEngine} from "../../src/core/PolicyEngine.sol";
import {PolicyGuard} from "../../src/safe/PolicyGuard.sol";
import {Enum} from "@safe/interfaces/Enum.sol";

contract EmptyTarget {}

contract PolicyGuardTest is Test {
    PolicyStorage public store;
    PolicyEngine public engine;
    PolicyGuard public guard;

    address constant SAFE = address(0xBEEF);

    function _policy(uint256 threshold, uint16 drainBps, bool active) internal pure returns (PolicyStorage.Policy memory p) {
        p.spendingThreshold = threshold;
        p.drainBps = drainBps;
        p.blockUnknownContracts = false;
        p.monitorRiskyApprovals = false;
        p.rapidTxProtectionEnabled = false;
        p.rapidWindowSeconds = 0;
        p.rapidMaxTxsInWindow = 0;
        p.rapidLockDurationSeconds = 0;
        p.active = active;
    }

    function _setupPolicy(uint256 threshold, bool active) internal {
        _setupPolicyWithDrain(threshold, 10000, active);
    }

    function _setupPolicyWithDrain(uint256 threshold, uint16 drainBps, bool active) internal {
        PolicyStorage.Policy memory p = _policy(threshold, drainBps, active);
        vm.prank(SAFE);
        store.scheduleUpdate(p);
        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);
        vm.prank(SAFE);
        store.executeUpdate();
    }

    function _callCheckTx(address safe, address to, uint256 value, bytes memory data, Enum.Operation op) internal {
        vm.prank(safe);
        guard.checkTransaction(to, value, data, op, 0, 0, 0, address(0), payable(address(0)), "", address(0));
    }

    function setUp() public {
        store = new PolicyStorage();
        engine = new PolicyEngine(address(store));
        guard = new PolicyGuard(address(engine), address(store));
        vm.prank(address(this));
        store.setPolicyGuard(address(guard));
    }

    function test_AllowedTx_DoesNotRevert() public {
        deal(SAFE, 100 ether);
        _setupPolicy(1 ether, true);
        _callCheckTx(SAFE, address(0xCAFE), 0.5 ether, "", Enum.Operation.Call);
    }

    function test_InactivePolicy_AllowsAnything() public {
        _callCheckTx(SAFE, address(0xCAFE), 100 ether, "", Enum.Operation.Call);
    }

    function test_AboveThreshold_Reverts() public {
        _setupPolicy(1 ether, true);
        vm.prank(SAFE);
        vm.expectRevert(
            abi.encodeWithSelector(PolicyGuard.PolicyViolated.selector, keccak256("THRESHOLD_EXCEEDED"))
        );
        guard.checkTransaction(
            address(0xCAFE), 2 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0)
        );
    }

    function test_DelegateCall_Reverts_WhenActive() public {
        _setupPolicy(1 ether, true);
        vm.prank(SAFE);
        vm.expectRevert(
            abi.encodeWithSelector(PolicyGuard.PolicyViolated.selector, keccak256("DELEGATECALL_BLOCKED"))
        );
        guard.checkTransaction(
            address(0xCAFE), 0, "", Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), "", address(0)
        );
    }

    function test_BlockedTx_EmitsTransactionBlockedEvent() public {
        _setupPolicy(1 ether, true);
        bytes32 expectedCode = keccak256("THRESHOLD_EXCEEDED");

        vm.expectEmit(true, true, false, true);
        emit PolicyGuard.TransactionBlocked(SAFE, address(0xCAFE), 2 ether, expectedCode);

        vm.prank(SAFE);
        try guard.checkTransaction(
            address(0xCAFE), 2 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0)
        ) {} catch {}
    }

    function test_SupportsITransactionGuardInterface() public view {
        assertTrue(guard.supportsInterface(0xe6d7a83a));
    }

    function test_ZeroAddressEngine_Reverts() public {
        vm.expectRevert(PolicyGuard.ZeroAddressEngine.selector);
        new PolicyGuard(address(0), address(store));
    }

    function test_ZeroAddressStorage_Reverts() public {
        vm.expectRevert(PolicyGuard.ZeroAddressStorage.selector);
        new PolicyGuard(address(engine), address(0));
    }

    function test_CheckAfterExecution_NoPriorCheck_IsNoOp() public {
        vm.prank(SAFE);
        guard.checkAfterExecution(bytes32(0), true);
    }

    function test_CheckAfterExecution_AfterCheck_DoesNotRevert() public {
        deal(SAFE, 100 ether);
        _setupPolicy(1 ether, true);
        _callCheckTx(SAFE, address(0xCAFE), 0.5 ether, "", Enum.Operation.Call);
        vm.prank(SAFE);
        guard.checkAfterExecution(bytes32(0), true);

        deal(SAFE, 100 ether);
        _setupPolicy(1 ether, true);
        _callCheckTx(SAFE, address(0xCAFE), 0.5 ether, "", Enum.Operation.Call);
        vm.prank(SAFE);
        guard.checkAfterExecution(bytes32(0), false);
    }

    function test_PostSuccess_MarksContractKnown() public {
        deal(SAFE, 100 ether);
        _setupPolicy(type(uint256).max, true);

        address c = address(new EmptyTarget());
        assertFalse(store.isContractKnown(SAFE, c));

        _callCheckTx(SAFE, c, 0, "", Enum.Operation.Call);
        vm.prank(SAFE);
        guard.checkAfterExecution(bytes32(0), true);

        assertTrue(store.isContractKnown(SAFE, c));
    }

    function test_ExecutionFailure_DoesNotMarkKnown() public {
        deal(SAFE, 100 ether);
        _setupPolicy(type(uint256).max, true);

        address c = address(new EmptyTarget());
        _callCheckTx(SAFE, c, 0, "", Enum.Operation.Call);
        vm.prank(SAFE);
        guard.checkAfterExecution(bytes32(0), false);

        assertFalse(store.isContractKnown(SAFE, c));
    }

    function test_PolicyAppliesOnlyToCallerSafe() public {
        address safeA = address(0xAAAA);
        address safeB = address(0xBBBB);

        PolicyStorage.Policy memory p = _policy(1 ether, 5000, true);
        vm.prank(safeA);
        store.scheduleUpdate(p);
        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);
        vm.prank(safeA);
        store.executeUpdate();

        vm.prank(safeA);
        vm.expectRevert();
        guard.checkTransaction(
            address(0xCAFE), 5 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0)
        );

        vm.prank(safeB);
        guard.checkTransaction(
            address(0xCAFE), 5 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0)
        );
    }

    function test_Attack_DirectCallCannotSpoofAccount() public {
        _setupPolicy(1 ether, true);

        address attacker = address(0xDEAD);
        vm.prank(attacker);
        guard.checkTransaction(
            address(0xCAFE), 100 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0)
        );
    }

    function test_RapidViolation_ThenEngineLockout() public {
        deal(SAFE, 100 ether);
        PolicyStorage.Policy memory p = _policy(type(uint256).max, 10000, true);
        p.rapidTxProtectionEnabled = true;
        p.rapidWindowSeconds = 3600;
        p.rapidMaxTxsInWindow = 1;
        p.rapidLockDurationSeconds = 1000;
        vm.prank(SAFE);
        store.scheduleUpdate(p);
        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);
        vm.prank(SAFE);
        store.executeUpdate();

        address a1 = address(new EmptyTarget());
        address a2 = address(new EmptyTarget());

        _callCheckTx(SAFE, a1, 0, "", Enum.Operation.Call);
        vm.prank(SAFE);
        guard.checkAfterExecution(bytes32(0), true);

        _callCheckTx(SAFE, a2, 0, "", Enum.Operation.Call);
        vm.prank(SAFE);
        guard.checkAfterExecution(bytes32(0), true);

        vm.prank(SAFE);
        vm.expectRevert(
            abi.encodeWithSelector(PolicyGuard.PolicyViolated.selector, keccak256("RAPID_TX_LOCKOUT"))
        );
        guard.checkTransaction(
            address(0xCAFE), 0, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0)
        );
    }
}
