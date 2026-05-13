// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PolicyStorage} from "../../src/core/PolicyStorage.sol";
import {PolicyEngine} from "../../src/core/PolicyEngine.sol";
import {PolicyGuard} from "../../src/safe/PolicyGuard.sol";
import {Enum} from "@safe/interfaces/Enum.sol";

contract PolicyGuardTest is Test {
    PolicyStorage public store;
    PolicyEngine public engine;
    PolicyGuard public guard;

    address constant SAFE = address(0xBEEF);

    function _setupPolicy(uint256 threshold, bool active) internal {
        _setupPolicyWithDrain(threshold, 10000, active);  // 10000 = 100% = no drain limit
    }

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

    // Mimics how Safe calls the Guard — msg.sender is the Safe
    function _callCheckTx(address safe, address to, uint256 value, Enum.Operation op) internal {
        vm.prank(safe);
        guard.checkTransaction(
            to,
            value,
            "",
            op,
            0, 0, 0,
            address(0),
            payable(address(0)),
            "",
            address(0)
        );
    }

    function setUp() public {
        store = new PolicyStorage();
        engine = new PolicyEngine(address(store));
        guard = new PolicyGuard(address(engine), address(store));
    }

    // ─── Normal operation ─────────────────────────────────────────────────────

    function test_AllowedTx_DoesNotRevert() public {
        deal(SAFE, 100 ether);
        _setupPolicy(1 ether, true);
        // No revert expected
        _callCheckTx(SAFE, address(0xCAFE), 0.5 ether, Enum.Operation.Call);
    }

    function test_InactivePolicy_AllowsAnything() public {
        // No policy set — protection is inactive by default
        _callCheckTx(SAFE, address(0xCAFE), 100 ether, Enum.Operation.Call);
    }

    // ─── Blocked transactions ─────────────────────────────────────────────────

    function test_AboveThreshold_Reverts() public {
        _setupPolicy(1 ether, true);
        vm.prank(SAFE);
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyGuard.PolicyViolated.selector,
                keccak256("THRESHOLD_EXCEEDED")
            )
        );
        guard.checkTransaction(
            address(0xCAFE), 2 ether, "", Enum.Operation.Call,
            0, 0, 0, address(0), payable(address(0)), "", address(0)
        );
    }

    function test_DelegateCall_Reverts_WhenActive() public {
        _setupPolicy(1 ether, true);
        vm.prank(SAFE);
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyGuard.PolicyViolated.selector,
                keccak256("DELEGATECALL_BLOCKED")
            )
        );
        guard.checkTransaction(
            address(0xCAFE), 0, "", Enum.Operation.DelegateCall,
            0, 0, 0, address(0), payable(address(0)), "", address(0)
        );
    }

    // ─── Events ───────────────────────────────────────────────────────────────

    function test_BlockedTx_EmitsTransactionBlockedEvent() public {
        _setupPolicy(1 ether, true);
        bytes32 expectedCode = keccak256("THRESHOLD_EXCEEDED");

        vm.expectEmit(true, true, false, true);
        emit PolicyGuard.TransactionBlocked(SAFE, address(0xCAFE), 2 ether, expectedCode);

        vm.prank(SAFE);
        try guard.checkTransaction(
            address(0xCAFE), 2 ether, "", Enum.Operation.Call,
            0, 0, 0, address(0), payable(address(0)), "", address(0)
        ) {} catch {}
    }

    // ─── ERC165 interface support ─────────────────────────────────────────────

    function test_SupportsITransactionGuardInterface() public view {
        // Safe calls supportsInterface to validate the guard before setGuard
        // interfaceId = 0xe6d7a83a (ITransactionGuard)
        assertTrue(guard.supportsInterface(0xe6d7a83a));
    }

    // ─── Constructor guards ───────────────────────────────────────────────────

    function test_ZeroAddressEngine_Reverts() public {
        vm.expectRevert(PolicyGuard.ZeroAddressEngine.selector);
        new PolicyGuard(address(0), address(store));
    }

    function test_ZeroAddressStorage_Reverts() public {
        vm.expectRevert(PolicyGuard.ZeroAddressStorage.selector);
        new PolicyGuard(address(engine), address(0));
    }

    // ─── checkAfterExecution ─────────────────────────────────────────────────

    function test_CheckAfterExecution_DoesNotRevert() public {
        // Currently a no-op — must not revert under any circumstances
        // (a reverting checkAfterExecution would brick the Safe)
        vm.prank(SAFE);
        guard.checkAfterExecution(bytes32(0), true);
        guard.checkAfterExecution(bytes32(0), false);
    }

    // ─── Account isolation ────────────────────────────────────────────────────

    function test_PolicyAppliesOnlyToCallerSafe() public {
        address safeA = address(0xAAAA);
        address safeB = address(0xBBBB);

        // Only safeA has active protection
        PolicyStorage.Policy memory p = PolicyStorage.Policy({spendingThreshold: 1 ether, drainBps: 5000, blockUnknownContracts: false, active: true});
        vm.prank(safeA);
        store.scheduleUpdate(p);
        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);
        vm.prank(safeA);
        store.executeUpdate();

        // safeA blocked on large tx
        vm.prank(safeA);
        vm.expectRevert();
        guard.checkTransaction(
            address(0xCAFE), 5 ether, "", Enum.Operation.Call,
            0, 0, 0, address(0), payable(address(0)), "", address(0)
        );

        // safeB has no policy — allowed (no revert)
        vm.prank(safeB);
        guard.checkTransaction(
            address(0xCAFE), 5 ether, "", Enum.Operation.Call,
            0, 0, 0, address(0), payable(address(0)), "", address(0)
        );
    }

    // ─── Attack simulation ────────────────────────────────────────────────────

    /**
     * Attack: call checkTransaction directly (not from Safe) with a spoofed account.
     * Observe: msg.sender is the attacker address, so it looks up ATTACKER's policy — not SAFE's.
     * This is expected behavior — the guard only reads the caller's own policy.
     * An attacker cannot escalate permissions by calling the guard directly.
     */
    function test_Attack_DirectCallCannotSpoofAccount() public {
        _setupPolicy(1 ether, true); // SAFE has 1 ETH threshold

        address attacker = address(0xDEAD);
        // Attacker has no policy — inactive. Direct call with 100 ETH should pass
        // because attacker's own policy is inactive. This is correct: the
        // guard only runs when called BY the Safe during execTransaction.
        vm.prank(attacker);
        guard.checkTransaction(
            address(0xCAFE), 100 ether, "", Enum.Operation.Call,
            0, 0, 0, address(0), payable(address(0)), "", address(0)
        );
        // No revert — attacker has no policy. But this call also has no effect:
        // the attacker cannot execute Safe transactions without the Safe's signatures.
    }
}
