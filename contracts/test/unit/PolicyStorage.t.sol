// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PolicyStorage} from "../../src/core/PolicyStorage.sol";

contract PolicyStorageTest is Test {
    PolicyStorage public store;

    // Simulates a Safe address — in production this is the Safe contract itself
    address constant SAFE = address(0xBEEF);

    PolicyStorage.Policy internal defaultPolicy = PolicyStorage.Policy({
        spendingThreshold: 1 ether,
        active: true
    });

    function setUp() public {
        store = new PolicyStorage();
    }

    // ─── Schedule ─────────────────────────────────────────────────────────────

    function test_ScheduleUpdate_EmitsEvent() public {
        // Precompute before vm.prank — the call to store.TIMELOCK_DURATION() would
        // otherwise consume the prank, causing msg.sender to be the test contract.
        uint256 expectedExecuteAfter = block.timestamp + store.TIMELOCK_DURATION();

        vm.prank(SAFE);
        vm.expectEmit(true, false, false, true);
        emit PolicyStorage.PolicyUpdateScheduled(SAFE, defaultPolicy, expectedExecuteAfter);
        store.scheduleUpdate(defaultPolicy);
    }

    function test_ScheduleUpdate_StoresPending() public {
        vm.prank(SAFE);
        store.scheduleUpdate(defaultPolicy);

        PolicyStorage.PendingUpdate memory pending = store.getPending(SAFE);
        assertTrue(pending.exists);
        assertEq(pending.policy.spendingThreshold, 1 ether);
        assertEq(pending.scheduledAt, block.timestamp);
    }

    function test_ScheduleUpdate_OverwritesPreviousPending() public {
        PolicyStorage.Policy memory first = PolicyStorage.Policy({spendingThreshold: 1 ether, active: true});
        PolicyStorage.Policy memory second = PolicyStorage.Policy({spendingThreshold: 2 ether, active: true});

        vm.startPrank(SAFE);
        store.scheduleUpdate(first);
        store.scheduleUpdate(second);
        vm.stopPrank();

        PolicyStorage.PendingUpdate memory pending = store.getPending(SAFE);
        assertEq(pending.policy.spendingThreshold, 2 ether);
    }

    // ─── Execute ──────────────────────────────────────────────────────────────

    function test_ExecuteUpdate_SucceedsAfterTimelock() public {
        vm.prank(SAFE);
        store.scheduleUpdate(defaultPolicy);

        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);

        vm.prank(SAFE);
        store.executeUpdate();

        PolicyStorage.Policy memory applied = store.getPolicy(SAFE);
        assertEq(applied.spendingThreshold, 1 ether);
        assertTrue(applied.active);
    }

    function test_ExecuteUpdate_RevertsBeforeTimelock() public {
        vm.prank(SAFE);
        store.scheduleUpdate(defaultPolicy);

        // Try to execute 1 second before timelock expires
        vm.warp(block.timestamp + store.TIMELOCK_DURATION() - 1);

        vm.prank(SAFE);
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyStorage.TimelockNotExpired.selector,
                block.timestamp + 1 // executeAfter = scheduledAt + duration
            )
        );
        store.executeUpdate();
    }

    function test_ExecuteUpdate_RevertsWithNoPending() public {
        vm.prank(SAFE);
        vm.expectRevert(PolicyStorage.NoPendingUpdate.selector);
        store.executeUpdate();
    }

    function test_ExecuteUpdate_ClearsPendingAfterExecution() public {
        vm.prank(SAFE);
        store.scheduleUpdate(defaultPolicy);

        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);
        vm.prank(SAFE);
        store.executeUpdate();

        PolicyStorage.PendingUpdate memory pending = store.getPending(SAFE);
        assertFalse(pending.exists);
    }

    // ─── Cancel ───────────────────────────────────────────────────────────────

    function test_CancelUpdate_DeletesPending() public {
        vm.startPrank(SAFE);
        store.scheduleUpdate(defaultPolicy);
        store.cancelUpdate();
        vm.stopPrank();

        assertFalse(store.getPending(SAFE).exists);
    }

    function test_CancelUpdate_RevertsWithNoPending() public {
        vm.prank(SAFE);
        vm.expectRevert(PolicyStorage.NoPendingUpdate.selector);
        store.cancelUpdate();
    }

    // ─── Isolation between accounts ───────────────────────────────────────────

    function test_PoliciesAreIsolatedPerAccount() public {
        address safeA = address(0xAAAA);
        address safeB = address(0xBBBB);

        PolicyStorage.Policy memory policyA = PolicyStorage.Policy({spendingThreshold: 1 ether, active: true});
        PolicyStorage.Policy memory policyB = PolicyStorage.Policy({spendingThreshold: 5 ether, active: false});

        vm.prank(safeA);
        store.scheduleUpdate(policyA);
        vm.prank(safeB);
        store.scheduleUpdate(policyB);

        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);

        vm.prank(safeA);
        store.executeUpdate();
        vm.prank(safeB);
        store.executeUpdate();

        assertEq(store.getPolicy(safeA).spendingThreshold, 1 ether);
        assertEq(store.getPolicy(safeB).spendingThreshold, 5 ether);
        assertFalse(store.getPolicy(safeB).active);
    }

    // ─── Edge cases ───────────────────────────────────────────────────────────

    function test_ZeroThreshold_IsValidPolicy() public {
        PolicyStorage.Policy memory blockAll = PolicyStorage.Policy({spendingThreshold: 0, active: true});

        vm.prank(SAFE);
        store.scheduleUpdate(blockAll);
        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);
        vm.prank(SAFE);
        store.executeUpdate();

        assertEq(store.getPolicy(SAFE).spendingThreshold, 0);
    }

    function test_MaxThreshold_IsValidPolicy() public {
        PolicyStorage.Policy memory noLimit = PolicyStorage.Policy({
            spendingThreshold: type(uint256).max,
            active: true
        });

        vm.prank(SAFE);
        store.scheduleUpdate(noLimit);
        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);
        vm.prank(SAFE);
        store.executeUpdate();

        assertEq(store.getPolicy(SAFE).spendingThreshold, type(uint256).max);
    }

    // ─── Attack simulation ────────────────────────────────────────────────────

    /**
     * Attack: attacker compromises owner key, immediately tries to disable policy.
     * Expected: cannot — must wait 24h. Legitimate owner can cancel during window.
     */
    function test_Attack_CannotBypassTimelockToDisablePolicy() public {
        // Legitimate owner sets up protection
        PolicyStorage.Policy memory protection = PolicyStorage.Policy({spendingThreshold: 1 ether, active: true});
        vm.prank(SAFE);
        store.scheduleUpdate(protection);
        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);
        vm.prank(SAFE);
        store.executeUpdate();

        // Attacker compromises key, immediately tries to remove protection
        PolicyStorage.Policy memory noProtection = PolicyStorage.Policy({
            spendingThreshold: type(uint256).max,
            active: false
        });
        vm.prank(SAFE); // attacker now has the key
        store.scheduleUpdate(noProtection);

        // Attacker tries to execute immediately — must fail
        vm.prank(SAFE);
        vm.expectRevert();
        store.executeUpdate();

        // Policy unchanged — original protection still active
        assertEq(store.getPolicy(SAFE).spendingThreshold, 1 ether);
        assertTrue(store.getPolicy(SAFE).active);
    }

    /**
     * Fuzz: policy changes always respect the 24h timelock regardless of timing.
     */
    function testFuzz_TimelockAlwaysEnforced(uint256 warpSeconds) public {
        vm.assume(warpSeconds < store.TIMELOCK_DURATION());

        vm.prank(SAFE);
        store.scheduleUpdate(defaultPolicy);

        vm.warp(block.timestamp + warpSeconds);

        vm.prank(SAFE);
        vm.expectRevert();
        store.executeUpdate();
    }
}
