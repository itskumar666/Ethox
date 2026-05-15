// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Enum} from "@safe/interfaces/Enum.sol";
import {PolicyStorage} from "../../src/core/PolicyStorage.sol";
import {PolicyEngine} from "../../src/core/PolicyEngine.sol";
import {DelayModule} from "../../src/modules/DelayModule.sol";
import {GuardianModule} from "../../src/modules/GuardianModule.sol";
import {MockSafe} from "../mocks/MockSafe.sol";

contract DelayGuardianIntegrationTest is Test {
    MockSafe public safe;
    PolicyStorage public store;
    PolicyEngine public engine;
    DelayModule public delay;
    GuardianModule public guardian;

    address public recipient = address(0xB0B);

    uint256 internal constant GUARDIAN_PK = 0xA11CE;
    address public guardianAddr;

    function _policy(uint256 threshold) internal pure returns (PolicyStorage.Policy memory p) {
        p.spendingThreshold = threshold;
        p.drainBps = 10000;
        p.blockUnknownContracts = false;
        p.monitorRiskyApprovals = false;
        p.rapidTxProtectionEnabled = false;
        p.rapidWindowSeconds = 0;
        p.rapidMaxTxsInWindow = 0;
        p.rapidLockDurationSeconds = 0;
        p.active = true;
    }

    function setUp() public {
        guardianAddr = vm.addr(GUARDIAN_PK);
        safe = new MockSafe();
        store = new PolicyStorage();
        engine = new PolicyEngine(address(store));

        vm.prank(address(safe));
        store.scheduleUpdate(_policy(1 ether));
        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);
        vm.prank(address(safe));
        store.executeUpdate();

        deal(address(safe), 20 ether);
    }

    function test_DelayQueueExecute_NoGuardian() public {
        delay = new DelayModule(address(safe), address(engine), address(0), 100);
        safe.enableModule(address(delay));

        vm.prank(address(safe));
        uint256 txId = delay.queue(recipient, 5 ether, "", Enum.Operation.Call);
        assertEq(txId, 1);

        vm.expectRevert(DelayModule.TooEarly.selector);
        delay.execute(txId);

        vm.warp(block.timestamp + 100);
        uint256 balBefore = recipient.balance;
        delay.execute(txId);
        assertEq(recipient.balance, balBefore + 5 ether);
    }

    function test_DelayCancel() public {
        delay = new DelayModule(address(safe), address(engine), address(0), 100);
        safe.enableModule(address(delay));

        vm.prank(address(safe));
        uint256 txId = delay.queue(recipient, 5 ether, "", Enum.Operation.Call);

        vm.prank(address(safe));
        delay.cancel(txId);

        vm.warp(block.timestamp + 200);
        vm.expectRevert(DelayModule.UnknownTx.selector);
        delay.execute(txId);
    }

    function test_DelayCannotQueueAllow() public {
        delay = new DelayModule(address(safe), address(engine), address(0), 100);
        safe.enableModule(address(delay));

        vm.prank(address(safe));
        vm.expectRevert(DelayModule.MustBeRequireDelay.selector);
        delay.queue(recipient, 0.5 ether, "", Enum.Operation.Call);
    }

    function test_ExecuteSucceedsAfterPolicyRelaxed() public {
        delay = new DelayModule(address(safe), address(engine), address(0), 100);
        safe.enableModule(address(delay));

        vm.prank(address(safe));
        uint256 txId = delay.queue(recipient, 5 ether, "", Enum.Operation.Call);

        vm.warp(block.timestamp + 100);

        PolicyStorage.Policy memory relaxed = _policy(type(uint256).max);
        relaxed.active = false;
        vm.prank(address(safe));
        store.scheduleUpdate(relaxed);
        vm.warp(block.timestamp + store.TIMELOCK_DURATION() + 1);
        vm.prank(address(safe));
        store.executeUpdate();

        delay.execute(txId);
    }

    function test_GuardianRequired_BlocksUntilApprovals() public {
        guardian = new GuardianModule();
        delay = new DelayModule(address(safe), address(engine), address(guardian), 100);
        safe.enableModule(address(delay));

        address[] memory guards = new address[](1);
        guards[0] = guardianAddr;
        vm.prank(address(safe));
        guardian.setGuardians(guards, 1);

        vm.prank(address(safe));
        uint256 txId = delay.queue(recipient, 5 ether, "", Enum.Operation.Call);
        vm.warp(block.timestamp + 100);

        vm.expectRevert(DelayModule.GuardiansPending.selector);
        delay.execute(txId);

        bytes32 digest = guardian.getApprovalDigest(address(safe), txId, address(delay));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(GUARDIAN_PK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        guardian.recordApproval(address(safe), txId, address(delay), sig);

        delay.execute(txId);
        assertEq(recipient.balance, 5 ether);
    }

    function test_GuardianReplay_Reverts() public {
        guardian = new GuardianModule();
        delay = new DelayModule(address(safe), address(engine), address(guardian), 100);
        safe.enableModule(address(delay));

        address[] memory guards = new address[](1);
        guards[0] = guardianAddr;
        vm.prank(address(safe));
        guardian.setGuardians(guards, 1);

        vm.prank(address(safe));
        uint256 txId = delay.queue(recipient, 5 ether, "", Enum.Operation.Call);
        vm.warp(block.timestamp + 100);

        bytes32 digest = guardian.getApprovalDigest(address(safe), txId, address(delay));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(GUARDIAN_PK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        guardian.recordApproval(address(safe), txId, address(delay), sig);

        vm.expectRevert(GuardianModule.AlreadyApproved.selector);
        guardian.recordApproval(address(safe), txId, address(delay), sig);
    }

    function test_VetoBlocksExecute() public {
        guardian = new GuardianModule();
        delay = new DelayModule(address(safe), address(engine), address(guardian), 100);
        safe.enableModule(address(delay));

        address[] memory guards = new address[](1);
        guards[0] = guardianAddr;
        vm.prank(address(safe));
        guardian.setGuardians(guards, 1);

        vm.prank(address(safe));
        uint256 txId = delay.queue(recipient, 5 ether, "", Enum.Operation.Call);

        bytes32 approveDigest = guardian.getApprovalDigest(address(safe), txId, address(delay));
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(GUARDIAN_PK, approveDigest);
        guardian.recordApproval(address(safe), txId, address(delay), abi.encodePacked(r1, s1, v1));

        bytes32 vetoDigest = guardian.getVetoDigest(address(safe), txId, address(delay));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(GUARDIAN_PK, vetoDigest);
        guardian.recordVeto(address(safe), txId, address(delay), abi.encodePacked(r2, s2, v2));

        vm.warp(block.timestamp + 100);
        vm.expectRevert(DelayModule.Vetoed.selector);
        delay.execute(txId);
    }

    function test_DelayCannotQueueDelegateCall() public {
        delay = new DelayModule(address(safe), address(engine), address(0), 100);
        safe.enableModule(address(delay));

        vm.prank(address(safe));
        vm.expectRevert(DelayModule.CannotQueueBlocked.selector);
        delay.queue(address(0x1234), 0, "", Enum.Operation.DelegateCall);
    }
}
