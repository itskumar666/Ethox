// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Enum} from "@safe/interfaces/Enum.sol";
import {PolicyEngine} from "../core/PolicyEngine.sol";

/**
 * @title DelayModule
 * @notice Safe module (per-Safe deployment) that queues transactions which are blocked
 *         on the direct path with `RequireDelay`, then executes them after `DELAY_DURATION`
 *         via `execTransactionFromModule`.
 *
 * Trust model:
 *   - Only the bound `SAFE` can queue or cancel.
 *   - Anyone may call `execute` after the delay (liveness); optional `GuardianModule` can
 *     require M-of-N guardian approvals before execution proceeds.
 *   - At queue time: `Block` cannot be queued; only `RequireDelay` may be queued.
 *   - At execute time: `Block` still prevents execution (policy tightened or rapid lockout).
 *     `Allow` or `RequireDelay` permits execution (user waited through the delay window).
 */
interface ISafeLike {
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) external returns (bool success);
}

interface IGuardianChecker {
    function isApproved(address safe, uint256 txId, address delayModule) external view returns (bool);
    function isVetoed(address safe, uint256 txId, address delayModule) external view returns (bool);
}

contract DelayModule {
    address public immutable SAFE;
    PolicyEngine public immutable POLICY_ENGINE;
    IGuardianChecker public immutable GUARDIAN_MODULE;
    uint256 public immutable DELAY_DURATION;

    struct QueuedTx {
        address to;
        uint256 value;
        bytes data;
        Enum.Operation operation;
        uint256 unlockAt;
        bool exists;
    }

    uint256 public nextTxId;
    mapping(uint256 => QueuedTx) private _queued;

    error OnlySafe();
    error CannotQueueBlocked();
    error MustBeRequireDelay();
    error UnknownTx();
    error TooEarly();
    error PolicyNowBlocks();
    error ExecFailed();
    error GuardiansPending();
    error Vetoed();

    error ZeroAddress();
    error ZeroDelay();

    event TxQueued(uint256 indexed txId, address indexed safe, address to, uint256 unlockAt);
    event TxExecuted(uint256 indexed txId);
    event TxCancelled(uint256 indexed txId);

    constructor(address safe_, address policyEngine_, address guardianModule_, uint256 delayDuration_) {
        if (safe_ == address(0) || policyEngine_ == address(0)) revert ZeroAddress();
        if (delayDuration_ == 0) revert ZeroDelay();
        SAFE = safe_;
        POLICY_ENGINE = PolicyEngine(policyEngine_);
        GUARDIAN_MODULE = IGuardianChecker(guardianModule_);
        DELAY_DURATION = delayDuration_;
    }

    function getQueued(uint256 txId)
        external
        view
        returns (address to, uint256 value, bytes memory data, Enum.Operation operation, uint256 unlockAt, bool exists)
    {
        QueuedTx storage q = _queued[txId];
        return (q.to, q.value, q.data, q.operation, q.unlockAt, q.exists);
    }

    /**
     * @notice Queue a transaction that currently evaluates to `RequireDelay` on the direct path.
     * @dev Must be invoked from the Safe (e.g. owners sign a Safe tx whose `to` is this module).
     */
    function queue(address to, uint256 value, bytes calldata data, Enum.Operation operation)
        external
        returns (uint256 txId)
    {
        if (msg.sender != SAFE) revert OnlySafe();

        (PolicyEngine.Decision dec,) = POLICY_ENGINE.evaluate(SAFE, to, value, data, operation);
        if (dec == PolicyEngine.Decision.Block) revert CannotQueueBlocked();
        if (dec != PolicyEngine.Decision.RequireDelay) revert MustBeRequireDelay();

        txId = ++nextTxId;
        uint256 unlockAt = block.timestamp + DELAY_DURATION;
        _queued[txId] =
            QueuedTx({to: to, value: value, data: bytes(data), operation: operation, unlockAt: unlockAt, exists: true});

        emit TxQueued(txId, SAFE, to, unlockAt);
    }

    /**
     * @notice Cancel a queued transaction before execution. Only the Safe may cancel.
     */
    function cancel(uint256 txId) external {
        if (msg.sender != SAFE) revert OnlySafe();
        if (!_queued[txId].exists) revert UnknownTx();
        delete _queued[txId];
        emit TxCancelled(txId);
    }

    /**
     * @notice Execute a queued transaction after the delay. Re-validates policy; optional guardian approvals.
     */
    function execute(uint256 txId) external {
        QueuedTx storage q = _queued[txId];
        if (!q.exists) revert UnknownTx();
        if (block.timestamp < q.unlockAt) revert TooEarly();

        (PolicyEngine.Decision dec,) = POLICY_ENGINE.evaluate(SAFE, q.to, q.value, q.data, q.operation);
        if (dec == PolicyEngine.Decision.Block) revert PolicyNowBlocks();

        if (address(GUARDIAN_MODULE) != address(0)) {
            if (GUARDIAN_MODULE.isVetoed(SAFE, txId, address(this))) revert Vetoed();
            if (!GUARDIAN_MODULE.isApproved(SAFE, txId, address(this))) revert GuardiansPending();
        }

        bool ok = ISafeLike(SAFE).execTransactionFromModule(q.to, q.value, q.data, q.operation);
        if (!ok) revert ExecFailed();

        delete _queued[txId];
        emit TxExecuted(txId);
    }
}
