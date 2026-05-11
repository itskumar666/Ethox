// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseTransactionGuard} from "@safe/base/GuardManager.sol";
import {Enum} from "@safe/interfaces/Enum.sol";
import {PolicyEngine} from "../core/PolicyEngine.sol";

/**
 * @title PolicyGuard
 * @notice Safe transaction guard that enforces Ethox security policies.
 *
 * How it integrates with Safe:
 *   1. Owner calls Safe.setGuard(address(this)) — one Safe tx, signed by owners.
 *   2. On every subsequent Safe.execTransaction(), Safe calls checkTransaction()
 *      before executing. If we revert, the whole Safe transaction reverts.
 *   3. checkAfterExecution() runs post-execution (used for state tracking in later features).
 *
 * Trust model:
 *   - msg.sender in checkTransaction is always the Safe itself.
 *   - We use msg.sender as the `account` for policy lookup — no spoofing possible.
 *
 * What this CANNOT prevent:
 *   - The Safe owner calling setGuard(address(0)) to remove this guard.
 *     That call goes through Safe.execTransaction → checkTransaction (so we see it),
 *     but we cannot revert a setGuard(0) call without bricking the Safe permanently.
 *     Mitigation: monitor GuardManager.ChangedGuard events and alert the user.
 */
contract PolicyGuard is BaseTransactionGuard {
    // ─── Errors ───────────────────────────────────────────────────────────────

    error PolicyViolated(bytes32 reasonCode);
    error ZeroAddressEngine();

    // ─── Events ───────────────────────────────────────────────────────────────

    /// Emitted when a transaction is blocked by policy — useful for off-chain monitoring.
    event TransactionBlocked(
        address indexed account,
        address indexed to,
        uint256 value,
        bytes32 reasonCode
    );

    // ─── State ────────────────────────────────────────────────────────────────

    PolicyEngine public immutable POLICY_ENGINE;

    // ─── Constructor ──────────────────────────────────────────────────────────

    constructor(address _policyEngine) {
        if (_policyEngine == address(0)) revert ZeroAddressEngine();
        POLICY_ENGINE = PolicyEngine(_policyEngine);
    }

    // ─── ITransactionGuard ────────────────────────────────────────────────────

    /**
     * @notice Called by Safe before executing any transaction.
     *         Reverts if policy is violated, preventing execution.
     */
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 /* safeTxGas */,
        uint256 /* baseGas */,
        uint256 /* gasPrice */,
        address /* gasToken */,
        address payable /* refundReceiver */,
        bytes memory /* signatures */,
        address /* msgSender */
    ) external override {
        PolicyEngine.EvalContext memory ctx = PolicyEngine.EvalContext({
            account: msg.sender,  // msg.sender is the Safe
            to: to,
            value: value,
            data: data,
            operation: operation
        });

        (PolicyEngine.Decision decision, bytes32 reasonCode) = POLICY_ENGINE.evaluate(ctx);

        if (decision == PolicyEngine.Decision.Block || decision == PolicyEngine.Decision.RequireDelay) {
            emit TransactionBlocked(msg.sender, to, value, reasonCode);
            revert PolicyViolated(reasonCode);
        }
    }

    /**
     * @notice Called by Safe after transaction execution.
     *         Used in later features (rapid-tx tracking, anomaly detection).
     */
    function checkAfterExecution(bytes32 /* hash */, bool /* success */) external override {
        // Feature 4 (rapid-tx detection) will write state here.
        // Writing state here (post-execution) instead of checkTransaction
        // prevents reentrancy manipulation of in-flight counters.
    }
}
