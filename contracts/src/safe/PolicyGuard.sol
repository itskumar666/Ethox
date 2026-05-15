// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseTransactionGuard} from "@safe/base/GuardManager.sol";
import {Enum} from "@safe/interfaces/Enum.sol";
import {PolicyEngine} from "../core/PolicyEngine.sol";
import {PolicyStorage} from "../core/PolicyStorage.sol";

/**
 * @title PolicyGuard
 * @notice Safe transaction guard that enforces Ethox security policies.
 *
 * How it integrates with Safe:
 *   1. Owner calls Safe.setGuard(address(this)) — one Safe tx, signed by owners.
 *   2. On every subsequent Safe.execTransaction(), Safe calls checkTransaction()
 *      before executing. If we revert, the whole Safe transaction reverts.
 *   3. checkAfterExecution() runs post-execution for known-address + rapid counters.
 *
 * Trust model:
 *   - msg.sender in checkTransaction is always the Safe itself.
 *   - We use msg.sender as the `account` for policy lookup — no spoofing possible.
 */
contract PolicyGuard is BaseTransactionGuard {
    // ─── Errors ───────────────────────────────────────────────────────────────

    error PolicyViolated(bytes32 reasonCode);
    error ZeroAddressEngine();
    error ZeroAddressStorage();

    // ─── Events ───────────────────────────────────────────────────────────────

    event TransactionBlocked(
        address indexed account,
        address indexed to,
        uint256 value,
        bytes32 reasonCode
    );

    // ─── State ────────────────────────────────────────────────────────────────

    PolicyEngine public immutable POLICY_ENGINE;
    PolicyStorage public immutable POLICY_STORAGE;

    /// Safe → pending `to` for post-hook correlation
    mapping(address => address) private _pendingTo;
    /// Safe → pending calldata (copied; needed for approve / post-decode)
    mapping(address => bytes) private _pendingData;
    /// Post-hook only after checkTransaction in the same Safe execution.
    mapping(address => bool) private _postHookExpected;

    // ─── Constructor ──────────────────────────────────────────────────────────

    constructor(address _policyEngine, address _policyStorage) {
        if (_policyEngine == address(0)) revert ZeroAddressEngine();
        if (_policyStorage == address(0)) revert ZeroAddressStorage();
        POLICY_ENGINE = PolicyEngine(_policyEngine);
        POLICY_STORAGE = PolicyStorage(_policyStorage);
    }

    // ─── ITransactionGuard ────────────────────────────────────────────────────

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
        (PolicyEngine.Decision decision, bytes32 reasonCode) =
            POLICY_ENGINE.evaluate(msg.sender, to, value, data, operation);

        if (decision == PolicyEngine.Decision.Block || decision == PolicyEngine.Decision.RequireDelay) {
            emit TransactionBlocked(msg.sender, to, value, reasonCode);
            revert PolicyViolated(reasonCode);
        }

        _pendingTo[msg.sender] = to;
        _pendingData[msg.sender] = data;
        _postHookExpected[msg.sender] = true;
    }

    function checkAfterExecution(bytes32 /* hash */, bool success) external override {
        address safe = msg.sender;
        if (!_postHookExpected[safe]) {
            return;
        }
        _postHookExpected[safe] = false;

        address to = _pendingTo[safe];
        bytes memory data = _pendingData[safe];
        delete _pendingTo[safe];
        delete _pendingData[safe];

        if (success && POLICY_STORAGE.policyGuard() == address(this)) {
            POLICY_STORAGE.guardAfterSuccess(safe, to, data);
        }
    }
}
