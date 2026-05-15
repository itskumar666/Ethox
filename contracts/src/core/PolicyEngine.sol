// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PolicyStorage} from "./PolicyStorage.sol";
import {Enum} from "@safe/interfaces/Enum.sol";

/**
 * @title PolicyEngine
 * @notice Stateless evaluation of a transaction against a stored policy.
 *         Returns a Decision — callers (Guards, Modules) decide how to act on it.
 */
contract PolicyEngine {
    // ─── Types ────────────────────────────────────────────────────────────────

    enum Decision {
        Allow,
        Block,
        RequireDelay
    }

    bytes4 private constant APPROVE_SELECTOR = 0x095ea7b3;

    // ─── Errors ───────────────────────────────────────────────────────────────

    error ZeroAddressStorage();

    // ─── State ─────────────────────────────────────────────────────────────────

    PolicyStorage public immutable POLICY_STORAGE;

    constructor(address _policyStorage) {
        if (_policyStorage == address(0)) revert ZeroAddressStorage();
        POLICY_STORAGE = PolicyStorage(_policyStorage);
    }

    // ─── External functions ───────────────────────────────────────────────────

    /**
     * @notice Evaluate a transaction context against the account's active policy.
     * @dev Flattened arguments avoid ABI edge cases with dynamic `bytes` inside structs.
     */
    function evaluate(
        address account,
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation
    ) external view returns (Decision decision, bytes32 reasonCode) {
        PolicyStorage.Policy memory policy = POLICY_STORAGE.getPolicy(account);

        if (!policy.active) return (Decision.Allow, bytes32(0));

        if (operation == Enum.Operation.DelegateCall) {
            return (Decision.Block, keccak256("DELEGATECALL_BLOCKED"));
        }

        if (policy.rapidTxProtectionEnabled) {
            uint256 lockedUntil = POLICY_STORAGE.getRapidLockedUntil(account);
            if (block.timestamp < lockedUntil) {
                return (Decision.Block, keccak256("RAPID_TX_LOCKOUT"));
            }
        }

        if (value > policy.spendingThreshold) {
            return (Decision.RequireDelay, keccak256("THRESHOLD_EXCEEDED"));
        }

        uint256 balance = account.balance;
        uint256 maxDrain = (balance * policy.drainBps) / 10000;
        if (value > maxDrain) {
            return (Decision.RequireDelay, keccak256("DRAIN_LIMIT_EXCEEDED"));
        }

        if (policy.monitorRiskyApprovals && to.code.length > 0) {
            (bool isApprove, address spender, uint256 amount) = _decodeApprove(data);
            if (isApprove && _isInfiniteApproval(amount)) {
                if (!POLICY_STORAGE.isContractKnown(account, spender)) {
                    return (Decision.RequireDelay, keccak256("RISKY_APPROVAL_UNKNOWN_SPENDER"));
                }
            }
        }

        if (policy.blockUnknownContracts && to.code.length > 0) {
            if (!POLICY_STORAGE.isContractKnown(account, to)) {
                return (Decision.RequireDelay, keccak256("UNKNOWN_CONTRACT"));
            }
        }

        return (Decision.Allow, bytes32(0));
    }

    function _decodeApprove(bytes calldata data)
        private
        pure
        returns (bool ok, address spender, uint256 amount)
    {
        if (data.length < 68) return (false, address(0), 0);
        bytes4 sig = bytes4(data[0:4]);
        if (sig != APPROVE_SELECTOR) return (false, address(0), 0);
        spender = address(uint160(bytes20(data[16:36])));
        amount = uint256(bytes32(data[36:68]));
        return (true, spender, amount);
    }

    function _isInfiniteApproval(uint256 amount) private pure returns (bool) {
        return amount == type(uint256).max;
    }
}
