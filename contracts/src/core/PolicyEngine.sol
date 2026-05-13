// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PolicyStorage} from "./PolicyStorage.sol";
import {Enum} from "@safe/interfaces/Enum.sol";

/**
 * @title PolicyEngine
 * @notice Stateless evaluation of a transaction against a stored policy.
 *         Returns a Decision — callers (Guards, Modules) decide how to act on it.
 *
 * Keeping evaluation logic separate from storage means:
 *   - this contract can be upgraded without migrating policy data
 *   - audit surface is small and focused on logic, not storage
 *   - future features (drain %, cooldown) extend EvalContext without touching storage layout
 */
contract PolicyEngine {
    // ─── Types ────────────────────────────────────────────────────────────────

    enum Decision {
        Allow,          // proceed normally
        Block,          // hard block — not recoverable through delay
        RequireDelay    // user must submit via DelayModule instead
    }

    struct EvalContext {
        address account;        // the Safe whose policy applies
        address to;             // transaction recipient
        uint256 value;          // ETH value in wei
        bytes data;             // calldata
        Enum.Operation operation; // Call or DelegateCall
    }

    // ─── Errors ───────────────────────────────────────────────────────────────

    error ZeroAddressStorage();

    // ─── State ────────────────────────────────────────────────────────────────

    PolicyStorage public immutable POLICY_STORAGE;

    // ─── Constructor ──────────────────────────────────────────────────────────

    constructor(address _policyStorage) {
        if (_policyStorage == address(0)) revert ZeroAddressStorage();
        POLICY_STORAGE = PolicyStorage(_policyStorage);
    }

    // ─── External functions ───────────────────────────────────────────────────

    /**
     * @notice Evaluate a transaction context against the account's active policy.
     * @return decision   The enforcement action required.
     * @return reasonCode A keccak256 identifier for the violated rule (bytes32(0) if Allow).
     *                    Used by the frontend to display a human-readable reason.
     */
    function evaluate(EvalContext calldata ctx)
        external
        view
        returns (Decision decision, bytes32 reasonCode)
    {
        PolicyStorage.Policy memory policy = POLICY_STORAGE.getPolicy(ctx.account);

        // No-op when protection is inactive
        if (!policy.active) return (Decision.Allow, bytes32(0));

        // DelegateCall is a privilege escalation — hard block, not just delay.
        // A delegatecall runs in the context of the Safe itself, giving the target
        // contract full control over Safe storage and funds.
        if (ctx.operation == Enum.Operation.DelegateCall) {
            return (Decision.Block, keccak256("DELEGATECALL_BLOCKED"));
        }

        // Feature 1: ETH spending threshold
        // Note: ERC-20 transfers have value=0 and are NOT caught here.
        // That is a known limitation addressed in Feature 5 (approval monitoring).
        if (ctx.value > policy.spendingThreshold) {
            return (Decision.RequireDelay, keccak256("THRESHOLD_EXCEEDED"));
        }

        // Feature 2: Wallet drain protection
        // Check if this transaction would drain more than X% of the account's balance.
        // drainBps is in basis points: 4000 = 40%, 5000 = 50%, 10000 = 100%.
        // Calculation: maxAllowed = (balance * drainBps) / 10000
        // Integer division rounds down, which is conservative (in wallet's favor).
        uint256 balance = ctx.account.balance;
        uint256 maxDrain = (balance * policy.drainBps) / 10000;
        if (ctx.value > maxDrain) {
            return (Decision.RequireDelay, keccak256("DRAIN_LIMIT_EXCEEDED"));
        }

        // Feature 3: Unknown contract protection
        // If blockUnknownContracts is enabled, check if we've seen this contract before.
        // First interaction with a new contract requires delay/confirmation.
        if (policy.blockUnknownContracts && !POLICY_STORAGE.isContractKnown(ctx.account, ctx.to)) {
            return (Decision.RequireDelay, keccak256("UNKNOWN_CONTRACT"));
        }

        return (Decision.Allow, bytes32(0));
    }
}
