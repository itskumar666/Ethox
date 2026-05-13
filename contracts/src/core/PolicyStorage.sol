// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title PolicyStorage
 * @notice Stores per-account security policies with a mandatory timelock on all changes.
 *
 * The timelock is the single most important primitive here. Without it:
 *   - attacker compromises owner key
 *   - attacker sets threshold to 0 (no limit)
 *   - attacker drains immediately
 *
 * With a 24h timelock, the attack window is observable and cancellable.
 *
 * Caller model: msg.sender IS the account (the Safe). The Safe's own multi-sig
 * authorises policy changes, so no separate access control is needed here.
 */
contract PolicyStorage {
    // ─── Constants ────────────────────────────────────────────────────────────

    uint256 public constant TIMELOCK_DURATION = 24 hours;

    // ─── Types ────────────────────────────────────────────────────────────────

    struct Policy {
        /// Maximum ETH value (wei) allowed per direct transaction (Feature 1).
        /// type(uint256).max = no limit (default).
        /// 0 = block all ETH transfers.
        uint256 spendingThreshold;
        /// Maximum % of balance allowed per transaction (Feature 2).
        /// In basis points: 4000 = 40%, 5000 = 50%, 10000 = 100% (no limit).
        /// Checked as: (tx.value * 10000 / account.balance) > drainBps → RequireDelay
        uint16 drainBps;
        /// Block first interaction with unknown contracts (Feature 3).
        /// If true: tx to a contract you haven't used before → RequireDelay
        /// If false: first interaction is allowed
        bool blockUnknownContracts;
        /// Protection is only enforced when active = true.
        /// Allows users to deploy the Guard without immediately enforcing rules.
        bool active;
    }

    struct PendingUpdate {
        Policy policy;
        uint256 scheduledAt;
        bool exists;
    }

    // ─── Storage ──────────────────────────────────────────────────────────────

    /// account → current enforced policy
    mapping(address => Policy) private _policies;

    /// account → pending (scheduled) policy change
    mapping(address => PendingUpdate) private _pending;

    /// account → contract → has been seen
    /// Used by Feature 3: track which contracts the account has interacted with
    mapping(address => mapping(address => bool)) private _knownContracts;

    // ─── Events ───────────────────────────────────────────────────────────────

    event PolicyUpdateScheduled(
        address indexed account,
        Policy policy,
        uint256 executeAfter
    );
    event PolicyUpdateExecuted(address indexed account, Policy policy);
    event PolicyUpdateCancelled(address indexed account);

    // ─── Errors ───────────────────────────────────────────────────────────────

    error NoPendingUpdate();
    error TimelockNotExpired(uint256 executeAfter);
    error UpdateAlreadyScheduled();

    // ─── External functions ───────────────────────────────────────────────────

    /**
     * @notice Schedule a policy change. Takes effect after TIMELOCK_DURATION.
     * @dev Called by the Safe (msg.sender = account). Overwrites any existing
     *      pending update — intentional, so users can correct a mistake.
     */
    function scheduleUpdate(Policy calldata newPolicy) external {
        _pending[msg.sender] = PendingUpdate({
            policy: newPolicy,
            scheduledAt: block.timestamp,
            exists: true
        });

        emit PolicyUpdateScheduled(
            msg.sender,
            newPolicy,
            block.timestamp + TIMELOCK_DURATION
        );
    }

    /**
     * @notice Apply a pending policy change after the timelock has expired.
     */
    function executeUpdate() external {
        PendingUpdate storage pending = _pending[msg.sender];
        if (!pending.exists) revert NoPendingUpdate();

        uint256 executeAfter = pending.scheduledAt + TIMELOCK_DURATION;
        if (block.timestamp < executeAfter) revert TimelockNotExpired(executeAfter);

        _policies[msg.sender] = pending.policy;
        delete _pending[msg.sender];

        emit PolicyUpdateExecuted(msg.sender, _policies[msg.sender]);
    }

    /**
     * @notice Cancel a pending policy change before it executes.
     * @dev Critical escape hatch: if an attacker schedules a weakening policy
     *      change, the legitimate owner can cancel during the timelock window.
     */
    function cancelUpdate() external {
        if (!_pending[msg.sender].exists) revert NoPendingUpdate();
        delete _pending[msg.sender];
        emit PolicyUpdateCancelled(msg.sender);
    }

    // ─── Contract tracking (Feature 3) ────────────────────────────────────────

    /**
     * @notice Mark a contract as "known" (seen before).
     * @dev Called by PolicyGuard after a transaction executes successfully.
     *      This way, the next interaction with the same contract won't trigger
     *      the "unknown contract" warning.
     */
    function markContractKnown(address contract_) external {
        _knownContracts[msg.sender][contract_] = true;
    }

    /**
     * @notice Check if account has interacted with a contract before.
     */
    function isContractKnown(address account, address contract_) external view returns (bool) {
        return _knownContracts[account][contract_];
    }

    // ─── View functions ───────────────────────────────────────────────────────

    function getPolicy(address account) external view returns (Policy memory) {
        return _policies[account];
    }

    function getPending(address account) external view returns (PendingUpdate memory) {
        return _pending[account];
    }
}
