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
 *
 * Post-execution hooks (`guardAfterSuccess`) are restricted to the registered
 * PolicyGuard so counters and "known address" state are keyed by Safe, not by
 * the guard contract address.
 */
contract PolicyStorage {
    // ─── Constants ────────────────────────────────────────────────────────────

    uint256 public constant TIMELOCK_DURATION = 24 hours;

    /// @dev ERC-20 `approve(address,uint256)` — used for Feature 5 decoding in the guard.
    bytes4 internal constant APPROVE_SELECTOR = 0x095ea7b3;

    // ─── Types ────────────────────────────────────────────────────────────────

    struct Policy {
        /// Maximum ETH value (wei) allowed per direct transaction (Feature 1).
        /// type(uint256).max = no limit (default).
        /// 0 = block all ETH transfers.
        uint256 spendingThreshold;
        /// Maximum % of balance allowed per transaction (Feature 2).
        /// In basis points: 4000 = 40%, 10000 = 100% (no limit).
        uint16 drainBps;
        /// First interaction with an unknown **contract** requires delay (Feature 3).
        bool blockUnknownContracts;
        /// Unlimited (or very large) ERC-20 approvals to an unknown spender require delay (Feature 5).
        bool monitorRiskyApprovals;
        /// Feature 4: too many successful Safe txs in a short window triggers a temporary lock.
        bool rapidTxProtectionEnabled;
        /// Sliding window length in seconds (0 = rapid feature treated as off).
        uint32 rapidWindowSeconds;
        /// Lock after more than this many txs in the window (0 = off).
        uint8 rapidMaxTxsInWindow;
        /// How long the rapid lock lasts (seconds).
        uint32 rapidLockDurationSeconds;
        /// Protection is only enforced when active = true.
        bool active;
    }

    struct PendingUpdate {
        Policy policy;
        uint256 scheduledAt;
        bool exists;
    }

    struct RapidState {
        uint64 windowStart;
        uint64 lockedUntil;
        uint8 count;
    }

    // ─── Storage ──────────────────────────────────────────────────────────────

    address private immutable DEPLOYER;

    /// @dev Set once by deployer — must be the Ethox PolicyGuard for this deployment.
    address public policyGuard;

    /// account → current enforced policy
    mapping(address => Policy) private _policies;

    /// account → pending (scheduled) policy change
    mapping(address => PendingUpdate) private _pending;

    /// account → address → successfully interacted before (contracts + approval spenders)
    mapping(address => mapping(address => bool)) private _knownContracts;

    /// account → rapid-transaction rolling window state (Feature 4)
    mapping(address => RapidState) private _rapid;

    // ─── Events ───────────────────────────────────────────────────────────────

    event PolicyUpdateScheduled(address indexed account, Policy policy, uint256 executeAfter);
    event PolicyUpdateExecuted(address indexed account, Policy policy);
    event PolicyUpdateCancelled(address indexed account);
    event PolicyGuardSet(address indexed guard);
    event RapidTxLockActivated(address indexed account, uint256 lockedUntil);

    // ─── Errors ───────────────────────────────────────────────────────────────

    error NoPendingUpdate();
    error TimelockNotExpired(uint256 executeAfter);
    error GuardAlreadySet();
    error OnlyDeployer();
    error OnlyPolicyGuard();
    error ZeroGuard();

    // ─── Modifiers ────────────────────────────────────────────────────────────

    modifier onlyDeployer() {
        if (msg.sender != DEPLOYER) revert OnlyDeployer();
        _;
    }

    modifier onlyPolicyGuard() {
        if (msg.sender != policyGuard) revert OnlyPolicyGuard();
        _;
    }

    // ─── Constructor ──────────────────────────────────────────────────────────

    constructor() {
        DEPLOYER = msg.sender;
    }

    // ─── Guard registration ─────────────────────────────────────────────────────

    /**
     * @notice One-time link to PolicyGuard. Call from the same deployer that created this storage
     *         immediately after deploying PolicyGuard (same script / tx bundle recommended).
     */
    function setPolicyGuard(address guard) external onlyDeployer {
        if (policyGuard != address(0)) revert GuardAlreadySet();
        if (guard == address(0)) revert ZeroGuard();
        policyGuard = guard;
        emit PolicyGuardSet(guard);
    }

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

        emit PolicyUpdateScheduled(msg.sender, newPolicy, block.timestamp + TIMELOCK_DURATION);
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

    /**
     * @notice Called by PolicyGuard after a successful Safe execution.
     * @param account The Safe address (caller context from the guard).
     * @param to      The `to` field of the executed transaction.
     * @param data    Calldata of the executed transaction (for approve decoding).
     */
    function guardAfterSuccess(address account, address to, bytes memory data) external onlyPolicyGuard {
        Policy memory policy = _policies[account];

        if (to != address(0) && to.code.length > 0) {
            _knownContracts[account][to] = true;
        }

        if (data.length >= 68) {
            bytes4 sig;
            assembly {
                sig := shr(224, mload(add(data, 32)))
            }
            if (sig == APPROVE_SELECTOR) {
                bytes memory args = new bytes(64);
                for (uint256 i; i < 64; ++i) {
                    args[i] = data[4 + i];
                }
                (address spender,) = abi.decode(args, (address, uint256));
                if (spender != address(0)) {
                    _knownContracts[account][spender] = true;
                }
            }
        }

        if (!policy.active || !policy.rapidTxProtectionEnabled) {
            return;
        }

        uint32 window = policy.rapidWindowSeconds;
        uint8 maxTx = policy.rapidMaxTxsInWindow;
        uint32 lockDur = policy.rapidLockDurationSeconds;
        if (window == 0 || maxTx == 0 || lockDur == 0) {
            return;
        }

        RapidState storage r = _rapid[account];
        uint256 nowTs = block.timestamp;

        if (nowTs < uint256(r.lockedUntil)) {
            return;
        }

        if (r.windowStart == 0 || nowTs >= uint256(r.windowStart) + uint256(window)) {
            r.windowStart = uint64(nowTs);
            r.count = 1;
            return;
        }

        unchecked {
            r.count++;
        }
        if (r.count > maxTx) {
            uint256 until = nowTs + uint256(lockDur);
            r.lockedUntil = uint64(until);
            r.count = 0;
            r.windowStart = 0;
            emit RapidTxLockActivated(account, until);
        }
    }

    // ─── View functions ─────────────────────────────────────────────────────────

    function getPolicy(address account) external view returns (Policy memory) {
        return _policies[account];
    }

    function getPending(address account) external view returns (PendingUpdate memory) {
        return _pending[account];
    }

    function isContractKnown(address account, address addr) external view returns (bool) {
        return _knownContracts[account][addr];
    }

    function getRapidLockedUntil(address account) external view returns (uint256) {
        return uint256(_rapid[account].lockedUntil);
    }
}
