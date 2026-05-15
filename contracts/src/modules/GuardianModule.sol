// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title GuardianModule
 * @notice Collects off-chain guardian signatures so a `DelayModule` (or other workflow) can
 *         require human approval before a delayed transaction executes.
 *
 * Each Safe configures its own guardian set and threshold via `setGuardians` (called from the Safe).
 * Guardians sign an Eth personal message over a fixed prefix + chain id + safe + txId + delayModule.
 *
 * Replay: the same guardian cannot approve the same (safe, txId, delayModule) twice.
 */
contract GuardianModule {
    bytes32 private constant MESSAGE_TYPEHASH =
        keccak256("EthoxGuardianApproval(uint256 chainId,address safe,uint256 txId,address delayModule)");

    bytes32 private constant VETO_TYPEHASH =
        keccak256("EthoxGuardianVeto(uint256 chainId,address safe,uint256 txId,address delayModule)");

    struct GuardianConfig {
        address[] guardians;
        uint8 threshold;
    }

    mapping(address safe => GuardianConfig) private _config;

    /// keccak256(abi.encode(safe, txId, delayModule)) => guardian => already approved
    mapping(bytes32 => mapping(address => bool)) private _approved;

    /// keccak256(abi.encode(safe, txId, delayModule)) => vetoed
    mapping(bytes32 => bool) private _vetoed;

    /// keccak256(abi.encode(safe, txId, delayModule)) => distinct guardian approval count
    mapping(bytes32 => uint256) private _approvalCount;

    error ZeroAddress();
    error BadThreshold();
    error NotGuardian();
    error AlreadyApproved();
    error BadSignature();

    event GuardiansSet(address indexed safe, uint8 threshold);
    event GuardianApproved(address indexed safe, uint256 indexed txId, address indexed delayModule, address signer);
    event GuardianVetoed(address indexed safe, uint256 indexed txId, address indexed delayModule, address signer);

    function getGuardians(address safe) external view returns (address[] memory guardians, uint8 threshold) {
        GuardianConfig storage c = _config[safe];
        return (c.guardians, c.threshold);
    }

    /**
     * @notice Configure guardians for the calling Safe. Caller must be the Safe contract.
     */
    function setGuardians(address[] calldata guardians_, uint8 threshold_) external {
        if (threshold_ == 0 || threshold_ > guardians_.length) revert BadThreshold();
        for (uint256 i; i < guardians_.length; ++i) {
            if (guardians_[i] == address(0)) revert ZeroAddress();
        }

        GuardianConfig storage c = _config[msg.sender];
        delete c.guardians;
        for (uint256 j; j < guardians_.length; ++j) {
            c.guardians.push(guardians_[j]);
        }
        c.threshold = threshold_;

        emit GuardiansSet(msg.sender, threshold_);
    }

    /**
     * @notice Submit one guardian's approval for a specific delayed tx id on a given DelayModule.
     */
    function recordApproval(address safe, uint256 txId, address delayModule, bytes calldata signature) external {
        if (safe == address(0) || delayModule == address(0)) revert ZeroAddress();

        address signer = _recoverSigner(safe, txId, delayModule, signature);
        if (!_isGuardian(safe, signer)) revert NotGuardian();

        bytes32 uid = keccak256(abi.encode(safe, txId, delayModule));
        if (_approved[uid][signer]) revert AlreadyApproved();
        _approved[uid][signer] = true;
        unchecked {
            ++_approvalCount[uid];
        }

        emit GuardianApproved(safe, txId, delayModule, signer);
    }

    /**
     * @dev Called by `DelayModule` before executing a queued tx.
     */
    function isApproved(address safe, uint256 txId, address delayModule) external view returns (bool) {
        GuardianConfig storage c = _config[safe];
        if (c.threshold == 0) {
            return false;
        }
        bytes32 uid = keccak256(abi.encode(safe, txId, delayModule));
        return _approvalCount[uid] >= c.threshold;
    }

    function isVetoed(address safe, uint256 txId, address delayModule) external view returns (bool) {
        bytes32 uid = keccak256(abi.encode(safe, txId, delayModule));
        return _vetoed[uid];
    }

    /**
     * @notice Any guardian may veto a pending delayed transaction (one signature, irreversible for that tx id).
     */
    function recordVeto(address safe, uint256 txId, address delayModule, bytes calldata signature) external {
        if (safe == address(0) || delayModule == address(0)) revert ZeroAddress();
        address signer = _recoverVetoSigner(safe, txId, delayModule, signature);
        if (!_isGuardian(safe, signer)) revert NotGuardian();
        bytes32 uid = keccak256(abi.encode(safe, txId, delayModule));
        _vetoed[uid] = true;
        emit GuardianVetoed(safe, txId, delayModule, signer);
    }

    function _recoverVetoSigner(address safe, uint256 txId, address delayModule, bytes calldata signature)
        internal
        view
        returns (address)
    {
        bytes32 structHash = keccak256(abi.encode(VETO_TYPEHASH, block.chainid, safe, txId, delayModule));
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(structHash);
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, bytes(signature));
        if (err != ECDSA.RecoverError.NoError || recovered == address(0)) revert BadSignature();
        return recovered;
    }

    function _recoverSigner(address safe, uint256 txId, address delayModule, bytes calldata signature)
        internal
        view
        returns (address)
    {
        bytes32 structHash = keccak256(abi.encode(MESSAGE_TYPEHASH, block.chainid, safe, txId, delayModule));
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(structHash);
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, bytes(signature));
        if (err != ECDSA.RecoverError.NoError || recovered == address(0)) revert BadSignature();
        return recovered;
    }

    function _isGuardian(address safe, address account) internal view returns (bool) {
        address[] storage g = _config[safe].guardians;
        for (uint256 i; i < g.length; ++i) {
            if (g[i] == account) return true;
        }
        return false;
    }

    /// @dev Digest passed to `vm.sign` / wallets (ERC-191 personal sign over `structHash`).
    function getApprovalDigest(address safe, uint256 txId, address delayModule) external view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(MESSAGE_TYPEHASH, block.chainid, safe, txId, delayModule));
        return MessageHashUtils.toEthSignedMessageHash(structHash);
    }

    function getVetoDigest(address safe, uint256 txId, address delayModule) external view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(VETO_TYPEHASH, block.chainid, safe, txId, delayModule));
        return MessageHashUtils.toEthSignedMessageHash(structHash);
    }
}
