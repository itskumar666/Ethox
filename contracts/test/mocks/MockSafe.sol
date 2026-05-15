// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Enum} from "@safe/interfaces/Enum.sol";

/// @dev Minimal stand-in for a Safe: enables one module and forwards `execTransactionFromModule`.
contract MockSafe {
    mapping(address => bool) public moduleEnabled;

    error NotModule();

    function enableModule(address module) external {
        moduleEnabled[module] = true;
    }

    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) external returns (bool success) {
        if (!moduleEnabled[msg.sender]) revert NotModule();
        if (operation == Enum.Operation.DelegateCall) {
            (success,) = to.delegatecall(data);
        } else {
            (success,) = to.call{value: value}(data);
        }
    }

    receive() external payable {}
}
