// SPDX-License-Identifier: CAL
pragma solidity =0.8.25;

/// A contract that doesnt implement erc165
contract NonERC165 {
    function externalFn() external pure returns (bool) {
        return internalFn();
    }

    function internalFn() internal pure returns (bool) {
        return true;
    }
}
