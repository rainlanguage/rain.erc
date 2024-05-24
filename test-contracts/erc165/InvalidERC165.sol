// SPDX-License-Identifier: CAL
pragma solidity =0.8.25;

/// A contract that doesnt implement erc165, but has supportsInterface method
contract InvalidERC165 {
    function externalFn() external pure returns (bool) {
        return internalFn(true);
    }

    function internalFn(bool val) internal pure returns (bool) {
        return val;
    }

    function supportsInterface(bytes4 interfaceID) external pure returns (bool) {
        (interfaceID);
        return true;
    }
}
