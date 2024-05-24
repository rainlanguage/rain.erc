// SPDX-License-Identifier: CAL
pragma solidity =0.8.25;

/// A contract that doesnt implement erc165, but has supportsInterface method
contract InvalidERC165 {
    function supportsInterface(bytes4 interfaceID) external pure returns (bool) {
        (interfaceID);
        return true;
    }
}
