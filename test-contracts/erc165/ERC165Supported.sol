// SPDX-License-Identifier: CAL
pragma solidity >=0.6.0;

import {IERC165} from "../../lib/forge-std/src/interfaces/IERC165.sol";

/// A contract that implements erc165
contract ERC165Supported is IERC165 {
    function externalFn() external pure returns (bool) {
        return internalFn(true);
    }

    function internalFn(bool val) internal pure returns (bool) {
        return val;
    }

    function supportsInterface(bytes4 interfaceID) external pure returns (bool) {
        return (interfaceID == type(IERC165).interfaceId);
    }
}
