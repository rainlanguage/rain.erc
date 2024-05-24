// SPDX-License-Identifier: CAL
pragma solidity =0.8.25;

import {IERC165} from "../../lib/forge-std/src/interfaces/IERC165.sol";

/// A contract that implements erc165
contract ERC165Supported is IERC165 {
    function supportsInterface(bytes4 interfaceID) external pure returns (bool) {
        return (interfaceID == type(IERC165).interfaceId);
    }
}
