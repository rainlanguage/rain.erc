use alloy_primitives::Address;
use alloy_sol_types::{sol, SolCall};
use alloy_ethers_typecast::transaction::{ReadContractParameters, ReadableClientHttp};

// IERC165 contract alloy bindings
sol!("lib/forge-std/src/interfaces/IERC165.sol");

/// get interface id from the given array of selectors the array of selectors
/// should include all the functions (and only function) selectors of the
/// contract, in alloy and using its contract bindings, the functions selectors
/// can be accessed through: `{AlloyContractName}::{AlloyContractNameCalls}::SELECTORS``
///
/// related info can be found here:
/// https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified
pub fn get_interface_id(selectors: &[[u8; 4]]) -> [u8; 4] {
    let mut result = u32::from_be_bytes(selectors[0]);
    for selector in &selectors[1..] {
        result ^= u32::from_be_bytes(*selector);
    }
    result.to_be_bytes()
}

/// checks if the given contract implements ERC165
/// the process is done as described per ERC165 specs:
///
/// https://eips.ethereum.org/EIPS/eip-165#how-to-detect-if-a-contract-implements-erc-165
pub async fn supports_erc165(client: &ReadableClientHttp, contract_address: Address) -> bool {
    let parameters = ReadContractParameters {
        address: contract_address,
        // equates to 0x01ffc9a701ffc9a700000000000000000000000000000000000000000000000000000000
        call: IERC165::supportsInterfaceCall {
            interfaceID: IERC165::supportsInterfaceCall::SELECTOR.into(),
        },
        block_number: None,
    };
    let result = client.read(parameters).await.map(|v| v._0).unwrap_or(false);
    if !result {
        return false;
    }

    let parameters = ReadContractParameters {
        address: contract_address,
        // equates to 0x01ffc9a7ffffffff00000000000000000000000000000000000000000000000000000000
        call: IERC165::supportsInterfaceCall {
            interfaceID: [0xff, 0xff, 0xff, 0xff].into(),
        },
        block_number: None,
    };
    !client.read(parameters).await.map(|v| v._0).unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex::FromHex;

    #[test]
    fn test_get_interface_id() {
        let selectors = vec![[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]];
        let result = get_interface_id(&selectors);
        let expected: [u8; 4] = [13, 14, 15, 0];
        assert_eq!(result, expected);

        let result = get_interface_id(IERC165::IERC165Calls::SELECTORS);
        let expected: [u8; 4] = 0x01ffc9a7u32.to_be_bytes(); // known IERC165 interface id
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn test_supports_erc165() {
        let non_erc165_contract =
            Address::from_hex("7ceB23fD6bC0adD59E62ac25578270cFf1b9f619").unwrap();
        let erc165_supported_contract =
            Address::from_hex("9a8545FA798A7be7F8E1B8DaDD79c9206357C015").unwrap();

        let rpc_url =
            std::env::var("TEST_POLYGON_RPC_URL").expect("'TEST_POLYGON_RPC_URL' is undefined");
        let client = ReadableClientHttp::new_from_url(rpc_url.to_string()).unwrap();

        let result = supports_erc165(&client, non_erc165_contract).await;
        assert!(!result);

        let result = supports_erc165(&client, erc165_supported_contract).await;
        assert!(result);
    }
}
