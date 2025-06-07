use thiserror::Error;
use alloy::primitives::Address;
use alloy::sol_types::{SolCall, SolInterface};
use alloy::sol;
use alloy_ethers_typecast::transaction::{ReadContractParameters, ReadableClient};

// IERC165 contract alloy bindings
sol!("lib/forge-std/src/interfaces/IERC165.sol");

#[derive(Error, Debug)]
pub enum XorSelectorsError {
    #[error("no selectors")]
    NoSelectors,
}

/// Calculates XOR of the selectors of a type that implements SolInterface
pub trait XorSelectors<T: SolInterface> {
    /// get xor of all the selectors.
    ///
    /// in order to get interface id the array of selectors should include all the functions
    /// (and only function) selectors of the interface, in alloy and using its sol! macro
    /// bindings, the generated Calls enum includes all the fn selectors:
    /// `{AlloyContractName}::{AlloyContractNameCalls}`
    ///
    /// related info can be found here:
    /// https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified
    fn xor_selectors() -> Result<[u8; 4], XorSelectorsError> {
        let selectors = T::selectors().collect::<Vec<_>>();
        if selectors.is_empty() {
            return Err(XorSelectorsError::NoSelectors);
        }
        let mut result = u32::from_be_bytes(selectors[0]);
        for selector in &selectors[1..] {
            result ^= u32::from_be_bytes(*selector);
        }
        Ok(result.to_be_bytes())
    }
}
impl<T: SolInterface> XorSelectors<T> for T {}

/// the first check for checking if a contract supports erc165
async fn supports_erc165_check1(client: &ReadableClient, contract_address: Address) -> bool {
    let parameters = ReadContractParameters {
        address: contract_address,
        // equates to 0x01ffc9a701ffc9a700000000000000000000000000000000000000000000000000000000
        call: IERC165::supportsInterfaceCall {
            interfaceID: IERC165::supportsInterfaceCall::SELECTOR.into(),
        },
        block_number: None,
        gas: None,
    };
    // NOTE: the ERC-165 spec states that if this call fails then it is not supported, however,
    // it likely refers to the case where the contract call fails and the unwrap_or here can
    // be due to another issue, e.g. connection error.
    client.read(parameters).await.unwrap_or(false)
}

/// the second check for checking if a contract supports erc165
async fn supports_erc165_check2(client: &ReadableClient, contract_address: Address) -> bool {
    let parameters = ReadContractParameters {
        address: contract_address,
        // equates to 0x01ffc9a7ffffffff00000000000000000000000000000000000000000000000000000000
        call: IERC165::supportsInterfaceCall {
            interfaceID: [0xff, 0xff, 0xff, 0xff].into(),
        },
        block_number: None,
        gas: None,
    };
    // NOTE: the ERC-165 spec states that if this call fails then it is not supported, however,
    // it likely refers to the case where the contract call fails and the unwrap_or here can
    // be due to another issue, e.g. connection error.
    !client.read(parameters).await.unwrap_or(true)
}

/// checks if the given contract implements ERC165
/// the process is done as described in ERC165 specs:
///
/// https://eips.ethereum.org/EIPS/eip-165#how-to-detect-if-a-contract-implements-erc-165
pub async fn supports_erc165(client: &ReadableClient, contract_address: Address) -> bool {
    let check1 = supports_erc165_check1(client, contract_address);
    let check2 = supports_erc165_check2(client, contract_address);
    check1.await && check2.await
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{providers::mock::Asserter, rpc::json_rpc::ErrorPayload};
    use serde_json::{json};
    use alloy_ethers_typecast::{transaction::ReadableClient};
    use super::XorSelectors;

    // test contracts bindings
    sol! {
        interface ITest {
            function externalFn1() external pure returns (bool);
            function externalFn2(uint256 val1, uint256 val2) external returns (uint256, bool);
            function externalFn3(address add) external returns (address);
            error SomeError();
            event SomeEvent(uint256 value);
        }
    }

    #[test]
    fn test_get_interface_id() {
        let result = IERC165::IERC165Calls::xor_selectors().unwrap();
        let expected: [u8; 4] = 0x01ffc9a7u32.to_be_bytes(); // known IERC165 interface id
        assert_eq!(result, expected);

        let result = ITest::ITestCalls::xor_selectors().unwrap();
        let expected: [u8; 4] = 0x3dcd3fedu32.to_be_bytes(); // known ITest interface id
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn test_supports_erc165_check1_true_response() {
        let asserter = Asserter::new();
        let address = Address::random();
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000001");

        let client = ReadableClient::new_mocked(asserter);
        let result = supports_erc165_check1(&client, address).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check1_false_response() {
        let asserter = Asserter::new();
        let address = Address::random();
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000000");

        let client = ReadableClient::new_mocked(asserter);
        let result = supports_erc165_check1(&client, address).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check1_revert_response() {
        let asserter = Asserter::new();
        let address = Address::random();

        let error_payload = ErrorPayload {
            code: -32003,
            message: "execution reverted".into(),
            data: Some(serde_json::value::to_raw_value(&json!("0x00")).unwrap()),
        };
        asserter.push_failure(error_payload);
        let client = ReadableClient::new_mocked(asserter);
        let result = supports_erc165_check1(&client, address).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check2_returns_false() {
        let asserter = Asserter::new();
        let address = Address::random();
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000000");

        let client = ReadableClient::new_mocked(asserter);
        let result = supports_erc165_check2(&client, address).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check2_returns_true() {
        let asserter = Asserter::new();
        let address = Address::random();
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000001");

        let client = ReadableClient::new_mocked(asserter);
        let result = supports_erc165_check2(&client, address).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check2_reverts() {
        let asserter = Asserter::new();
        let address = Address::random();

        let error_payload = ErrorPayload {
            code: -32003,
            message: "execution reverted".into(),
            data: Some(serde_json::value::to_raw_value(&json!("0x00")).unwrap()),
        };
        asserter.push_failure(error_payload);
        let client = ReadableClient::new_mocked(asserter);
        let result = supports_erc165_check2(&client, address).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165_both_checks_pass() {
        let asserter = Asserter::new();
        let address = Address::random();
        // check1 returns true
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000001");
        // check2 returns false (which means it passes)
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000000");

        let client = ReadableClient::new_mocked(asserter);
        let result = supports_erc165(&client, address).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check1_fails() {
        let asserter = Asserter::new();
        let address = Address::random();
        // check1 returns false
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000000");
        // check2 result doesn't matter since check1 already failed
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000000");

        let client = ReadableClient::new_mocked(asserter);
        let result = supports_erc165(&client, address).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check2_fails() {
        let asserter = Asserter::new();
        let address = Address::random();
        // check1 returns true
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000001");
        // check2 returns true (which means it fails)
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000001");

        let client = ReadableClient::new_mocked(asserter);
        let result = supports_erc165(&client, address).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check1_reverts() {
        let asserter = Asserter::new();
        let address = Address::random();
        // check1 reverts
        let error_payload = ErrorPayload {
            code: -32003,
            message: "execution reverted".into(),
            data: Some(serde_json::value::to_raw_value(&json!("0x00")).unwrap()),
        };
        asserter.push_failure(error_payload);
        // check2 result doesn't matter since check1 already failed
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000000");

        let client = ReadableClient::new_mocked(asserter);
        let result = supports_erc165(&client, address).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check2_reverts_after_check1_passes() {
        let asserter = Asserter::new();
        let address = Address::random();
        // check1 returns true
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000001");
        // check2 reverts
        let error_payload = ErrorPayload {
            code: -32003,
            message: "execution reverted".into(),
            data: Some(serde_json::value::to_raw_value(&json!("0x00")).unwrap()),
        };
        asserter.push_failure(error_payload);

        let client = ReadableClient::new_mocked(asserter);
        let result = supports_erc165(&client, address).await;
        assert!(!result);
    }
}
