use alloy::primitives::Address;
use alloy::providers::Provider;
use alloy::sol;
use alloy::sol_types::{SolCall, SolInterface};
use thiserror::Error;

// IERC165 contract alloy bindings. Inline rather than via
// `sol!("lib/forge-std/.../IERC165.sol")` so the `#[sol(rpc)]` attribute
// generates a `Provider`-aware contract instance (IERC165::new(addr, provider)).
sol!(
    #[sol(rpc)]
    interface IERC165 {
        function supportsInterface(bytes4 interfaceID) external view returns (bool);
    }
);

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
async fn supports_erc165_check1<P: Provider>(provider: &P, contract_address: Address) -> bool {
    let contract = IERC165::new(contract_address, provider);
    // equates to 0x01ffc9a701ffc9a700000000000000000000000000000000000000000000000000000000
    contract
        .supportsInterface(IERC165::supportsInterfaceCall::SELECTOR.into())
        .call()
        .await
        // NOTE: the ERC-165 spec states that if this call fails then it is not supported, however,
        // it likely refers to the case where the contract call fails and the unwrap_or here can
        // be due to another issue, e.g. connection error.
        .unwrap_or(false)
}

/// the second check for checking if a contract supports erc165
async fn supports_erc165_check2<P: Provider>(provider: &P, contract_address: Address) -> bool {
    let contract = IERC165::new(contract_address, provider);
    // equates to 0x01ffc9a7ffffffff00000000000000000000000000000000000000000000000000000000
    !contract
        .supportsInterface([0xff, 0xff, 0xff, 0xff].into())
        .call()
        .await
        // NOTE: the ERC-165 spec states that if this call fails then it is not supported, however,
        // it likely refers to the case where the contract call fails and the unwrap_or here can
        // be due to another issue, e.g. connection error.
        .unwrap_or(true)
}

/// checks if the given contract implements ERC165
/// the process is done as described in ERC165 specs:
///
/// https://eips.ethereum.org/EIPS/eip-165#how-to-detect-if-a-contract-implements-erc-165
pub async fn supports_erc165<P: Provider>(provider: &P, contract_address: Address) -> bool {
    let check1 = supports_erc165_check1(provider, contract_address);
    let check2 = supports_erc165_check2(provider, contract_address);
    check1.await && check2.await
}

#[cfg(test)]
mod tests {
    use super::XorSelectors;
    use super::*;
    use alloy::providers::{ProviderBuilder, mock::Asserter};
    use alloy::rpc::json_rpc::ErrorPayload;
    use serde_json::json;

    // test contracts bindings
    sol! {
        #[sol(rpc)]
        interface ITest {
            function externalFn1() external pure returns (bool);
            function externalFn2(uint256 val1, uint256 val2) external returns (uint256, bool);
            function externalFn3(address add) external returns (address);
            error SomeError();
            event SomeEvent(uint256 value);
        }
    }

    fn mocked_provider(asserter: Asserter) -> impl Provider {
        ProviderBuilder::new().connect_mocked_client(asserter)
    }

    fn revert_payload() -> ErrorPayload {
        ErrorPayload {
            code: -32003,
            message: "execution reverted".into(),
            data: Some(serde_json::value::to_raw_value(&json!("0x00")).unwrap()),
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

        let provider = mocked_provider(asserter);
        let result = supports_erc165_check1(&provider, address).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check1_false_response() {
        let asserter = Asserter::new();
        let address = Address::random();
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000000");

        let provider = mocked_provider(asserter);
        let result = supports_erc165_check1(&provider, address).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check1_revert_response() {
        let asserter = Asserter::new();
        let address = Address::random();
        asserter.push_failure(revert_payload());

        let provider = mocked_provider(asserter);
        let result = supports_erc165_check1(&provider, address).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check2_returns_false() {
        let asserter = Asserter::new();
        let address = Address::random();
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000000");

        let provider = mocked_provider(asserter);
        let result = supports_erc165_check2(&provider, address).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check2_returns_true() {
        let asserter = Asserter::new();
        let address = Address::random();
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000001");

        let provider = mocked_provider(asserter);
        let result = supports_erc165_check2(&provider, address).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check2_reverts() {
        let asserter = Asserter::new();
        let address = Address::random();
        asserter.push_failure(revert_payload());

        let provider = mocked_provider(asserter);
        let result = supports_erc165_check2(&provider, address).await;
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

        let provider = mocked_provider(asserter);
        let result = supports_erc165(&provider, address).await;
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

        let provider = mocked_provider(asserter);
        let result = supports_erc165(&provider, address).await;
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

        let provider = mocked_provider(asserter);
        let result = supports_erc165(&provider, address).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check1_reverts() {
        let asserter = Asserter::new();
        let address = Address::random();
        // check1 reverts
        asserter.push_failure(revert_payload());
        // check2 result doesn't matter since check1 already failed
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000000");

        let provider = mocked_provider(asserter);
        let result = supports_erc165(&provider, address).await;
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
        asserter.push_failure(revert_payload());

        let provider = mocked_provider(asserter);
        let result = supports_erc165(&provider, address).await;
        assert!(!result);
    }
}
