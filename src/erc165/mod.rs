use alloy::contract::Error as ContractError;
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

/// Non-revert errors from an ERC-165 probe.
///
/// The ERC-165 spec collapses execution reverts into "interface not
/// supported" — those stay as `Ok(false)` from the probe. The
/// "called address has no code / returned empty calldata" case is
/// also folded into `Ok(false)` for the same reason. Anything else
/// (RPC transport failure, response decode failure) is a real
/// failure mode the caller needs to see, so it is surfaced as `Err`.
#[derive(Error, Debug)]
pub enum Erc165Error {
    /// The underlying contract call failed for a reason other than
    /// the contract reverting or returning empty calldata
    /// (transport, decode, …).
    #[error(transparent)]
    Call(#[from] ContractError),
}

/// True iff `e` represents the contract executing the call and
/// reverting (with or without revert data), or the destination
/// returning empty calldata. Per ERC-165 these are equivalent to
/// "interface not supported".
fn is_revert_like(e: &ContractError) -> bool {
    e.as_revert_data().is_some() || matches!(e, ContractError::ZeroData(_, _))
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

/// the first check for checking if a contract supports erc165:
/// the contract claims it supports the IERC165 interface itself
/// (interfaceID = 0x01ffc9a7).
///
/// Returns `Ok(true)` when the call succeeded and the contract
/// returned `true`; `Ok(false)` when the call succeeded with `false`
/// or reverted (per spec); `Err` for anything else.
async fn supports_erc165_check1<P: Provider>(
    provider: &P,
    contract_address: Address,
) -> Result<bool, Erc165Error> {
    let contract = IERC165::new(contract_address, provider);
    match contract
        .supportsInterface(IERC165::supportsInterfaceCall::SELECTOR.into())
        .call()
        .await
    {
        Ok(v) => Ok(v),
        Err(e) if is_revert_like(&e) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// the second check for checking if a contract supports erc165:
/// the contract claims it does NOT support the all-ones sentinel
/// interface (interfaceID = 0xffffffff).
///
/// Returns `Ok(true)` when the contract correctly returned `false`
/// (so check2 passes); `Ok(false)` when it returned `true` or
/// reverted (per spec); `Err` for anything else.
async fn supports_erc165_check2<P: Provider>(
    provider: &P,
    contract_address: Address,
) -> Result<bool, Erc165Error> {
    let contract = IERC165::new(contract_address, provider);
    match contract
        .supportsInterface([0xff, 0xff, 0xff, 0xff].into())
        .call()
        .await
    {
        Ok(v) => Ok(!v),
        Err(e) if is_revert_like(&e) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// checks if the given contract implements ERC165
/// the process is done as described in ERC165 specs:
///
/// https://eips.ethereum.org/EIPS/eip-165#how-to-detect-if-a-contract-implements-erc-165
///
/// Returns `Ok(true)` if both spec-mandated probes pass, `Ok(false)`
/// if either probe says "not supported" (including via revert per
/// spec, including via `ZeroData` for empty calldata responses),
/// `Err` if a non-revert failure (transport or decode)
/// prevented us from finishing the probe — callers can treat that as
/// "answer unknown" rather than silently reading "no support".
pub async fn supports_erc165<P: Provider>(
    provider: &P,
    contract_address: Address,
) -> Result<bool, Erc165Error> {
    if !supports_erc165_check1(provider, contract_address).await? {
        return Ok(false);
    }
    supports_erc165_check2(provider, contract_address).await
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

    sol! {
        // Interface with exactly one function — exercises the
        // single-selector branch of xor_selectors (the loop body
        // never runs, the result is just that one selector).
        interface IOne {
            function only() external;
        }
    }

    sol! {
        // Interface with exactly two functions — exercises the
        // single-iteration of the XOR loop (initial selector XOR'd
        // with one more, no further partners).
        interface ITwo {
            function first() external;
            function second(uint256 v) external;
        }
    }

    // The `sol!` macro does not generate a `Calls` enum for an
    // interface with zero functions, so the
    // `XorSelectorsError::NoSelectors` branch is only reachable via a
    // hand-rolled `SolInterface` whose `selectors()` is empty. This
    // uninhabited type provides exactly that: `COUNT == 0`, so
    // `selectors()` yields no items and `xor_selectors` must hit the
    // empty guard.
    enum EmptyInterface {}

    impl SolInterface for EmptyInterface {
        const NAME: &'static str = "EmptyInterface";
        const MIN_DATA_LENGTH: usize = 0;
        const COUNT: usize = 0;

        fn selector(&self) -> [u8; 4] {
            match *self {}
        }

        fn selector_at(_i: usize) -> Option<[u8; 4]> {
            None
        }

        fn valid_selector(_selector: [u8; 4]) -> bool {
            false
        }

        fn abi_decode_raw(_selector: [u8; 4], _data: &[u8]) -> alloy::sol_types::Result<Self> {
            Err(alloy::sol_types::Error::UnknownSelector {
                name: Self::NAME,
                selector: [0; 4].into(),
            })
        }

        fn abi_decode_raw_validate(
            _selector: [u8; 4],
            _data: &[u8],
        ) -> alloy::sol_types::Result<Self> {
            Err(alloy::sol_types::Error::UnknownSelector {
                name: Self::NAME,
                selector: [0; 4].into(),
            })
        }

        fn abi_encoded_size(&self) -> usize {
            match *self {}
        }

        fn abi_encode_raw(&self, _out: &mut Vec<u8>) {
            match *self {}
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

    /// A non-revert-shaped JSON-RPC error: no `data` field, so
    /// `Error::as_revert_data()` returns `None` and `is_revert_like`
    /// is false. Stand-in for transport / RPC failures that the
    /// probe should propagate as `Err`.
    fn transport_error_payload() -> ErrorPayload {
        ErrorPayload {
            code: -32603,
            message: "internal error".into(),
            data: None,
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

    #[test]
    fn test_xor_selectors_single_selector_returns_that_selector() {
        // Single-function interface: the result must equal that one
        // function's selector unchanged (no XOR partner).
        let result = IOne::IOneCalls::xor_selectors().unwrap();
        let expected = IOne::onlyCall::SELECTOR;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_xor_selectors_two_function_interface_xors_both() {
        // Pin the loop body's correctness: the result must be the
        // bitwise XOR of the two function selectors. Using
        // `selectors().collect()` here re-derives independently of the
        // implementation under test, so a mutation that swaps XOR for
        // OR / AND / + would diverge from the manual computation.
        let result = ITwo::ITwoCalls::xor_selectors().unwrap();
        let selectors = ITwo::ITwoCalls::selectors().collect::<Vec<_>>();
        assert_eq!(selectors.len(), 2);
        let manual = u32::from_be_bytes(selectors[0]) ^ u32::from_be_bytes(selectors[1]);
        assert_eq!(result, manual.to_be_bytes());
        // Sanity: the answer is not just one selector unchanged
        // (that would be the single-selector path).
        assert_ne!(result, selectors[0]);
        assert_ne!(result, selectors[1]);
    }

    #[test]
    fn test_xor_selectors_empty_interface_errors() {
        // An interface with no selectors must yield the NoSelectors
        // error rather than indexing `selectors[0]` (which would panic)
        // or returning some default. Pins the `selectors.is_empty()`
        // guard and its exact error variant — a mutant that drops the
        // guard would panic on the empty-slice index, and one that
        // returns a different error variant is caught by the match.
        let err = EmptyInterface::xor_selectors().unwrap_err();
        assert!(matches!(err, XorSelectorsError::NoSelectors));
    }

    #[tokio::test]
    async fn test_supports_erc165_check1_true_response() {
        let asserter = Asserter::new();
        let address = Address::random();
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000001");

        let provider = mocked_provider(asserter);
        let result = supports_erc165_check1(&provider, address).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check1_false_response() {
        let asserter = Asserter::new();
        let address = Address::random();
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000000");

        let provider = mocked_provider(asserter);
        let result = supports_erc165_check1(&provider, address).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check1_revert_response() {
        let asserter = Asserter::new();
        let address = Address::random();
        asserter.push_failure(revert_payload());

        let provider = mocked_provider(asserter);
        let result = supports_erc165_check1(&provider, address).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check1_transport_error_propagates() {
        // A non-revert error (no `data` on the JSON-RPC error) must
        // surface as Err, not get silently collapsed to Ok(false).
        let asserter = Asserter::new();
        let address = Address::random();
        asserter.push_failure(transport_error_payload());

        let provider = mocked_provider(asserter);
        let err = supports_erc165_check1(&provider, address)
            .await
            .unwrap_err();
        assert!(matches!(err, Erc165Error::Call(_)));
    }

    #[tokio::test]
    async fn test_supports_erc165_check1_zero_data_response() {
        // An eth_call success with empty calldata (`"0x"`) — typical
        // when the destination address has no code — must be treated
        // as "interface not supported" via the ContractError::ZeroData
        // branch of is_revert_like, not propagated as Err.
        let asserter = Asserter::new();
        let address = Address::random();
        asserter.push_success(&"0x");

        let provider = mocked_provider(asserter);
        let result = supports_erc165_check1(&provider, address).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check2_returns_false() {
        let asserter = Asserter::new();
        let address = Address::random();
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000000");

        let provider = mocked_provider(asserter);
        let result = supports_erc165_check2(&provider, address).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check2_returns_true() {
        let asserter = Asserter::new();
        let address = Address::random();
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000001");

        let provider = mocked_provider(asserter);
        let result = supports_erc165_check2(&provider, address).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check2_reverts() {
        let asserter = Asserter::new();
        let address = Address::random();
        asserter.push_failure(revert_payload());

        let provider = mocked_provider(asserter);
        let result = supports_erc165_check2(&provider, address).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check2_transport_error_propagates() {
        // Same shape as the check1 transport-error test: anything
        // that isn't a revert must come back as Err.
        let asserter = Asserter::new();
        let address = Address::random();
        asserter.push_failure(transport_error_payload());

        let provider = mocked_provider(asserter);
        let err = supports_erc165_check2(&provider, address)
            .await
            .unwrap_err();
        assert!(matches!(err, Erc165Error::Call(_)));
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
        let result = supports_erc165(&provider, address).await.unwrap();
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
        let result = supports_erc165(&provider, address).await.unwrap();
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
        let result = supports_erc165(&provider, address).await.unwrap();
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
        let result = supports_erc165(&provider, address).await.unwrap();
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
        let result = supports_erc165(&provider, address).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165_propagates_check1_transport_error() {
        // check1 hits a non-revert error; the whole probe must Err
        // out rather than silently returning Ok(false).
        let asserter = Asserter::new();
        let address = Address::random();
        asserter.push_failure(transport_error_payload());

        let provider = mocked_provider(asserter);
        let err = supports_erc165(&provider, address).await.unwrap_err();
        assert!(matches!(err, Erc165Error::Call(_)));
    }

    #[tokio::test]
    async fn test_supports_erc165_propagates_check2_transport_error() {
        // check1 succeeds (true), check2 hits a non-revert error.
        // The probe must propagate the Err from check2.
        let asserter = Asserter::new();
        let address = Address::random();
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000001");
        asserter.push_failure(transport_error_payload());

        let provider = mocked_provider(asserter);
        let err = supports_erc165(&provider, address).await.unwrap_err();
        assert!(matches!(err, Erc165Error::Call(_)));
    }
}
