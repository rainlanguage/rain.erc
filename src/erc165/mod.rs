use thiserror::Error;
use alloy::primitives::Address;
use alloy::sol_types::{SolCall, SolInterface};
use alloy::sol;
use alloy_ethers_typecast::transaction::{ReadContractParameters, ReadableClientHttp};

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
async fn supports_erc165_check1(client: &ReadableClientHttp, contract_address: Address) -> bool {
    let parameters = ReadContractParameters {
        address: contract_address,
        // equates to 0x01ffc9a701ffc9a700000000000000000000000000000000000000000000000000000000
        call: IERC165::supportsInterfaceCall {
            interfaceID: IERC165::supportsInterfaceCall::SELECTOR.into(),
        },
        block_number: None,
        gas: None,
    };
    client.read(parameters).await.map(|v| v._0).unwrap_or(false)
}

/// the second check for checking if a contract supports erc165
async fn supports_erc165_check2(client: &ReadableClientHttp, contract_address: Address) -> bool {
    let parameters = ReadContractParameters {
        address: contract_address,
        // equates to 0x01ffc9a7ffffffff00000000000000000000000000000000000000000000000000000000
        call: IERC165::supportsInterfaceCall {
            interfaceID: [0xff, 0xff, 0xff, 0xff].into(),
        },
        block_number: None,
        gas: None,
    };
    !client.read(parameters).await.map(|v| v._0).unwrap_or(true)
}

/// checks if the given contract implements ERC165
/// the process is done as described in ERC165 specs:
///
/// https://eips.ethereum.org/EIPS/eip-165#how-to-detect-if-a-contract-implements-erc-165
pub async fn supports_erc165(client: &ReadableClientHttp, contract_address: Address) -> bool {
    let check1 = supports_erc165_check1(client, contract_address);
    let check2 = supports_erc165_check2(client, contract_address);
    check1.await && check2.await
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::hex::decode;
    use httpmock::{Method::POST, MockServer};
    use serde_json::{from_str, Value};
    use alloy_ethers_typecast::{
        request_shim::{AlloyTransactionRequest, TransactionRequestShim},
        rpc::{Request, Response},
        transaction::ReadableClient,
    };
    use ethers::types::{transaction::eip2718::TypedTransaction, BlockNumber};
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
    async fn test_supports_erc165_check1() {
        let rpc_server = MockServer::start_async().await;
        let client = ReadableClient::new_from_url(rpc_server.url("/")).unwrap();

        // Mock a successful response, true
        let address = Address::random();
        rpc_server.mock(|when, then| {
            when.method(POST)
                .path("/")
                .json_body_partial(
                    Request::<(TypedTransaction, BlockNumber)>::eth_call_request(
                        1,
                        TypedTransaction::Eip1559(
                            AlloyTransactionRequest::new()
                                .with_to(Some(address))
                                .with_data(Some(
                                    decode(
                                        "0x01ffc9a701ffc9a700000000000000000000000000000000000000000000000000000000"
                                    ).unwrap()
                                ))
                                .to_eip1559()
                        ),
                        None
                    )
                    .to_json_string()
                    .unwrap(),
                );
            then.json_body_obj(
                &from_str::<Value>(&Response::new_success(
                    1,
                    "0x0000000000000000000000000000000000000000000000000000000000000001"
                ).to_json_string().unwrap())
                .unwrap(),
            );
        });
        let result = supports_erc165_check1(&client, address).await;
        assert!(result);

        // Mock a successful response, false
        let address = Address::random();
        rpc_server.mock(|when, then| {
            when.method(POST)
                .path("/")
                .json_body_partial(
                    Request::<(TypedTransaction, BlockNumber)>::eth_call_request(
                        2,
                        TypedTransaction::Eip1559(
                            AlloyTransactionRequest::new()
                                .with_to(Some(address))
                                .with_data(Some(
                                    decode(
                                        "0x01ffc9a701ffc9a700000000000000000000000000000000000000000000000000000000"
                                    ).unwrap()
                                ))
                                .to_eip1559()
                        ),
                        None
                    )
                    .to_json_string()
                    .unwrap(),
                );
            then.json_body_obj(
                &from_str::<Value>(&Response::new_success(
                    2,
                    "0x0000000000000000000000000000000000000000000000000000000000000000"
                ).to_json_string().unwrap())
                .unwrap(),
            );
        });
        let result = supports_erc165_check1(&client, address).await;
        assert!(!result);

        // Mock a revert response
        let address = Address::random();
        rpc_server.mock(|when, then| {
            when.method(POST)
                .path("/")
                .json_body_partial(
                    Request::<(TypedTransaction, BlockNumber)>::eth_call_request(
                        3,
                        TypedTransaction::Eip1559(
                            AlloyTransactionRequest::new()
                                .with_to(Some(address))
                                .with_data(Some(
                                    decode(
                                        "0x01ffc9a701ffc9a700000000000000000000000000000000000000000000000000000000"
                                    ).unwrap()
                                ))
                                .to_eip1559()
                        ),
                        None
                    )
                    .to_json_string()
                    .unwrap(),
                );
            then.json_body_obj(
                &from_str::<Value>(&Response::new_error(
                    3,
                    -32003,
                    "execution reverted",
                    Some("0x00"),
                ).to_json_string().unwrap())
                .unwrap(),
            );
        });
        let result = supports_erc165_check1(&client, address).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check2() {
        let rpc_server = MockServer::start_async().await;
        let client = ReadableClient::new_from_url(rpc_server.url("/")).unwrap();

        // Mock a successful response, false
        let address = Address::random();
        rpc_server.mock(|when, then| {
            when.method(POST)
                .path("/")
                .json_body_partial(
                    Request::<(TypedTransaction, BlockNumber)>::eth_call_request(
                        1,
                        TypedTransaction::Eip1559(
                            AlloyTransactionRequest::new()
                                .with_to(Some(address))
                                .with_data(Some(
                                    decode(
                                        "0x01ffc9a7ffffffff00000000000000000000000000000000000000000000000000000000"
                                    ).unwrap()
                                ))
                                .to_eip1559()
                        ),
                        None
                    )
                    .to_json_string()
                    .unwrap(),
                );
            then.json_body_obj(
                &from_str::<Value>(&Response::new_success(
                    1,
                    "0x0000000000000000000000000000000000000000000000000000000000000000"
                ).to_json_string().unwrap())
                .unwrap(),
            );
        });
        let result = supports_erc165_check2(&client, address).await;
        assert!(result);

        // Mock a successful response, true
        let address = Address::random();
        rpc_server.mock(|when, then| {
            when.method(POST)
                .path("/")
                .json_body_partial(
                    Request::<(TypedTransaction, BlockNumber)>::eth_call_request(
                        2,
                        TypedTransaction::Eip1559(
                            AlloyTransactionRequest::new()
                                .with_to(Some(address))
                                .with_data(Some(
                                    decode(
                                        "0x01ffc9a7ffffffff00000000000000000000000000000000000000000000000000000000"
                                    ).unwrap()
                                ))
                                .to_eip1559()
                        ),
                        None
                    )
                    .to_json_string()
                    .unwrap(),
                );
            then.json_body_obj(
                &from_str::<Value>(&Response::new_success(
                    2,
                    "0x0000000000000000000000000000000000000000000000000000000000000001"
                ).to_json_string().unwrap())
                .unwrap(),
            );
        });
        let result = supports_erc165_check2(&client, address).await;
        assert!(!result);

        // Mock a revert response
        let address = Address::random();
        rpc_server.mock(|when, then| {
            when.method(POST)
                .path("/")
                .json_body_partial(
                    Request::<(TypedTransaction, BlockNumber)>::eth_call_request(
                        3,
                        TypedTransaction::Eip1559(
                            AlloyTransactionRequest::new()
                                .with_to(Some(address))
                                .with_data(Some(
                                    decode(
                                        "0x01ffc9a7ffffffff00000000000000000000000000000000000000000000000000000000"
                                    ).unwrap()
                                ))
                                .to_eip1559()
                        ),
                        None
                    )
                    .to_json_string()
                    .unwrap(),
                );
            then.json_body_obj(
                &from_str::<Value>(&Response::new_error(
                    3,
                    -32003,
                    "execution reverted",
                    Some("0x00"),
                ).to_json_string().unwrap())
                .unwrap(),
            );
        });
        let result = supports_erc165_check2(&client, address).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165() {
        let rpc_server = MockServer::start_async().await;
        let client = ReadableClient::new_from_url(rpc_server.url("/")).unwrap();

        // Mock a successful response
        let address = Address::random();
        rpc_server.mock(|when, then| {
            when.method(POST)
                .path("/")
                .json_body_partial(
                    Request::<(TypedTransaction, BlockNumber)>::eth_call_request(
                        1,
                        TypedTransaction::Eip1559(
                            AlloyTransactionRequest::new()
                                .with_to(Some(address))
                                .with_data(Some(
                                    decode(
                                        "0x01ffc9a701ffc9a700000000000000000000000000000000000000000000000000000000"
                                    ).unwrap()
                                ))
                                .to_eip1559()
                        ),
                        None
                    )
                    .to_json_string()
                    .unwrap(),
                );
            then.json_body_obj(
                &from_str::<Value>(&Response::new_success(
                    1,
                    "0x0000000000000000000000000000000000000000000000000000000000000001"
                ).to_json_string().unwrap())
                .unwrap(),
            );
        });
        rpc_server.mock(|when, then| {
            when.method(POST)
                .path("/")
                .json_body_partial(
                    Request::<(TypedTransaction, BlockNumber)>::eth_call_request(
                        2,
                        TypedTransaction::Eip1559(
                            AlloyTransactionRequest::new()
                                .with_to(Some(address))
                                .with_data(Some(
                                    decode(
                                        "0x01ffc9a7ffffffff00000000000000000000000000000000000000000000000000000000"
                                    ).unwrap()
                                ))
                                .to_eip1559()
                        ),
                        None
                    )
                    .to_json_string()
                    .unwrap(),
                );
            then.json_body_obj(
                &from_str::<Value>(&Response::new_success(
                    2,
                    "0x0000000000000000000000000000000000000000000000000000000000000000"
                ).to_json_string().unwrap())
                .unwrap(),
            );
        });
        let result = supports_erc165(&client, address).await;
        assert!(result);

        // Mock an unsuccessful response
        let address = Address::random();
        rpc_server.mock(|when, then| {
            when.method(POST)
                .path("/")
                .json_body_partial(
                    Request::<(TypedTransaction, BlockNumber)>::eth_call_request(
                        3,
                        TypedTransaction::Eip1559(
                            AlloyTransactionRequest::new()
                                .with_to(Some(address))
                                .with_data(Some(
                                    decode(
                                        "0x01ffc9a701ffc9a700000000000000000000000000000000000000000000000000000000"
                                    ).unwrap()
                                ))
                                .to_eip1559()
                        ),
                        None
                    )
                    .to_json_string()
                    .unwrap(),
                );
            then.json_body_obj(
                &from_str::<Value>(&Response::new_success(
                    3,
                    "0x0000000000000000000000000000000000000000000000000000000000000001"
                ).to_json_string().unwrap())
                .unwrap(),
            );
        });
        rpc_server.mock(|when, then| {
            when.method(POST)
                .path("/")
                .json_body_partial(
                    Request::<(TypedTransaction, BlockNumber)>::eth_call_request(
                        4,
                        TypedTransaction::Eip1559(
                            AlloyTransactionRequest::new()
                                .with_to(Some(address))
                                .with_data(Some(
                                    decode(
                                        "0x01ffc9a7ffffffff00000000000000000000000000000000000000000000000000000000"
                                    ).unwrap()
                                ))
                                .to_eip1559()
                        ),
                        None
                    )
                    .to_json_string()
                    .unwrap(),
                );
            then.json_body_obj(
                &from_str::<Value>(&Response::new_error(
                    4,
                    -32003,
                    "execution reverted",
                    Some("0x00"),
                )
                .to_json_string()
                .unwrap())
                .unwrap(),
            );
        });
        let result = supports_erc165(&client, address).await;
        assert!(!result);
    }
}
