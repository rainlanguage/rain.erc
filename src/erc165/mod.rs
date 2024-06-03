use alloy_primitives::Address;
use alloy_sol_types::{sol, SolCall};
use alloy_ethers_typecast::transaction::{ReadContractParameters, ReadableClientHttp};

// IERC165 contract alloy bindings
sol!("lib/forge-std/src/interfaces/IERC165.sol");

/// get interface id from the given array of selectors, the array of selectors
/// should include all the functions (and only function) selectors of the
/// interface, in alloy and using its sol! macro bindings, the functions selectors
/// can be accessed through: `{AlloyContractName}::{AlloyContractNameCalls}::SELECTORS``
///
/// related info can be found here:
/// https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified
pub fn get_interface_id(selectors: &[[u8; 4]]) -> [u8; 4] {
    if selectors.is_empty() {
        panic!("no selectors")
    }
    let mut result = u32::from_be_bytes(selectors[0]);
    for selector in &selectors[1..] {
        result ^= u32::from_be_bytes(*selector);
    }
    result.to_be_bytes()
}

/// the first check for checking if a contract supports erc165
async fn supports_erc165_check1(client: &ReadableClientHttp, contract_address: Address) -> bool {
    let parameters = ReadContractParameters {
        address: contract_address,
        // equates to 0x01ffc9a701ffc9a700000000000000000000000000000000000000000000000000000000
        call: IERC165::supportsInterfaceCall {
            interfaceID: IERC165::supportsInterfaceCall::SELECTOR.into(),
        },
        block_number: None,
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
    };
    !client.read(parameters).await.map(|v| v._0).unwrap_or(true)
}

/// checks if the given contract implements ERC165
/// the process is done as described per ERC165 specs:
///
/// https://eips.ethereum.org/EIPS/eip-165#how-to-detect-if-a-contract-implements-erc-165
pub async fn supports_erc165(client: &ReadableClientHttp, contract_address: Address) -> bool {
    supports_erc165_check1(client, contract_address).await
        && supports_erc165_check2(client, contract_address).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex::decode;
    use serde::{Deserialize, Serialize};
    use httpmock::{Method::POST, MockServer};
    use serde_json::{from_str, value::RawValue, Value};
    use alloy_ethers_typecast::{
        request_shim::{AlloyTransactionRequest, TransactionRequestShim},
        transaction::ReadableClient,
    };
    use ethers::{
        types::{transaction::eip2718::TypedTransaction, BlockId, BlockNumber, U256},
        utils,
    };

    /// A JSON-RPC request, taken from ethers since it is private
    /// https://github.com/gakonst/ethers-rs/blob/master/ethers-providers/src/rpc/transports/common.rs
    #[derive(Serialize, Deserialize, Debug)]
    pub struct Request<'a, T> {
        id: u64,
        jsonrpc: &'a str,
        method: &'a str,
        params: T,
    }
    impl<'a, T> Request<'a, T> {
        /// Creates a new JSON RPC request
        pub fn new(id: u64, method: &'a str, params: T) -> Self {
            Self {
                id,
                jsonrpc: "2.0",
                method,
                params,
            }
        }
    }

    /// A JSON-RPC response, taken from ethers since it is private
    /// https://github.com/gakonst/ethers-rs/blob/master/ethers-providers/src/rpc/transports/common.rs
    #[derive(Debug, Serialize)]
    #[serde(untagged)]
    pub enum Response<'a> {
        Success {
            jsonrpc: &'a str,
            id: u64,
            result: &'a RawValue,
        },
        Error {
            jsonrpc: &'a str,
            id: u64,
            error: JsonRpcError,
        },
        #[allow(dead_code)]
        Notification { method: &'a str, params: Params<'a> },
    }

    /// A JSON-RPC 2.0 error, taken from ethers since it is private
    /// https://github.com/gakonst/ethers-rs/blob/master/ethers-providers/src/rpc/transports/common.rs
    #[derive(Debug, Clone, Serialize)]
    pub struct JsonRpcError {
        /// The error code
        pub code: i64,
        /// The error message
        pub message: String,
        /// Additional data
        pub data: Option<Value>,
    }

    /// taken from ethers since it is private
    /// https://github.com/gakonst/ethers-rs/blob/master/ethers-providers/src/rpc/transports/common.rs
    #[derive(Deserialize, Debug, Serialize)]
    pub struct Params<'a> {
        pub subscription: U256,
        #[serde(borrow)]
        pub result: &'a RawValue,
    }

    // test contracts bindings
    sol! {
        interface ITest {
            function externalFn1() external pure returns (bool);
            function externalFn2(uint256 val1, uint256 val2) external returns (uint256, bool);
            function externalFn3(address add) external returns (address);
        }
    }

    fn get_rpc_request_body(
        method: &str,
        id: u64,
        transaction: &AlloyTransactionRequest,
    ) -> String {
        let tx = utils::serialize(&TypedTransaction::Eip1559(transaction.to_eip1559()));
        let block = utils::serialize::<BlockId>(&BlockNumber::Latest.into());
        serde_json::to_string(&Request::new(id, method, [tx, block])).unwrap()
    }

    fn get_rpc_success_response_body(id: u64, result_data: &str) -> String {
        let res = Response::Success {
            id,
            jsonrpc: "2.0",
            result: &RawValue::from_string(format!("\"{}\"", result_data)).unwrap(),
        };
        serde_json::to_string(&res).unwrap()
    }

    fn get_rpc_error_response_body(
        id: u64,
        code: i64,
        message: &str,
        data: Option<&str>,
    ) -> String {
        let res = Response::Error {
            id,
            jsonrpc: "2.0",
            error: JsonRpcError {
                code,
                message: message.to_string(),
                data: data.map(|v| serde_json::to_value(v).unwrap()),
            },
        };
        serde_json::to_string(&res).unwrap()
    }

    #[test]
    fn test_get_interface_id() {
        let selectors = vec![
            //[1     2       3       4]
            [0b0001, 0b0010, 0b0011, 0b0100],
            //[5     6       7       8]
            [0b0101, 0b0110, 0b0111, 0b1000],
            //[9     10      11      12]
            [0b1001, 0b1010, 0b1011, 0b1100],
        ];
        let result = get_interface_id(&selectors);
        let expected: [u8; 4] = [0b1101, 0b1110, 0b1111, 0b0000]; // [13 14 15 0]
        assert_eq!(result, expected);

        let result = get_interface_id(IERC165::IERC165Calls::SELECTORS);
        let expected: [u8; 4] = 0x01ffc9a7u32.to_be_bytes(); // known IERC165 interface id
        assert_eq!(result, expected);

        let result = get_interface_id(ITest::ITestCalls::SELECTORS);
        let expected: [u8; 4] = 0x3dcd3fedu32.to_be_bytes(); // known ITest interface id
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn test_supports_erc165_check1() {
        let rpc_server = MockServer::start_async().await;
        let rpc_url = rpc_server.url("/");
        let client = ReadableClient::new_from_url(rpc_url.clone()).unwrap();

        // Mock a successful response, true
        let address = Address::random();

        rpc_server.mock(|when, then| {
            when.method(POST)
                .path("/")
                .json_body_partial(
                    get_rpc_request_body(
                        "eth_call",
                        1,
                        &AlloyTransactionRequest::new()
                        .with_to(Some(address))
                        .with_data(Some(decode("0x01ffc9a701ffc9a700000000000000000000000000000000000000000000000000000000").unwrap())),
                ));
            then.json_body_obj(
                &from_str::<Value>(&get_rpc_success_response_body(
                    1,
                    "0x0000000000000000000000000000000000000000000000000000000000000001",
                ))
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
                .json_body_partial(get_rpc_request_body(
                    "eth_call",
                    2,
                    &AlloyTransactionRequest::new()
                        .with_to(Some(address))
                        .with_data(Some(decode("0x01ffc9a701ffc9a700000000000000000000000000000000000000000000000000000000").unwrap())),
                ));
            then.json_body_obj(
                &from_str::<Value>(&get_rpc_success_response_body(
                    2,
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                ))
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
                .json_body_partial(get_rpc_request_body(
                    "eth_call",
                    3,
                    &AlloyTransactionRequest::new()
                        .with_to(Some(address))
                        .with_data(Some(decode("0x01ffc9a701ffc9a700000000000000000000000000000000000000000000000000000000").unwrap())),
                ));
            then.json_body_obj(
                &from_str::<Value>(&get_rpc_error_response_body(
                    3,
                    -32003,
                    "execution reverted",
                    Some("0x00"),
                ))
                .unwrap(),
            );
        });
        let result = supports_erc165_check1(&client, address).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165_check2() {
        let rpc_server = MockServer::start_async().await;
        let rpc_url = rpc_server.url("/");
        let client = ReadableClient::new_from_url(rpc_url.clone()).unwrap();

        // Mock a successful response, false
        let address = Address::random();
        rpc_server.mock(|when, then| {
            when.method(POST)
                .path("/")
                .json_body_partial(get_rpc_request_body(
                    "eth_call",
                    1,
                    &AlloyTransactionRequest::new()
                        .with_to(Some(address))
                        .with_data(Some(decode("0x01ffc9a7ffffffff00000000000000000000000000000000000000000000000000000000").unwrap())),
                ));
            then.json_body_obj(
                &from_str::<Value>(&get_rpc_success_response_body(
                    1,
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                ))
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
                .json_body_partial(get_rpc_request_body(
                    "eth_call",
                    2,
                    &AlloyTransactionRequest::new()
                        .with_to(Some(address))
                        .with_data(Some(decode("0x01ffc9a7ffffffff00000000000000000000000000000000000000000000000000000000").unwrap())),
                ));
            then.json_body_obj(
                &from_str::<Value>(&get_rpc_success_response_body(
                    2,
                    "0x0000000000000000000000000000000000000000000000000000000000000001",
                ))
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
                .json_body_partial(get_rpc_request_body(
                    "eth_call",
                    3,
                    &AlloyTransactionRequest::new()
                        .with_to(Some(address))
                        .with_data(Some(decode("0x01ffc9a7ffffffff00000000000000000000000000000000000000000000000000000000").unwrap())),
                ));
            then.json_body_obj(
                &from_str::<Value>(&get_rpc_error_response_body(
                    3,
                    -32003,
                    "execution reverted",
                    Some("0x00"),
                ))
                .unwrap(),
            );
        });
        let result = supports_erc165_check2(&client, address).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_supports_erc165() {
        let rpc_server = MockServer::start_async().await;
        let rpc_url = rpc_server.url("/");
        let client = ReadableClient::new_from_url(rpc_url.clone()).unwrap();

        // Mock a successful response
        let address = Address::random();
        rpc_server.mock(|when, then| {
            when.method(POST)
                .path("/")
                .json_body_partial(get_rpc_request_body(
                    "eth_call",
                    1,
                    &AlloyTransactionRequest::new()
                        .with_to(Some(address))
                        .with_data(Some(decode("0x01ffc9a701ffc9a700000000000000000000000000000000000000000000000000000000").unwrap())),
                ));
            then.json_body_obj(
                &from_str::<Value>(&get_rpc_success_response_body(
                    1,
                    "0x0000000000000000000000000000000000000000000000000000000000000001",
                ))
                .unwrap(),
            );
        });
        rpc_server.mock(|when, then| {
            when.method(POST)
                .path("/")
                .json_body_partial(get_rpc_request_body(
                    "eth_call",
                    2,
                    &AlloyTransactionRequest::new()
                        .with_to(Some(address))
                        .with_data(Some(decode("0x01ffc9a7ffffffff00000000000000000000000000000000000000000000000000000000").unwrap())),
                ));
            then.json_body_obj(
                &from_str::<Value>(&get_rpc_success_response_body(
                    2,
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                ))
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
                .json_body_partial(get_rpc_request_body(
                    "eth_call",
                    3,
                    &AlloyTransactionRequest::new()
                        .with_to(Some(address))
                        .with_data(Some(decode("0x01ffc9a701ffc9a700000000000000000000000000000000000000000000000000000000").unwrap())),
                ));
            then.json_body_obj(
                &from_str::<Value>(&get_rpc_success_response_body(
                    3,
                    "0x0000000000000000000000000000000000000000000000000000000000000001",
                ))
                .unwrap(),
            );
        });
        rpc_server.mock(|when, then| {
            when.method(POST)
                .path("/")
                .json_body_partial(get_rpc_request_body(
                    "eth_call",
                    4,
                    &AlloyTransactionRequest::new()
                        .with_to(Some(address))
                        .with_data(Some(decode("0x01ffc9a7ffffffff00000000000000000000000000000000000000000000000000000000").unwrap())),
                ));
            then.json_body_obj(
                &from_str::<Value>(&get_rpc_error_response_body(
                    4,
                    -32003,
                    "execution reverted",
                    Some("0x00"),
                ))
                .unwrap(),
            );
        });
        let result = supports_erc165(&client, address).await;
        assert!(!result);
    }
}
