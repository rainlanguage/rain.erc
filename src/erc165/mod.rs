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
    // first check
    if !supports_erc165_check1(client, contract_address).await {
        return false;
    }
    // second check
    supports_erc165_check2(client, contract_address).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, time::Duration};
    use alloy_ethers_typecast::{ethers_address_to_alloy, transaction::ReadableClient};
    use ethers::{
        contract::abigen,
        core::utils::Anvil,
        middleware::SignerMiddleware,
        providers::{Http, Provider},
        signers::{LocalWallet, Signer},
    };

    sol! {
        interface ITest {
            function externalFn1() external pure returns (bool);
            function externalFn2(uint256 val1, uint256 val2) external returns (uint256, bool);
            function externalFn3(address add) external returns (address);
        }
    }
    abigen!(NonERC165, "test-contracts/out/NonERC165.sol/NonERC165.json");
    abigen!(BadERC165, "test-contracts/out/BadERC165.sol/BadERC165.json");
    abigen!(
        ERC165Supported,
        "test-contracts/out/ERC165Supported.sol/ERC165Supported.json"
    );

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
        let anvil = Anvil::new().spawn();
        let wallet: LocalWallet = anvil.keys()[0].clone().into();
        let provider = Provider::<Http>::try_from(anvil.endpoint())
            .expect("could not instantiate anvil provider")
            .interval(Duration::from_millis(10u64));
        let ethers_client =
            SignerMiddleware::new(provider.clone(), wallet.with_chain_id(anvil.chain_id()));

        let wallet_signer = Arc::new(ethers_client);
        let client = ReadableClient::new(provider);

        let contract = NonERC165::deploy(wallet_signer.clone(), ())
            .expect("failed to deploy NonERC165 test contract")
            .send()
            .await
            .expect("failed to deploy NonERC165 test contract");
        let contract_address = ethers_address_to_alloy(contract.address());
        assert!(!supports_erc165_check1(&client, contract_address).await);

        let contract = BadERC165::deploy(wallet_signer.clone(), ())
            .expect("failed to deploy BadERC165 test contract")
            .send()
            .await
            .expect("failed to deploy BadERC165 test contract");
        let contract_address = ethers_address_to_alloy(contract.address());
        assert!(supports_erc165_check1(&client, contract_address).await);

        let contract = ERC165Supported::deploy(wallet_signer.clone(), ())
            .expect("failed to deploy ERC165Supported test contract")
            .send()
            .await
            .expect("failed to deploy ERC165Supported test contract");
        let contract_address = ethers_address_to_alloy(contract.address());
        assert!(supports_erc165_check1(&client, contract_address).await);
    }

    #[tokio::test]
    async fn test_supports_erc165_check2() {
        let anvil = Anvil::new().spawn();
        let wallet: LocalWallet = anvil.keys()[0].clone().into();
        let provider = Provider::<Http>::try_from(anvil.endpoint())
            .expect("could not instantiate anvil provider")
            .interval(Duration::from_millis(10u64));
        let etheres_client =
            SignerMiddleware::new(provider.clone(), wallet.with_chain_id(anvil.chain_id()));

        let wallet_signer = Arc::new(etheres_client);
        let client = ReadableClient::new(provider);

        let contract = ERC165Supported::deploy(wallet_signer.clone(), ())
            .expect("failed to deploy ERC165Supported test contract")
            .send()
            .await
            .expect("failed to deploy ERC165Supported test contract");
        let contract_address = ethers_address_to_alloy(contract.address());
        assert!(supports_erc165_check2(&client, contract_address).await);

        let contract = BadERC165::deploy(wallet_signer.clone(), ())
            .expect("failed to deploy BadERC165 test contract")
            .send()
            .await
            .expect("failed to deploy BadERC165 test contract");
        let contract_address = ethers_address_to_alloy(contract.address());
        assert!(!supports_erc165_check2(&client, contract_address).await);
    }

    #[tokio::test]
    async fn test_supports_erc165() {
        let anvil = Anvil::new().spawn();
        let wallet: LocalWallet = anvil.keys()[0].clone().into();
        let provider = Provider::<Http>::try_from(anvil.endpoint())
            .expect("could not instantiate anvil provider")
            .interval(Duration::from_millis(10u64));
        let ethers_client =
            SignerMiddleware::new(provider.clone(), wallet.with_chain_id(anvil.chain_id()));

        let wallet_signer = Arc::new(ethers_client);
        let client = ReadableClient::new(provider);

        let contract = NonERC165::deploy(wallet_signer.clone(), ())
            .expect("failed to deploy NonERC165 test contract")
            .send()
            .await
            .expect("failed to deploy NonERC165 test contract");
        let contract_address = ethers_address_to_alloy(contract.address());
        assert!(!supports_erc165(&client, contract_address).await);

        let contract = BadERC165::deploy(wallet_signer.clone(), ())
            .expect("failed to deploy BadERC165 test contract")
            .send()
            .await
            .expect("failed to deploy BadERC165 test contract");
        let contract_address = ethers_address_to_alloy(contract.address());
        assert!(!supports_erc165(&client, contract_address).await);

        let contract = ERC165Supported::deploy(wallet_signer.clone(), ())
            .expect("failed to deploy ERC165Supported test contract")
            .send()
            .await
            .expect("failed to deploy ERC165Supported test contract");
        let contract_address = ethers_address_to_alloy(contract.address());
        assert!(supports_erc165(&client, contract_address).await);
    }
}
