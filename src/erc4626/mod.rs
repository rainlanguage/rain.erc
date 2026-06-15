// SPDX-License-Identifier: CAL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2024 Rain Open Source Software Ltd

use alloy::contract::Error as ContractError;
use alloy::network::Network;
use alloy::primitives::{Address, U256};
use alloy::providers::{CallItem, Failure, MulticallError, Provider, MULTICALL3_ADDRESS};
use alloy::rpc::types::{BlockId, BlockNumberOrTag};
use alloy::sol;
use alloy::sol_types::SolCall;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

sol!(
    #[sol(rpc)]
    interface IERC4626 {
        function asset() external view returns (address);
        function decimals() external view returns (uint8);
        function convertToAssets(uint256 shares) external view returns (uint256);
        function convertToShares(uint256 assets) external view returns (uint256);
    }
);

sol!(
    #[sol(rpc)]
    interface IERC20Metadata {
        function decimals() external view returns (uint8);
    }
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Erc4626ShareAssetConversion {
    pub share_token_address: Address,
    pub share_token_decimals: u8,
    pub asset_address: Address,
    pub asset_decimals: u8,
    pub shares: U256,
    pub shares_display: String,
    pub assets: U256,
    pub assets_display: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Erc4626BatchVault {
    pub vault_address: Address,
    pub shares: Option<U256>,
}

impl Erc4626BatchVault {
    pub const fn new(vault_address: Address) -> Self {
        Self {
            vault_address,
            shares: None,
        }
    }

    pub const fn with_shares(mut self, shares: U256) -> Self {
        self.shares = Some(shares);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Erc4626BatchItem {
    pub vault_address: Address,
    pub success: bool,
    pub data: Option<Erc4626ShareAssetConversion>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Erc4626BatchResponse {
    pub block_number: u64,
    pub block_timestamp: u64,
    pub captured_at: u64,
    pub items: Vec<Erc4626BatchItem>,
}

#[derive(Error, Debug)]
pub enum Erc4626Error {
    #[error(transparent)]
    Contract(#[from] ContractError),
    #[error(transparent)]
    Transport(#[from] alloy::transports::TransportError),
    #[error("multicall failed: {0}")]
    Multicall(#[from] MulticallError),
    #[error("decimal scale overflow for decimals {decimals}")]
    DecimalScaleOverflow { decimals: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BatchState {
    vault_address: Address,
    share_decimals: Option<u8>,
    asset_address: Option<Address>,
    asset_decimals: Option<u8>,
    shares: Option<U256>,
    assets: Option<U256>,
    error: Option<String>,
}

impl BatchState {
    fn new(input: &Erc4626BatchVault) -> Self {
        Self {
            vault_address: input.vault_address,
            share_decimals: None,
            asset_address: None,
            asset_decimals: None,
            shares: input.shares,
            assets: None,
            error: None,
        }
    }

    fn set_error(&mut self, error: impl Into<String>) {
        if self.error.is_none() {
            self.error = Some(error.into());
        }
    }

    fn into_item(self) -> Erc4626BatchItem {
        let mut error = self.error;
        let data = match (
            self.share_decimals,
            self.asset_address,
            self.asset_decimals,
            self.shares,
            self.assets,
        ) {
            (
                Some(share_decimals),
                Some(asset_address),
                Some(asset_decimals),
                Some(shares),
                Some(assets),
            ) => match build_conversion(
                self.vault_address,
                share_decimals,
                asset_address,
                asset_decimals,
                shares,
                assets,
            ) {
                Ok(conversion) => Some(conversion),
                Err(err) => {
                    if error.is_none() {
                        error = Some(err.to_string());
                    }
                    None
                }
            },
            _ => None,
        };

        let error = match (error, data.is_none()) {
            (Some(error), _) => Some(error),
            (None, true) => Some("Incomplete ERC4626 batch result".to_string()),
            (None, false) => None,
        };

        Erc4626BatchItem {
            vault_address: self.vault_address,
            success: error.is_none(),
            data,
            error,
        }
    }
}

pub async fn batch_share_ratios<P, N>(
    provider: &P,
    vaults: Vec<Erc4626BatchVault>,
    multicall3_address: Option<Address>,
) -> Result<Erc4626BatchResponse, Erc4626Error>
where
    P: Provider<N>,
    N: Network,
{
    let captured_at = captured_at_unix_timestamp();
    let block_number = provider.get_block_number().await?;
    let block_id = BlockId::Number(BlockNumberOrTag::Number(block_number));
    let multicall3_address = multicall3_address.unwrap_or(MULTICALL3_ADDRESS);
    let block_timestamp = current_block_timestamp(provider, block_id, multicall3_address).await?;

    let mut states = vaults.iter().map(BatchState::new).collect::<Vec<_>>();
    if !states.is_empty() {
        read_share_decimals(provider, block_id, multicall3_address, &mut states).await?;
        read_assets(provider, block_id, multicall3_address, &mut states).await?;
        read_asset_decimals(provider, block_id, multicall3_address, &mut states).await?;
        read_converted_assets(provider, block_id, multicall3_address, &mut states).await?;
    }

    let items = states.into_iter().map(BatchState::into_item).collect();

    Ok(Erc4626BatchResponse {
        block_number,
        block_timestamp,
        captured_at,
        items,
    })
}

pub async fn share_ratio<P, N>(
    provider: &P,
    vault_address: Address,
    multicall3_address: Option<Address>,
) -> Result<Erc4626BatchResponse, Erc4626Error>
where
    P: Provider<N>,
    N: Network,
{
    batch_share_ratios(
        provider,
        vec![Erc4626BatchVault::new(vault_address)],
        multicall3_address,
    )
    .await
}

pub async fn share_decimals<P, N>(provider: &P, vault_address: Address) -> Result<u8, Erc4626Error>
where
    P: Provider<N>,
    N: Network,
{
    let vault = IERC4626::new(vault_address, provider);
    Ok(vault.decimals().call().await?)
}

pub async fn asset<P, N>(provider: &P, vault_address: Address) -> Result<Address, Erc4626Error>
where
    P: Provider<N>,
    N: Network,
{
    let vault = IERC4626::new(vault_address, provider);
    Ok(vault.asset().call().await?)
}

pub async fn convert_to_assets<P, N>(
    provider: &P,
    vault_address: Address,
    shares: U256,
) -> Result<U256, Erc4626Error>
where
    P: Provider<N>,
    N: Network,
{
    let vault = IERC4626::new(vault_address, provider);
    Ok(vault.convertToAssets(shares).call().await?)
}

pub async fn convert_to_shares<P, N>(
    provider: &P,
    vault_address: Address,
    assets: U256,
) -> Result<U256, Erc4626Error>
where
    P: Provider<N>,
    N: Network,
{
    let vault = IERC4626::new(vault_address, provider);
    Ok(vault.convertToShares(assets).call().await?)
}

async fn current_block_timestamp<P, N>(
    provider: &P,
    block_id: BlockId,
    multicall3_address: Address,
) -> Result<u64, Erc4626Error>
where
    P: Provider<N>,
    N: Network,
{
    let (timestamp,) = provider
        .multicall()
        .address(multicall3_address)
        .block(block_id)
        .get_current_block_timestamp()
        .aggregate()
        .await?;
    Ok(timestamp.to())
}

async fn read_share_decimals<P, N>(
    provider: &P,
    block_id: BlockId,
    multicall3_address: Address,
    states: &mut [BatchState],
) -> Result<(), Erc4626Error>
where
    P: Provider<N>,
    N: Network,
{
    let mut multicall = provider
        .multicall()
        .address(multicall3_address)
        .block(block_id)
        .dynamic::<IERC4626::decimalsCall>();

    for state in states.iter() {
        multicall = multicall.add_call_dynamic(
            CallItem::<IERC4626::decimalsCall>::new(
                state.vault_address,
                IERC4626::decimalsCall {}.abi_encode().into(),
            )
            .allow_failure(true),
        );
    }

    for (state, result) in states.iter_mut().zip(multicall.aggregate3().await?) {
        match result {
            Ok(decimals) => state.share_decimals = Some(decimals),
            Err(failure) => state.set_error(multicall_failure("share decimals", failure)),
        }
    }

    for state in states.iter_mut() {
        if state.error.is_none() && state.shares.is_none() {
            if let Some(share_decimals) = state.share_decimals {
                match decimal_scale(share_decimals) {
                    Ok(shares) => state.shares = Some(shares),
                    Err(err) => state.set_error(err.to_string()),
                }
            }
        }
    }

    Ok(())
}

async fn read_assets<P, N>(
    provider: &P,
    block_id: BlockId,
    multicall3_address: Address,
    states: &mut [BatchState],
) -> Result<(), Erc4626Error>
where
    P: Provider<N>,
    N: Network,
{
    let mut multicall = provider
        .multicall()
        .address(multicall3_address)
        .block(block_id)
        .dynamic::<IERC4626::assetCall>();

    for state in states.iter() {
        multicall = multicall.add_call_dynamic(
            CallItem::<IERC4626::assetCall>::new(
                state.vault_address,
                IERC4626::assetCall {}.abi_encode().into(),
            )
            .allow_failure(true),
        );
    }

    for (state, result) in states.iter_mut().zip(multicall.aggregate3().await?) {
        match result {
            Ok(asset) => state.asset_address = Some(asset),
            Err(failure) => state.set_error(multicall_failure("asset", failure)),
        }
    }

    Ok(())
}

async fn read_asset_decimals<P, N>(
    provider: &P,
    block_id: BlockId,
    multicall3_address: Address,
    states: &mut [BatchState],
) -> Result<(), Erc4626Error>
where
    P: Provider<N>,
    N: Network,
{
    let mut call_indexes = Vec::new();
    let mut multicall = provider
        .multicall()
        .address(multicall3_address)
        .block(block_id)
        .dynamic::<IERC20Metadata::decimalsCall>();

    for (index, state) in states.iter().enumerate() {
        if state.error.is_some() {
            continue;
        }
        if let Some(asset_address) = state.asset_address {
            call_indexes.push(index);
            multicall = multicall.add_call_dynamic(
                CallItem::<IERC20Metadata::decimalsCall>::new(
                    asset_address,
                    IERC20Metadata::decimalsCall {}.abi_encode().into(),
                )
                .allow_failure(true),
            );
        }
    }

    if call_indexes.is_empty() {
        return Ok(());
    }

    for (index, result) in call_indexes.into_iter().zip(multicall.aggregate3().await?) {
        match result {
            Ok(decimals) => states[index].asset_decimals = Some(decimals),
            Err(failure) => states[index].set_error(multicall_failure("asset decimals", failure)),
        }
    }

    Ok(())
}

async fn read_converted_assets<P, N>(
    provider: &P,
    block_id: BlockId,
    multicall3_address: Address,
    states: &mut [BatchState],
) -> Result<(), Erc4626Error>
where
    P: Provider<N>,
    N: Network,
{
    let mut call_indexes = Vec::new();
    let mut multicall = provider
        .multicall()
        .address(multicall3_address)
        .block(block_id)
        .dynamic::<IERC4626::convertToAssetsCall>();

    for (index, state) in states.iter().enumerate() {
        if state.error.is_some() {
            continue;
        }
        if let Some(shares) = state.shares {
            call_indexes.push(index);
            multicall = multicall.add_call_dynamic(
                CallItem::<IERC4626::convertToAssetsCall>::new(
                    state.vault_address,
                    IERC4626::convertToAssetsCall { shares }.abi_encode().into(),
                )
                .allow_failure(true),
            );
        }
    }

    if call_indexes.is_empty() {
        return Ok(());
    }

    for (index, result) in call_indexes.into_iter().zip(multicall.aggregate3().await?) {
        match result {
            Ok(assets) => states[index].assets = Some(assets),
            Err(failure) => {
                states[index].set_error(multicall_failure("convert to assets", failure))
            }
        }
    }

    Ok(())
}

fn build_conversion(
    share_token_address: Address,
    share_decimals: u8,
    asset_address: Address,
    asset_decimals: u8,
    shares: U256,
    assets: U256,
) -> Result<Erc4626ShareAssetConversion, Erc4626Error> {
    Ok(Erc4626ShareAssetConversion {
        share_token_address,
        share_token_decimals: share_decimals,
        asset_address,
        asset_decimals,
        shares,
        shares_display: format_units(shares, share_decimals)?,
        assets,
        assets_display: format_units(assets, asset_decimals)?,
    })
}

fn format_units(value: U256, decimals: u8) -> Result<String, Erc4626Error> {
    let scale = decimal_scale(decimals)?;
    let whole = value / scale;
    let fractional = value % scale;
    if fractional.is_zero() {
        return Ok(whole.to_string());
    }

    let width = usize::from(decimals);
    let mut fractional = fractional.to_string();
    if fractional.len() > width {
        return Err(Erc4626Error::DecimalScaleOverflow { decimals });
    }
    let padding = width - fractional.len();
    if padding > 0 {
        fractional = format!("{}{}", "0".repeat(padding), fractional);
    }
    let fractional = fractional.trim_end_matches('0');
    Ok(format!("{whole}.{fractional}"))
}

fn decimal_scale(decimals: u8) -> Result<U256, Erc4626Error> {
    U256::from(10)
        .checked_pow(U256::from(decimals))
        .ok_or(Erc4626Error::DecimalScaleOverflow { decimals })
}

fn multicall_failure(label: &str, failure: Failure) -> String {
    format!(
        "{label} call failed at index {} with return data: {}",
        failure.idx, failure.return_data
    )
}

fn captured_at_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::hex;
    use alloy::providers::bindings::IMulticall3::{
        aggregate3Call, aggregateCall, aggregateReturn, getCurrentBlockTimestampCall,
        Result as MulticallResult,
    };
    use alloy::providers::{mock::Asserter, ProviderBuilder};

    fn mocked_provider(asserter: Asserter) -> impl Provider {
        ProviderBuilder::new().connect_mocked_client(asserter)
    }

    fn success_result<C: SolCall>(value: &C::Return) -> MulticallResult {
        MulticallResult {
            success: true,
            returnData: C::abi_encode_returns(value).into(),
        }
    }

    fn failed_result() -> MulticallResult {
        MulticallResult {
            success: false,
            returnData: vec![0xde, 0xad, 0xbe, 0xef].into(),
        }
    }

    fn aggregate_success(results: Vec<MulticallResult>) -> String {
        format!(
            "0x{}",
            hex::encode(aggregate3Call::abi_encode_returns(&results))
        )
    }

    fn timestamp_success(block_number: u64, timestamp: u64) -> String {
        let ret = aggregateReturn {
            blockNumber: U256::from(block_number),
            returnData: vec![
                getCurrentBlockTimestampCall::abi_encode_returns(&U256::from(timestamp)).into(),
            ],
        };
        format!("0x{}", hex::encode(aggregateCall::abi_encode_returns(&ret)))
    }

    #[tokio::test]
    async fn test_batch_share_ratios_multi_vault_success() {
        let asserter = Asserter::new();
        let vault1 = Address::repeat_byte(0x11);
        let vault2 = Address::repeat_byte(0x22);
        let asset1 = Address::repeat_byte(0xaa);
        let asset2 = Address::repeat_byte(0xbb);
        let shares = U256::from(10).pow(U256::from(18));

        asserter.push_success(&"0x7d");
        asserter.push_success(&timestamp_success(125, 456));
        asserter.push_success(&aggregate_success(vec![
            success_result::<IERC4626::decimalsCall>(&18u8),
            success_result::<IERC4626::decimalsCall>(&18u8),
        ]));
        asserter.push_success(&aggregate_success(vec![
            success_result::<IERC4626::assetCall>(&asset1),
            success_result::<IERC4626::assetCall>(&asset2),
        ]));
        asserter.push_success(&aggregate_success(vec![
            success_result::<IERC20Metadata::decimalsCall>(&18u8),
            success_result::<IERC20Metadata::decimalsCall>(&6u8),
        ]));
        asserter.push_success(&aggregate_success(vec![
            success_result::<IERC4626::convertToAssetsCall>(&shares),
            success_result::<IERC4626::convertToAssetsCall>(&U256::from(1_500_000u64)),
        ]));

        let response = batch_share_ratios(
            &mocked_provider(asserter),
            vec![
                Erc4626BatchVault::new(vault1),
                Erc4626BatchVault::new(vault2),
            ],
            None,
        )
        .await
        .unwrap();

        assert_eq!(response.block_number, 125);
        assert_eq!(response.block_timestamp, 456);
        assert_eq!(response.items.len(), 2);
        assert!(response.items[0].success);
        let data = response.items[0].data.as_ref().unwrap();
        assert_eq!(data.share_token_address, vault1);
        assert_eq!(data.asset_address, asset1);
        assert_eq!(data.shares, shares);
        assert_eq!(data.assets, shares);
        assert_eq!(data.shares_display, "1");
        assert_eq!(data.assets_display, "1");

        assert!(response.items[1].success);
        let data = response.items[1].data.as_ref().unwrap();
        assert_eq!(data.asset_address, asset2);
        assert_eq!(data.assets_display, "1.5");
    }

    #[tokio::test]
    async fn test_batch_share_ratios_per_item_failure() {
        let asserter = Asserter::new();
        let vault1 = Address::repeat_byte(0x33);
        let vault2 = Address::repeat_byte(0x44);
        let asset1 = Address::repeat_byte(0xcc);
        let shares = U256::from(10).pow(U256::from(18));

        asserter.push_success(&"0x7e");
        asserter.push_success(&timestamp_success(126, 457));
        asserter.push_success(&aggregate_success(vec![
            success_result::<IERC4626::decimalsCall>(&18u8),
            success_result::<IERC4626::decimalsCall>(&18u8),
        ]));
        asserter.push_success(&aggregate_success(vec![
            success_result::<IERC4626::assetCall>(&asset1),
            failed_result(),
        ]));
        asserter.push_success(&aggregate_success(vec![success_result::<
            IERC20Metadata::decimalsCall,
        >(&18u8)]));
        asserter.push_success(&aggregate_success(vec![success_result::<
            IERC4626::convertToAssetsCall,
        >(&shares)]));

        let response = batch_share_ratios(
            &mocked_provider(asserter),
            vec![
                Erc4626BatchVault::new(vault1),
                Erc4626BatchVault::new(vault2),
            ],
            None,
        )
        .await
        .unwrap();

        assert_eq!(response.items.len(), 2);
        assert!(response.items[0].success);
        assert!(response.items[0].data.is_some());
        assert!(!response.items[1].success);
        assert!(response.items[1].data.is_none());
        assert!(response.items[1]
            .error
            .as_ref()
            .unwrap()
            .contains("asset call failed"));
    }

    #[tokio::test]
    async fn test_batch_share_ratios_one_item_custom_shares() {
        let asserter = Asserter::new();
        let vault = Address::repeat_byte(0x55);
        let asset = Address::repeat_byte(0xdd);
        let shares = U256::from(2) * U256::from(10).pow(U256::from(18));
        let assets = U256::from(3) * U256::from(10).pow(U256::from(18));

        asserter.push_success(&"0x7f");
        asserter.push_success(&timestamp_success(127, 458));
        asserter.push_success(&aggregate_success(vec![success_result::<
            IERC4626::decimalsCall,
        >(&18u8)]));
        asserter.push_success(&aggregate_success(vec![success_result::<
            IERC4626::assetCall,
        >(&asset)]));
        asserter.push_success(&aggregate_success(vec![success_result::<
            IERC20Metadata::decimalsCall,
        >(&18u8)]));
        asserter.push_success(&aggregate_success(vec![success_result::<
            IERC4626::convertToAssetsCall,
        >(&assets)]));

        let response = batch_share_ratios(
            &mocked_provider(asserter),
            vec![Erc4626BatchVault::new(vault).with_shares(shares)],
            None,
        )
        .await
        .unwrap();

        assert_eq!(response.items.len(), 1);
        let data = response.items[0].data.as_ref().unwrap();
        assert_eq!(data.share_token_address, vault);
        assert_eq!(data.asset_address, asset);
        assert_eq!(data.shares, shares);
        assert_eq!(data.assets, assets);
        assert_eq!(data.shares_display, "2");
        assert_eq!(data.assets_display, "3");
    }

    #[test]
    fn test_format_units() {
        assert_eq!(format_units(U256::from(1_500_000u64), 6).unwrap(), "1.5");
        assert_eq!(format_units(U256::from(1_000_000u64), 6).unwrap(), "1");
        assert_eq!(format_units(U256::from(1u64), 6).unwrap(), "0.000001");
    }

    #[test]
    fn test_decimal_scale() {
        assert_eq!(
            decimal_scale(18).unwrap(),
            U256::from(10).pow(U256::from(18))
        );

        let err = decimal_scale(u8::MAX).unwrap_err();
        assert!(matches!(
            err,
            Erc4626Error::DecimalScaleOverflow { decimals: u8::MAX }
        ));
    }

    #[test]
    fn test_format_units_rejects_scale_overflow() {
        assert!(format_units(U256::from(1u64), u8::MAX).is_err());
    }

    // A BatchState carrying every field populated with valid data, so
    // `into_item` takes the success path. Individual tests clear one
    // field (or pre-seed an error) to drive a single branch of the
    // error-precedence state machine.
    fn complete_state() -> BatchState {
        BatchState {
            vault_address: Address::repeat_byte(0x11),
            share_decimals: Some(18),
            asset_address: Some(Address::repeat_byte(0xaa)),
            asset_decimals: Some(6),
            shares: Some(U256::from(10).pow(U256::from(18))),
            assets: Some(U256::from(1_500_000u64)),
            error: None,
        }
    }

    #[test]
    fn test_set_error_keeps_first() {
        // set_error is first-wins: a later error must not clobber an
        // earlier one. Pins the `if self.error.is_none()` guard.
        let mut state = complete_state();
        state.set_error("first");
        state.set_error("second");
        assert_eq!(state.error.as_deref(), Some("first"));
    }

    #[test]
    fn test_set_error_sets_when_empty() {
        // The other side of the guard: an empty error slot does get
        // filled. Without this, a mutant that no-ops set_error entirely
        // would survive the first-wins test above.
        let mut state = complete_state();
        assert!(state.error.is_none());
        state.set_error("only");
        assert_eq!(state.error.as_deref(), Some("only"));
    }

    #[test]
    fn test_into_item_complete_state_succeeds() {
        // All fields present, no error: success with populated data and
        // no error string. Anchors the (None, false) arm and the
        // success path of the value match.
        let item = complete_state().into_item();
        assert!(item.success);
        assert!(item.error.is_none());
        let data = item.data.as_ref().unwrap();
        assert_eq!(data.share_token_address, Address::repeat_byte(0x11));
        assert_eq!(data.share_token_decimals, 18);
        assert_eq!(data.asset_address, Address::repeat_byte(0xaa));
        assert_eq!(data.asset_decimals, 6);
        assert_eq!(data.shares, U256::from(10).pow(U256::from(18)));
        assert_eq!(data.assets, U256::from(1_500_000u64));
        assert_eq!(data.shares_display, "1");
        assert_eq!(data.assets_display, "1.5");
    }

    #[test]
    fn test_into_item_incomplete_without_error_synthesizes_message() {
        // A state that completed its reads without an explicit error but
        // is missing a field (here `assets`) must NOT silently report
        // success: into_item synthesizes the sentinel error and marks
        // the item failed. Pins the `(None, true)` arm and its exact
        // message — a mutant that drops the synthesized error (returns
        // None) or changes the string is killed.
        let mut state = complete_state();
        state.assets = None;
        let item = state.into_item();
        assert!(!item.success);
        assert!(item.data.is_none());
        assert_eq!(
            item.error.as_deref(),
            Some("Incomplete ERC4626 batch result")
        );
    }

    #[test]
    fn test_into_item_existing_error_takes_precedence_over_synthesized() {
        // When a real error was already recorded AND data is missing,
        // the recorded error must win over the synthesized "Incomplete"
        // sentinel. Distinguishes the `(Some, true)` arm from the
        // `(None, true)` arm.
        let mut state = complete_state();
        state.assets = None;
        state.set_error("asset call failed at index 3");
        let item = state.into_item();
        assert!(!item.success);
        assert!(item.data.is_none());
        assert_eq!(item.error.as_deref(), Some("asset call failed at index 3"));
    }

    #[test]
    fn test_into_item_error_present_with_data_reports_failure() {
        // A pre-seeded error must survive even when every field is
        // present and a conversion could be built: the item reports
        // failure and surfaces the recorded error. Pins the
        // error-wins precedence (the `(Some(error), _)` arm) — a mutant
        // that drops the error whenever data exists is killed. Whether
        // `data` is populated alongside is an implementation detail this
        // test deliberately does not constrain.
        let mut state = complete_state();
        state.set_error("share decimals call failed at index 0");
        let item = state.into_item();
        assert!(!item.success);
        assert_eq!(
            item.error.as_deref(),
            Some("share decimals call failed at index 0")
        );
    }

    #[test]
    fn test_into_item_build_conversion_error_recorded() {
        // All fields present but a field forces build_conversion to
        // fail (decimals = u8::MAX overflows decimal_scale). The
        // resulting error must be recorded and the item marked failed
        // with no data. Pins the `Err(err)` arm inside into_item that
        // folds a build_conversion failure into the state error.
        let mut state = complete_state();
        state.asset_decimals = Some(u8::MAX);
        let item = state.into_item();
        assert!(!item.success);
        assert!(item.data.is_none());
        assert!(item
            .error
            .as_deref()
            .unwrap()
            .contains("decimal scale overflow"));
    }

    #[test]
    fn test_multicall_failure_message_includes_label_index_and_data() {
        // The per-call failure message must interpolate the label, the
        // exact failing index, and the return data. The batch tests only
        // assert the label substring, so the index and return-data
        // fields are otherwise unpinned.
        let msg = multicall_failure(
            "asset",
            Failure {
                idx: 7,
                return_data: vec![0xde, 0xad, 0xbe, 0xef].into(),
            },
        );
        assert_eq!(
            msg,
            "asset call failed at index 7 with return data: 0xdeadbeef"
        );
    }
}
