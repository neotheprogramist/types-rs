use super::header::L1DataAvailabilityMode;
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;

use starknet_types_rpc::v0_7_1::starknet_api_openrpc::TxnWithHash;

pub type BlockHash = Felt;
pub type CasmHash = Felt;
pub type ClassHash = Felt;
pub type ContractAddress = Felt;
pub type ContractNonce = Felt;
pub type SierraHash = Felt;
pub type StateCommitment = Felt;
pub type StateDiffCommitment = Felt;
pub type StorageAddress = Felt;
pub type StorageValue = Felt;
pub type BlockNumber = u64;
pub type BlockTimestamp = u64;
pub type GlobalRoot = Felt;
pub type SequencerContractAddress = Felt;
pub type StarknetVersion = String;
pub type U128 = String;

#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq)]
pub struct Block {
    pub header: BlockHeaderData,
    pub transactions: Vec<TxnWithHash<Felt>>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq)]
pub struct BlockHeaderData {
    pub hash: Felt,
    pub parent_hash: Felt,
    pub number: u64,
    pub timestamp: u64,
    pub sequencer_address: Felt,
    pub state_commitment: Felt,
    pub state_diff_commitment: Felt,
    pub transaction_commitment: Felt,
    pub transaction_count: u32,
    pub event_commitment: Felt,
    pub event_count: u32,
    pub state_diff_length: u32,
    pub starknet_version: String,
    pub eth_l1_gas_price: u128,
    pub strk_l1_gas_price: u128,
    pub eth_l1_data_gas_price: u128,
    pub strk_l1_data_gas_price: u128,
    pub receipt_commitment: Felt,
    pub l1_da_mode: L1DataAvailabilityMode,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq)]
pub struct BlockHeader {
    pub block_hash: BlockHash,
    pub parent_hash: BlockHash,
    pub block_number: BlockNumber,
    pub l1_gas_price: ResourcePrice,
    pub l1_data_gas_price: ResourcePrice,
    pub state_root: GlobalRoot,
    pub sequencer: SequencerContractAddress,
    pub timestamp: BlockTimestamp,
    pub l1_da_mode: L1DataAvailabilityMode,
    pub starknet_version: StarknetVersion,
}

#[derive(Clone, Debug, Eq, Hash, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourcePrice {
    /// the price of one unit of the given resource, denominated in fri (10^-18 strk)
    pub price_in_fri: U128,
    /// the price of one unit of the given resource, denominated in wei
    pub price_in_wei: U128,
}
