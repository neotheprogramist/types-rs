use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use starknet_types_rpc::v0_7_1::starknet_api_openrpc::TxnWithHash;
use starknet_devnet_types::rpc::transaction_receipt::TransactionReceipt;
use super::block::BlockHeader;
use indexmap::IndexMap;
use crate::starknet::state_diff::StateDiff;
use starknet_types_core::felt::Felt;

pub type TransactionHash = Felt;
pub type BlockHash = Felt;


#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct StarknetTransactions(IndexMap<TransactionHash, StarknetTransaction>);

#[allow(unused)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StarknetTransaction {
    pub inner: TxnWithHash<Felt>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct StarknetBlock {
    pub header: BlockHeader,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct StarknetBlocks {
    pub hash_to_block: HashMap<BlockHash, StarknetBlock>,
    pub hash_to_state_diff: HashMap<BlockHash, StateDiff>,

}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct B11rInput {
    pub blocks: StarknetBlocks,
    pub transactions: StarknetTransactions,
    pub transaction_receipts: Vec<TransactionReceipt>,
}

impl StarknetBlocks {
    pub fn get_last_block_header(&self) -> Option<BlockHeader> {
        if let Some((_, block)) = self.hash_to_block.iter().last() {
            Some(block.header.clone())
        } else {
            None
        }
    }

    pub fn get_last_state_diff_with_hash(&self) -> Option<(BlockHash, StateDiff)> {
        if let Some((block_hash, block_state_diff)) = self.hash_to_state_diff.iter().last() {
            Some((block_hash.clone(), block_state_diff.clone()))
        } else {
            None
        }
    }
}

impl StarknetTransactions {
    pub fn to_txn_with_hash_vec(&self) -> Vec<TxnWithHash<Felt>> {
        self.0.values().map(|tx| tx.inner.clone()).collect()
    }
}