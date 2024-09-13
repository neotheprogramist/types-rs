use std::io::Write;
// use std::sync::LazyLock;

use super::block::BlockHeaderData;
use super::header::{BlockHeader, L1DataAvailabilityMode,};
use super::receipt::ThinReceipt;
use crate::types::event::Event;
use crate::types::hash::{FeltHash, PoseidonHash};
use anyhow::{Context, Result};
use starknet_types_core::hash::{poseidon_hash_many, PoseidonHasher};
use starknet_types_rpc::v0_7_1::starknet_api_openrpc::{
    DeclareTxn, DeployAccountTxn, InvokeTxn, Txn, TxnWithHash,
};


use super::transaction::TransactionOrEventTree;
use sha3::Digest;
use starknet_types_core::felt::Felt;
// use starknet_gateway_types::reply::Block;


impl BlockHeaderData {
    pub fn from_header(header: &BlockHeader) -> Self {
        Self {
            hash: header.hash,
            parent_hash: header.parent_hash,
            number: header.number,
            timestamp: header.timestamp,
            sequencer_address: header.sequencer_address,
            state_commitment: header.state_commitment,
            transaction_commitment: header.transaction_commitment,
            transaction_count: header
                .transaction_count
                .try_into()
                .expect("ptr size is 64bits"),
            event_commitment: header.event_commitment,
            event_count: header.event_count.try_into().expect("ptr size is 64bits"),
            starknet_version: header.starknet_version.to_string(),
            state_diff_length: header.state_diff_length,
            eth_l1_gas_price: header.eth_l1_gas_price,
            strk_l1_gas_price: header.strk_l1_gas_price,
            eth_l1_data_gas_price: header.eth_l1_data_gas_price,
            strk_l1_data_gas_price: header.strk_l1_data_gas_price,
            receipt_commitment: header.receipt_commitment,
            l1_da_mode: header.l1_da_mode,
            state_diff_commitment: header.state_diff_commitment,
        }
    }

}

pub fn compute_final_hash(header: &BlockHeaderData) -> Result<Felt> {
    // Concatenate the transaction count, event count, state diff length, and L1
    // data availability mode into a single felt.
    let mut concat_counts = [0u8; 32];
    let mut writer = concat_counts.as_mut_slice();
    writer
        .write_all(&header.transaction_count.to_be_bytes())
        .unwrap();
    writer.write_all(&header.event_count.to_be_bytes()).unwrap();
    writer
        .write_all(&header.state_diff_length.to_be_bytes())
        .unwrap();
    writer
        .write_all(&[match header.l1_da_mode {
            L1DataAvailabilityMode::Calldata => 0,
            L1DataAvailabilityMode::Blob => 0b10000000,
        }])
        .unwrap();
    let concat_counts = Felt::from_bytes_be(&concat_counts);
    // Hash the block header.
    let mut hasher = PoseidonHasher::new();
    hasher.update(Felt::from_bytes_be_slice(b"STARKNET_BLOCK_HASH0").into());
    hasher.update(header.number.into());
    hasher.update(header.state_commitment.into());
    hasher.update(header.sequencer_address.into());
    hasher.update(header.timestamp.into());
    hasher.update(concat_counts);
    hasher.update(header.state_diff_commitment.into());
    hasher.update(header.transaction_commitment.into());
    hasher.update(header.event_commitment.into());
    hasher.update(header.receipt_commitment.into());
    hasher.update(header.eth_l1_gas_price.into());
    hasher.update(header.strk_l1_gas_price.into());
    hasher.update(header.eth_l1_data_gas_price.into());
    hasher.update(header.strk_l1_data_gas_price.into());
    hasher.update(Felt::from_bytes_be_slice(header.starknet_version.as_bytes()).into());
    hasher.update(Felt::ZERO);
    hasher.update(header.parent_hash.into());
    Ok(hasher.finalize().into())
}

/// Calculate transaction commitment hash value.
///
/// The transaction commitment is the root of the Patricia Merkle tree with
/// height 64 constructed by adding the (transaction_index,
/// transaction_hash_with_signature) key-value pairs to the tree and computing
/// the root hash.
pub fn calculate_transaction_commitment(transactions: &[TxnWithHash<Felt>]) -> Result<Felt> {
    use rayon::prelude::*;

    let final_hashes = transactions
        .par_iter()
        .map(|tx| calculate_transaction_hash_with_signature(tx))
        .collect();

    calculate_commitment_root::<PoseidonHash>(final_hashes)
}

pub fn calculate_receipt_commitment(receipts: &[ThinReceipt]) -> Result<Felt> {
    use rayon::prelude::*;

    let hashes = receipts
        .par_iter()
        .map(|receipt| {
            poseidon_hash_many(&[
                receipt.transaction_hash.into(),
                receipt.actual_fee.into(),
                // Calculate hash of messages sent.
                {
                    let mut hasher = PoseidonHasher::new();
                    hasher.update((receipt.l2_to_l1_messages.len() as u64).into());
                    for msg in &receipt.l2_to_l1_messages {
                        hasher.update(msg.from_address.into());
                        hasher.update(msg.to_address.into());
                        hasher.update((msg.payload.len() as u64).into());
                        for payload in &msg.payload {
                            hasher.update(*payload);
                        }
                    }
                    hasher.finalize()
                },
                // Revert reason.
                match &receipt.revert_reason {
                    None => Felt::ZERO,
                    Some(reason) => {
                        let mut keccak = sha3::Keccak256::default();
                        keccak.update(reason.as_bytes());
                        let mut hashed_bytes: [u8; 32] = keccak.finalize().into();
                        hashed_bytes[0] &= 0b00000011_u8; // Discard the six MSBs.
                        Felt::from_bytes_be(&hashed_bytes)
                    }
                },
                // Execution resources:
                // L2 gas
                Felt::ZERO,
                // L1 gas consumed
                receipt.l1_gas.into(),
                // L1 data gas consumed
                receipt.l1_data_gas.into(),
            ])
            .into()
        })
        .collect();

    calculate_commitment_root::<PoseidonHash>(hashes)
}

fn calculate_commitment_root<H: FeltHash>(hashes: Vec<Felt>) -> Result<Felt> {
    let mut tree: TransactionOrEventTree<H> = Default::default();

    hashes
        .into_iter()
        .enumerate()
        .try_for_each(|(idx, final_hash)| {
            let idx: u64 = idx
                .try_into()
                .expect("too many transactions while calculating commitment");
            tree.set(idx, final_hash)
        })
        .context("Building transaction commitment tree")?;

    tree.commit()
}



/// Compute the combined hash of the transaction hash and the signature.
///
/// [Reference code from StarkWare](https://github.com/starkware-libs/starknet-api/blob/5565e5282f5fead364a41e49c173940fd83dee00/src/block_hash/block_hash_calculator.rs#L95-L98).
fn calculate_transaction_hash_with_signature(tx: &TxnWithHash<Felt>) -> Felt {
    let signature = match &tx.transaction {
        // Matching for Invoke transactions with different versions
        Txn::Invoke(invoke_txn) => match invoke_txn {
            InvokeTxn::V0(tx) => tx.signature.as_slice(),
            InvokeTxn::V1(tx) => tx.signature.as_slice(),
            InvokeTxn::V3(tx) => tx.signature.as_slice(),
        },
        Txn::Declare(declare_txn) => match declare_txn {
            DeclareTxn::V0(tx) => tx.signature.as_slice(),
            DeclareTxn::V1(tx) => tx.signature.as_slice(),
            DeclareTxn::V2(tx) => tx.signature.as_slice(),
            DeclareTxn::V3(tx) => tx.signature.as_slice(),
        },
        Txn::DeployAccount(deploy_acc) => match deploy_acc {
            DeployAccountTxn::V1(tx) => tx.signature.as_slice(),
            DeployAccountTxn::V3(tx) => tx.signature.as_slice(),
        },
        Txn::Deploy(_) | Txn::L1Handler(_) => &[Felt::ZERO],
    };

    let mut hasher = PoseidonHasher::new();
    hasher.update(tx.transaction_hash.into());
    for elem in signature {
        hasher.update(*elem);
    }
    hasher.finalize().into()
}



/// Calculate event commitment hash value.
///
/// The event commitment is the root of the Patricia Merkle tree with height 64
/// constructed by adding the (event_index, event_hash) key-value pairs to the
/// tree and computing the root hash.
pub fn calculate_event_commitment(transaction_events: &Vec<(Felt, Vec<Event>)>) -> Result<Felt> {
    use rayon::prelude::*;

    let event_hashes = transaction_events
        .par_iter()
        .flat_map(|(tx_hash, events)| events.par_iter().map(|e| (*tx_hash, e)))
        .map(|(tx_hash, e)| calculate_event_hash(e, tx_hash))
        .collect();

    calculate_commitment_root::<PoseidonHash>(event_hashes)
}


/// Calculate the hash of an event.
/// [Reference code from StarkWare](https://github.com/starkware-libs/starknet-api/blob/5565e5282f5fead364a41e49c173940fd83dee00/src/block_hash/event_commitment.rs#L33).
fn calculate_event_hash(event: &Event, transaction_hash: Felt) -> Felt {
    let mut hasher = PoseidonHasher::new();
    hasher.update(event.from_address.into());
    hasher.update(transaction_hash.into());
    hasher.update((event.keys.len() as u64).into());
    for key in &event.keys {
        hasher.update(*key);
    }
    hasher.update((event.data.len() as u64).into());
    for data in &event.data {
        hasher.update(*data);
    }
    hasher.finalize().into()
}
