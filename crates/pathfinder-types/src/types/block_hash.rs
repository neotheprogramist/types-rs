use std::io::Write;
// use std::sync::LazyLock;

use super::chain::HashChain;
use super::header::{BlockHeader, L1DataAvailabilityMode, StarknetVersion};
use super::transaction_common::{Transaction, TransactionVariant};
use crate::types::event::Event;
use crate::types::hash::{FeltHash, PedersenHash, PoseidonHash};
use crate::types::receipt::{ExecutionResources, ExecutionStatus, L1Gas, Receipt};
use crate::types::transaction_common::{DeclareTransactionV2, InvokeTransactionV3};
use anyhow::{Context, Result};
use starknet_types_core::hash::{poseidon_hash_many, PoseidonHasher};
// use pathfinder_common::{
//     felt_bytes,
//     BlockHash,
//     BlockHeader,
//     BlockNumber,
//     BlockTimestamp,
//     Chain,
//     ChainId,
//     EventCommitment,
//     GasPrice,
//     L1DataAvailabilityMode,
//     ReceiptCommitment,
//     SequencerAddress,
//     StarknetVersion,
//     StateCommitment,
//     StateDiffCommitment,
//     TransactionCommitment,
//     TransactionHash,
//     TransactionSignatureElem,
// };
// use crate::types::hash::{pedersen_hash, poseidon_hash_many, HashChain, PoseidonHasher};

use super::transaction::TransactionOrEventTree;
use sha3::Digest;
use starknet_types_core::felt::Felt;
// use starknet_gateway_types::reply::Block;

const V_0_11_1: StarknetVersion = StarknetVersion::new(0, 11, 1, 0);
const V_0_13_2: StarknetVersion = StarknetVersion::new(0, 13, 2, 0);

// #[derive(Debug, PartialEq, Eq)]
// pub enum VerifyResult {
//     Match((TransactionCommitment, EventCommitment, ReceiptCommitment)),
//     Mismatch,
// }

// impl VerifyResult {
//     pub fn is_match(&self) -> bool {
//         matches!(self, Self::Match(_))
//     }
// }

/// Verify the block hash value.
///
/// The method to compute the block hash is documented
/// [here](https://docs.starknet.io/docs/Blocks/header/#block-hash).
///
/// Unfortunately that'a not-fully-correct description, since the transaction
/// commitment Merkle tree is not constructed directly with the transaction
/// hashes, but with a hash computed from the transaction hash and the signature
/// values (for invoke transactions).
///
/// See the `compute_block_hash.py` helper script that uses the cairo-lang
/// Python implementation to compute the block hash for details.
// pub fn verify_gateway_block_commitments_and_hash(
//     block: &Block,
//     state_diff_commitment: StateDiffCommitment,
//     state_diff_length: u64,
//     chain: Chain,
//     chain_id: ChainId,
// ) -> Result<VerifyResult> {
//     let mut bhd =
//         BlockHeaderData::from_gateway_block(block, state_diff_commitment, state_diff_length)?;

//     let computed_transaction_commitment =
//         calculate_transaction_commitment(&block.transactions, block.starknet_version)?;

//     // Older blocks on mainnet don't carry a precalculated transaction commitment.
//     if block.transaction_commitment == TransactionCommitment::ZERO {
//         // Update with the computed transaction commitment, verification is not
//         // possible.
//         bhd.transaction_commitment = computed_transaction_commitment;
//     } else if computed_transaction_commitment != bhd.transaction_commitment {
//         tracing::debug!(%computed_transaction_commitment, actual_transaction_commitment=%bhd.transaction_commitment, "Transaction commitment mismatch");
//         return Ok(VerifyResult::Mismatch);
//     }

//     let computed_receipt_commitment = calculate_receipt_commitment(
//         block
//             .transaction_receipts
//             .iter()
//             .map(|(r, _)| r.clone())
//             .collect::<Vec<_>>()
//             .as_slice(),
//     )?;

//     // Older blocks on mainnet don't carry a precalculated receipt commitment.
//     if let Some(receipt_commitment) = block.receipt_commitment {
//         if computed_receipt_commitment != receipt_commitment {
//             tracing::debug!(%computed_receipt_commitment, actual_receipt_commitment=%receipt_commitment, "Receipt commitment mismatch");
//             return Ok(VerifyResult::Mismatch);
//         }
//     } else {
//         // Update with the computed transaction commitment, verification is not
//         // possible.
//         bhd.receipt_commitment = computed_receipt_commitment;
//     }

//     let event_commitment = calculate_event_commitment(
//         &block
//             .transaction_receipts
//             .iter()
//             .map(|(receipt, events)| (receipt.transaction_hash, events.as_slice()))
//             .collect::<Vec<_>>(),
//         block.starknet_version,
//     )?;

//     // Older blocks on mainnet don't carry a precalculated event
//     // commitment.
//     if block.event_commitment == EventCommitment::ZERO {
//         // Update with the computed transaction commitment, verification is not
//         // possible.
//         bhd.event_commitment = event_commitment;
//     } else if event_commitment != block.event_commitment {
//         tracing::debug!(computed_event_commitment=%event_commitment, actual_event_commitment=%block.event_commitment, "Event commitment mismatch");
//         return Ok(VerifyResult::Mismatch);
//     }

//     verify_block_hash(bhd, chain, chain_id)
// }

#[derive(Clone, Debug, Default)]
pub struct BlockHeaderData {
    pub hash: Felt,
    pub parent_hash: Felt,
    pub number: u64,
    pub timestamp: u64,
    pub sequencer_address: Felt,
    pub state_commitment: Felt,
    pub state_diff_commitment: Felt,
    pub transaction_commitment: Felt,
    pub transaction_count: u64,
    pub event_commitment: Felt,
    pub event_count: u64,
    pub state_diff_length: u64,
    pub starknet_version: StarknetVersion,
    pub starknet_version_str: String,
    pub eth_l1_gas_price: u128,
    pub strk_l1_gas_price: u128,
    pub eth_l1_data_gas_price: u128,
    pub strk_l1_data_gas_price: u128,
    pub receipt_commitment: Felt,
    pub l1_da_mode: L1DataAvailabilityMode,
}

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
            starknet_version: header.starknet_version,
            starknet_version_str: header.starknet_version.to_string(),
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

    // pub fn from_gateway_block(
    //     block: &Block,
    //     state_diff_commitment: Felt,
    //     state_diff_length: u64,
    // ) -> Result<Self> {
    //     Ok(Self {
    //         hash: block.block_hash,
    //         parent_hash: block.parent_block_hash,
    //         number: block.block_number,
    //         timestamp: block.timestamp,
    //         sequencer_address: block
    //             .sequencer_address
    //             .unwrap_or(SequencerAddress(Felt::ZERO)),
    //         state_commitment: block.state_commitment,
    //         transaction_commitment: block.transaction_commitment,
    //         transaction_count: block
    //             .transactions
    //             .len()
    //             .try_into()
    //             .expect("ptr size is 64bits"),
    //         event_commitment: block.event_commitment,
    //         event_count: block
    //             .transaction_receipts
    //             .iter()
    //             .flat_map(|(_, events)| events)
    //             .count()
    //             .try_into()
    //             .expect("ptr size is 64bits"),
    //         starknet_version: block.starknet_version,
    //         starknet_version_str: block.starknet_version.to_string(),
    //         state_diff_commitment,
    //         state_diff_length,
    //         eth_l1_gas_price: block.l1_gas_price.price_in_wei,
    //         strk_l1_gas_price: block.l1_gas_price.price_in_fri,
    //         eth_l1_data_gas_price: block.l1_data_gas_price.price_in_wei,
    //         strk_l1_data_gas_price: block.l1_data_gas_price.price_in_fri,
    //         receipt_commitment: block.receipt_commitment.unwrap_or_default(),
    //         l1_da_mode: block.l1_da_mode.into(),
    //     })
    // }
}

// pub fn verify_block_hash(
//     header: BlockHeaderData,
//     chain: Chain,
//     chain_id: ChainId,
// ) -> Result<VerifyResult> {
//     let meta_info = meta::for_chain(chain);

//     let verified = if meta_info.uses_pre_0_7_hash_algorithm(header.number) {
//         anyhow::ensure!(
//             chain != Chain::Custom,
//             "Chain::Custom should not have any pre 0.7 block hashes"
//         );

//         let computed_hash = compute_final_hash_pre_0_7(&header, chain_id);
//         computed_hash == header.hash
//     } else if header.starknet_version < V_0_13_2 {
//         let computed_hash = compute_final_hash_pre_0_13_2(&header);
//         if computed_hash == header.hash {
//             true
//         } else if let Some(fallback_sequencer_address) = meta_info.fallback_sequencer_address {
//             // Try with the fallback sequencer address.
//             let computed_hash = compute_final_hash_pre_0_13_2(&BlockHeaderData {
//                 sequencer_address: fallback_sequencer_address,
//                 ..header
//             });
//             computed_hash == header.hash
//         } else {
//             false
//         }
//     } else {
//         let computed_hash = compute_final_hash(&header)?;
//         computed_hash == header.hash
//     };

//     Ok(match verified {
//         false => VerifyResult::Mismatch,
//         true => VerifyResult::Match((
//             header.transaction_commitment,
//             header.event_commitment,
//             header.receipt_commitment,
//         )),
//     })
// }

// mod meta {
//     use pathfinder_common::{sequencer_address, BlockNumber, Chain, SequencerAddress};

//     /// Metadata about Starknet chains we use for block hash calculation
//     ///
//     /// Since the method for calculating block hashes has changed during the
//     /// operation of the Starknet alpha network, we need this information
//     /// to be able to decide which method to use for block hash calculation.
//     ///
//     /// * Before the Starknet 0.7 release block hashes were calculated with a
//     ///   slightly different algorithm (the Starknet chain ID was hashed into
//     ///   the final value). Zero was used both instead of the block timestamp
//     ///   and the sequencer value.
//     /// * After Starknet 0.7 and before Starknet 0.8 the block hash does not
//     ///   include the chain id anymore. The proper block timestamp is used but
//     ///   zero is used as the sequencer address.
//     /// * After Starknet 0.8 and before Starknet 0.8.2 the sequencer address is
//     ///   non-zero and is used for the block hash calculation. However, the
//     ///   blocks don't include the sequencer address that was used for the
//     ///   calculation and for the majority of the blocks the block hash value is
//     ///   irrecoverable.
//     /// * After Starknet 0.8.2 all blocks include the correct sequencer address
//     ///   value.
//     #[derive(Clone)]
//     pub struct BlockHashMetaInfo {
//         /// The number of the first block that was hashed with the Starknet 0.7
//         /// hash algorithm.
//         pub first_0_7_block: BlockNumber,
//         /// Fallback sequencer address to use for blocks that don't include the
//         /// address.
//         pub fallback_sequencer_address: Option<SequencerAddress>,
//     }

//     impl BlockHashMetaInfo {
//         pub fn uses_pre_0_7_hash_algorithm(&self, block_number: BlockNumber) -> bool {
//             block_number < self.first_0_7_block
//         }
//     }

//     const MAINNET_METAINFO: BlockHashMetaInfo = BlockHashMetaInfo {
//         first_0_7_block: BlockNumber::new_or_panic(833),
//         fallback_sequencer_address: Some(sequencer_address!(
//             "021f4b90b0377c82bf330b7b5295820769e72d79d8acd0effa0ebde6e9988bc5"
//         )),
//     };

//     const SEPOLIA_TESTNET_METAINFO: BlockHashMetaInfo = BlockHashMetaInfo {
//         first_0_7_block: BlockNumber::new_or_panic(0),
//         fallback_sequencer_address: None,
//     };

//     const SEPOLIA_INTEGRATION_METAINFO: BlockHashMetaInfo = BlockHashMetaInfo {
//         first_0_7_block: BlockNumber::new_or_panic(0),
//         fallback_sequencer_address: None,
//     };

//     const CUSTOM_METAINFO: BlockHashMetaInfo = BlockHashMetaInfo {
//         first_0_7_block: BlockNumber::new_or_panic(0),
//         fallback_sequencer_address: None,
//     };

//     pub fn for_chain(chain: Chain) -> &'static BlockHashMetaInfo {
//         match chain {
//             Chain::Mainnet => &MAINNET_METAINFO,
//             Chain::SepoliaTestnet => &SEPOLIA_TESTNET_METAINFO,
//             Chain::SepoliaIntegration => &SEPOLIA_INTEGRATION_METAINFO,
//             Chain::Custom => &CUSTOM_METAINFO,
//         }
//     }
// }

// /// Computes the final block hash for pre-0.7 blocks.
// ///
// /// This deviates from later algorithms by hashing a chain-specific
// /// ID into the final hash.
// ///
// /// Note that for these blocks we're using zero for:
// ///   * timestamps
// ///   * sequencer addresses
// ///   * event number and event commitment
// fn compute_final_hash_pre_0_7(header: &BlockHeaderData, chain_id: ChainId) -> BlockHash {
//     let mut chain = HashChain::default();

//     // block number
//     chain.update(Felt::from(header.number.get()));
//     // global state root
//     chain.update(header.state_commitment.0);
//     // sequencer address: these versions used 0 as the sequencer address
//     chain.update(Felt::ZERO);
//     // block timestamp: these versions used 0 as a timestamp for block hash
//     // computation
//     chain.update(Felt::ZERO);
//     // number of transactions
//     chain.update(Felt::from(header.transaction_count));
//     // transaction commitment
//     chain.update(header.transaction_commitment.0);
//     // number of events
//     chain.update(Felt::ZERO);
//     // event commitment
//     chain.update(Felt::ZERO);
//     // reserved: protocol version
//     chain.update(Felt::ZERO);
//     // reserved: extra data
//     chain.update(Felt::ZERO);
//     // EXTRA FIELD: chain id
//     chain.update(chain_id.0);
//     // parent block hash
//     chain.update(header.parent_hash.0);

//     BlockHash(chain.finalize())
// }

// /// This implements the final hashing step for post-0.7, pre-0.13.2 blocks.
// fn compute_final_hash_pre_0_13_2(header: &BlockHeaderData) -> BlockHash {
//     let mut chain = HashChain::default();

//     // block number
//     chain.update(Felt::from(header.number.get()));
//     // global state root
//     chain.update(header.state_commitment.0);
//     // sequencer address
//     chain.update(header.sequencer_address.0);
//     // block timestamp
//     chain.update(Felt::from(header.timestamp.get()));
//     // number of transactions
//     chain.update(Felt::from(header.transaction_count));
//     // transaction commitment
//     chain.update(header.transaction_commitment.0);
//     // number of events
//     chain.update(Felt::from(header.event_count));
//     // event commitment
//     chain.update(header.event_commitment.0);
//     // reserved: protocol version
//     chain.update(Felt::ZERO);
//     // reserved: extra data
//     chain.update(Felt::ZERO);
//     // parent block hash
//     chain.update(header.parent_hash.0);

//     BlockHash(chain.finalize())
// }

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
    hasher.update(Felt::from_bytes_be_slice(header.starknet_version_str.as_bytes()).into());
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
pub fn calculate_transaction_commitment(
    transactions: &[Transaction],
    version: StarknetVersion,
) -> Result<Felt> {
    use rayon::prelude::*;

    let final_hashes = transactions
        .par_iter()
        .map(|tx| calculate_transaction_hash_with_signature(tx))
        .collect();

    calculate_commitment_root::<PoseidonHash>(final_hashes)
}

pub fn calculate_receipt_commitment(receipts: &[Receipt]) -> Result<Felt> {
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
                match &receipt.execution_status {
                    ExecutionStatus::Succeeded => Felt::ZERO,
                    ExecutionStatus::Reverted { reason } => {
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
                receipt.execution_resources.total_gas_consumed.l1_gas.into(),
                // L1 data gas consumed
                receipt
                    .execution_resources
                    .total_gas_consumed
                    .l1_data_gas
                    .into(),
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
/// Since the transaction hash doesn't take the signature values as its input
/// computing the transaction commitent uses a hash value that combines
/// the transaction hash with the array of signature values.
///
/// Note that for non-invoke transactions we don't actually have signatures. The
/// cairo-lang uses an empty list (whose hash is not the ZERO value!) in that
/// case.
// fn calculate_transaction_hash_with_signature_pre_0_11_1(tx: &Transaction) -> Felt {
//     static HASH_OF_EMPTY_LIST: LazyLock<Felt> = LazyLock::new(|| HashChain::default().finalize());

//     let signature_hash = match &tx.variant {
//         TransactionVariant::InvokeV0(tx) => calculate_signature_hash(&tx.signature),
//         TransactionVariant::InvokeV1(tx) => calculate_signature_hash(&tx.signature),
//         TransactionVariant::InvokeV3(tx) => calculate_signature_hash(&tx.signature),
//         TransactionVariant::DeclareV0(_)
//         | TransactionVariant::DeclareV1(_)
//         | TransactionVariant::DeclareV2(_)
//         | TransactionVariant::DeclareV3(_)
//         | TransactionVariant::DeployV0(_)
//         | TransactionVariant::DeployV1(_)
//         | TransactionVariant::DeployAccountV1(_)
//         | TransactionVariant::DeployAccountV3(_)
//         | TransactionVariant::L1Handler(_) => *HASH_OF_EMPTY_LIST,
//     };

//     pedersen_hash(tx.hash.0, signature_hash)
// }

/// Compute the combined hash of the transaction hash and the signature for
/// block before v0.13.2.
///
/// Since the transaction hash doesn't take the signature values as its input
/// computing the transaction commitment uses a hash value that combines
/// the transaction hash with the array of signature values.
///
/// Note that for non-invoke transactions we don't actually have signatures. The
/// cairo-lang uses an empty list (whose hash is not the ZERO value!) in that
/// case.
// fn calculate_transaction_hash_with_signature_pre_0_13_2(tx: &Transaction) -> Felt {
//     static HASH_OF_EMPTY_LIST: LazyLock<Felt> = LazyLock::new(|| HashChain::default().finalize());

//     let signature_hash = match &tx.variant {
//         TransactionVariant::InvokeV0(tx) => calculate_signature_hash(&tx.signature),
//         TransactionVariant::DeclareV0(tx) => calculate_signature_hash(&tx.signature),
//         TransactionVariant::DeclareV1(tx) => calculate_signature_hash(&tx.signature),
//         TransactionVariant::DeclareV2(tx) => calculate_signature_hash(&tx.signature),
//         TransactionVariant::DeclareV3(tx) => calculate_signature_hash(&tx.signature),
//         TransactionVariant::DeployAccountV1(tx) => calculate_signature_hash(&tx.signature),
//         TransactionVariant::DeployAccountV3(tx) => calculate_signature_hash(&tx.signature),
//         TransactionVariant::InvokeV1(tx) => calculate_signature_hash(&tx.signature),
//         TransactionVariant::InvokeV3(tx) => calculate_signature_hash(&tx.signature),
//         TransactionVariant::DeployV0(_)
//         | TransactionVariant::DeployV1(_)
//         | TransactionVariant::L1Handler(_) => *HASH_OF_EMPTY_LIST,
//     };

//     pedersen_hash(tx.hash.0, signature_hash)
// }

/// Compute the combined hash of the transaction hash and the signature.
///
/// [Reference code from StarkWare](https://github.com/starkware-libs/starknet-api/blob/5565e5282f5fead364a41e49c173940fd83dee00/src/block_hash/block_hash_calculator.rs#L95-L98).
fn calculate_transaction_hash_with_signature(tx: &Transaction) -> Felt {
    let signature = match &tx.variant {
        TransactionVariant::InvokeV0(tx) => tx.signature.as_slice(),
        TransactionVariant::DeclareV0(tx) => tx.signature.as_slice(),
        TransactionVariant::DeclareV1(tx) => tx.signature.as_slice(),
        TransactionVariant::DeclareV2(tx) => tx.signature.as_slice(),
        TransactionVariant::DeclareV3(tx) => tx.signature.as_slice(),
        TransactionVariant::DeployAccountV1(tx) => tx.signature.as_slice(),
        TransactionVariant::DeployAccountV3(tx) => tx.signature.as_slice(),
        TransactionVariant::InvokeV1(tx) => tx.signature.as_slice(),
        TransactionVariant::InvokeV3(tx) => tx.signature.as_slice(),
        // TransactionVariant::DeployV0(_)
        // | TransactionVariant::DeployV1(_)
        // | TransactionVariant::L1Handler(_) => &[Felt::ZERO],
    };

    let mut hasher = PoseidonHasher::new();
    hasher.update(tx.hash.into());
    for elem in signature {
        hasher.update(*elem);
    }
    hasher.finalize().into()
}

fn calculate_signature_hash(signature: &[Felt]) -> Felt {
    let mut hash = HashChain::default();
    for s in signature {
        hash.update(*s);
    }
    hash.finalize()
}

/// Calculate event commitment hash value.
///
/// The event commitment is the root of the Patricia Merkle tree with height 64
/// constructed by adding the (event_index, event_hash) key-value pairs to the
/// tree and computing the root hash.
pub fn calculate_event_commitment(
    transaction_events: &[(Felt, &[Event])],
    version: StarknetVersion,
) -> Result<Felt> {
    use rayon::prelude::*;

    let event_hashes = transaction_events
        .par_iter()
        .flat_map(|(tx_hash, events)| events.par_iter().map(|e| (*tx_hash, e)))
        .map(|(tx_hash, e)| calculate_event_hash(e, tx_hash))
        .collect();

    calculate_commitment_root::<PoseidonHash>(event_hashes)
}

/// Calculate the hash of a pre-v0.13.2 Starknet event.
///
/// See the [documentation](https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/starknet-events/#event_hash)
/// for details.
// fn calculate_event_hash_pre_0_13_2(event: &Event) -> Felt {
//     let mut keys_hash = HashChain::default();
//     for key in event.keys.iter() {
//         keys_hash.update(key);
//     }
//     let keys_hash = keys_hash.finalize();

//     let mut data_hash = HashChain::default();
//     for data in event.data.iter() {
//         data_hash.update(data);
//     }
//     let data_hash = data_hash.finalize();

//     let mut event_hash = HashChain::default();
//     event_hash.update(*event.from_address.get());
//     event_hash.update(keys_hash);
//     event_hash.update(data_hash);

//     event_hash.finalize()
// }

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

// #[cfg(test)]
// mod tests {
//     use assert_matches::assert_matches;
//     use pathfinder_common::macro_prelude::*;
//     use pathfinder_common::receipt::{ExecutionResources, L1Gas, L2ToL1Message};
//     use pathfinder_common::transaction::{
//         EntryPointType,
//         InvokeTransactionV0,
//         InvokeTransactionV3,
//     };
//     use pathfinder_common::{
//         felt,
//         ContractAddress,
//         EventData,
//         EventKey,
//         Fee,
//         L2ToL1MessagePayloadElem,
//         TransactionHash,
//     };
//     use pathfinder_crypto::Felt;
//     use starknet_gateway_test_fixtures::v0_13_2;
//     use starknet_gateway_types::reply::StateUpdate;

//     use super::*;

//     #[test]
//     fn test_event_hash() {
//         let event = Event {
//             from_address: contract_address!("0xdeadbeef"),
//             data: vec![
//                 event_data!("0x5"),
//                 event_data!("0x6"),
//                 event_data!("0x7"),
//                 event_data!("0x8"),
//                 event_data!("0x9"),
//             ],
//             keys: vec![
//                 event_key!("0x1"),
//                 event_key!("0x2"),
//                 event_key!("0x3"),
//                 event_key!("0x4"),
//             ],
//         };

//         // produced by the cairo-lang Python implementation:
//         // `hex(calculate_event_hash(0xdeadbeef, [1, 2, 3, 4], [5, 6, 7, 8, 9]))`
//         let expected_event_hash =
//             felt!("0xdb96455b3a61f9139f7921667188d31d1e1d49fb60a1aa3dbf3756dbe3a9b4");
//         let calculated_event_hash = calculate_event_hash_pre_0_13_2(&event);
//         assert_eq!(expected_event_hash, calculated_event_hash);
//     }

//     #[test]
//     fn test_final_transaction_hash() {
//         let transaction = Transaction {
//             hash: transaction_hash!("0x1"),
//             variant: TransactionVariant::InvokeV0(InvokeTransactionV0 {
//                 sender_address: contract_address!("0xdeadbeef"),
//                 entry_point_type: Some(EntryPointType::External),
//                 entry_point_selector: entry_point!("0xe"),
//                 signature: vec![
//                     transaction_signature_elem!("0x2"),
//                     transaction_signature_elem!("0x3"),
//                 ],
//                 ..Default::default()
//             }),
//         };

//         // produced by the cairo-lang Python implementation:
//         // `hex(calculate_single_tx_hash_with_signature(1, [2, 3],
//         // hash_function=pedersen_hash))`
//         let expected_final_hash =
//             Felt::from_hex_str("0x259c3bd5a1951eafb2f41e0b783eab92cfe4e108b2b1f071e3736f06b909431")
//                 .unwrap();
//         let calculated_final_hash =
//             calculate_transaction_hash_with_signature_pre_0_13_2(&transaction);
//         assert_eq!(expected_final_hash, calculated_final_hash);
//     }

//     #[test]
//     fn test_block_hash_without_sequencer_address() {
//         // This tests with a post-0.7, pre-0.8.0 block where zero is used as the
//         // sequencer address.
//         let json = starknet_gateway_test_fixtures::v0_7_0::block::MAINNET_2240;
//         let block: Block = serde_json::from_str(json).unwrap();

//         assert_matches!(
//             verify_gateway_block_commitments_and_hash(
//                 &block,
//                 Default::default(),
//                 0,
//                 Chain::Mainnet,
//                 ChainId::MAINNET
//             )
//             .unwrap(),
//             VerifyResult::Match(_)
//         );
//     }

//     #[test]
//     fn test_block_hash_with_sequencer_address() {
//         // This tests with a post-0.8.2 block where we have correct sequencer address
//         // information in the block itself.
//         let json = starknet_gateway_test_fixtures::v0_9_0::block::MAINNET_2800;
//         let block: Block = serde_json::from_str(json).unwrap();

//         assert_matches!(
//             verify_gateway_block_commitments_and_hash(
//                 &block,
//                 Default::default(),
//                 0,
//                 Chain::Mainnet,
//                 ChainId::MAINNET
//             )
//             .unwrap(),
//             VerifyResult::Match(_)
//         );
//     }

//     #[test]
//     fn test_block_hash_with_sequencer_address_unavailable_but_not_zero() {
//         // This tests with a post-0.8.0 pre-0.8.2 block where we don't have the
//         // sequencer address in the JSON but the block hash was calculated with
//         // the magic value below instead of zero.
//         let json = starknet_gateway_test_fixtures::v0_8_0::block::MAINNET_2500;
//         let block: Block = serde_json::from_str(json).unwrap();

//         assert_matches!(
//             verify_gateway_block_commitments_and_hash(
//                 &block,
//                 Default::default(),
//                 0,
//                 Chain::Mainnet,
//                 ChainId::MAINNET
//             )
//             .unwrap(),
//             VerifyResult::Match(_)
//         );
//     }

//     #[test]
//     fn test_block_hash_0_11_1() {
//         let json = starknet_gateway_test_fixtures::v0_11_1::block::MAINNET_65000;
//         let block: Block = serde_json::from_str(json).unwrap();

//         assert_matches!(
//             verify_gateway_block_commitments_and_hash(
//                 &block,
//                 Default::default(),
//                 0,
//                 Chain::Mainnet,
//                 ChainId::MAINNET
//             )
//             .unwrap(),
//             VerifyResult::Match(_)
//         );
//     }

//     #[test]
//     fn test_block_hash_0() {
//         // This tests with a pre-0.7 block where the chain ID was hashed into
//         // the block hash.
//         let json = starknet_gateway_test_fixtures::pre_0_7_0::block::MAINNET_GENESIS;
//         let block: Block = serde_json::from_str(json).unwrap();

//         assert_matches!(
//             verify_gateway_block_commitments_and_hash(
//                 &block,
//                 Default::default(),
//                 0,
//                 Chain::Mainnet,
//                 ChainId::MAINNET
//             )
//             .unwrap(),
//             VerifyResult::Match(_)
//         );
//     }

//     /// Source:
//     /// https://github.com/starkware-libs/starknet-api/blob/5565e5282f5fead364a41e49c173940fd83dee00/src/block_hash/transaction_commitment_test.rs#L12-L29.
//     #[test]
//     fn test_transaction_hash_with_signature_0_13_2() {
//         let transaction = Transaction {
//             hash: TransactionHash(Felt::ONE),
//             variant: TransactionVariant::InvokeV3(InvokeTransactionV3 {
//                 signature: vec![
//                     TransactionSignatureElem(Felt::from_u64(2)),
//                     TransactionSignatureElem(Felt::from_u64(3)),
//                 ],
//                 ..Default::default()
//             }),
//         };
//         let expected = felt!("0x2f0d8840bcf3bc629598d8a6cc80cb7c0d9e52d93dab244bbf9cd0dca0ad082");
//         assert_eq!(
//             calculate_transaction_hash_with_signature(&transaction),
//             expected
//         );

//         let transaction = Transaction {
//             hash: TransactionHash(Felt::ONE),
//             variant: TransactionVariant::L1Handler(Default::default()),
//         };
//         let expected = felt!("0x00a93bf5e58b9378d093aa86ddc2f61a3295a1d1e665bd0ef3384dd07b30e033");
//         assert_eq!(
//             calculate_transaction_hash_with_signature(&transaction),
//             expected
//         );
//     }

//     /// Source:
//     /// https://github.com/starkware-libs/starknet-api/blob/5565e5282f5fead364a41e49c173940fd83dee00/src/block_hash/transaction_commitment_test.rs#L32.
#[test]
fn test_transaction_commitment_0_13_2() {
    let transaction_1 = Transaction {
        hash: (Felt::from_hex_unchecked(
            "0x5ac644bbd6ae98d3be2d988439854e33f0961e24f349a63b43e16d172bfe747",
        )),
        variant: TransactionVariant::DeclareV2(DeclareTransactionV2 {
            signature: vec![
                Felt::from_hex_unchecked(
                    "0x43ad3c7c77f7b7762db41ee9d33958813ee25efed77bc7199e08f4f40b1a59",
                ),
                Felt::from_hex_unchecked(
                    "0xfedb8715405faf28de29a07a3f3f06f078bac3fcb67ac7f5ae392e15a75921",
                ),
            ],
            class_hash: Felt::from_hex_unchecked(
                "0x2fd9e122406490dc0f299f3070eaaa8df854d97ff81b47e91da32b8cd9d757a",
            ),
            max_fee: Felt::from_hex_unchecked("0x4f6ac5195e92e4"),
            nonce: Felt::from_hex_unchecked("0xd"),
            sender_address: Felt::from_hex_unchecked(
                "0x472aa8128e01eb0df145810c9511a92852d62a68ba8198ce5fa414e6337a365",
            ),
            compiled_class_hash: Felt::from_hex_unchecked(
                "0x55d1e0ee31f8f937fc75b37045129fbe0e01747baacb44b89d2d3d2c649117e",
            ),
        }),
    };
    let transaction_2 = Transaction {
        hash: (Felt::from_hex_unchecked(
            "0x21bc0afe54123b946855e1bf9389d943313df5c5c396fbf0630234a44f6f592",
        )),
        variant: TransactionVariant::DeclareV2(DeclareTransactionV2 {
            signature: vec![
                Felt::from_hex_unchecked(
                    "0x12a928f7042a66c5419fc5182da6879c357f013335d8b61d0ad774009afbb40",
                ),
                Felt::from_hex_unchecked(
                    "0x63479f4343dc2f068bff99fbbf0027250a672999fb5675cee1f2d1a64d33844",
                ),
            ],
            class_hash: Felt::from_hex_unchecked(
                "0x19de7881922dbc95846b1bb9464dba34046c46470cfb5e18b4cb2892fd4111f",
            ),
            max_fee: Felt::from_hex_unchecked("0xe6e9346a5ae75a"),
            nonce: Felt::from_hex_unchecked("0xe"),
            sender_address: Felt::from_hex_unchecked(
                "0x472aa8128e01eb0df145810c9511a92852d62a68ba8198ce5fa414e6337a365",
            ),
            compiled_class_hash: Felt::from_hex_unchecked(
                "0x6506976af042088c9ea49e6cc9c9a12838ee6920bb989dce02f5c6467667367",
            ),
        }),
    };
    let expected = Felt::from_hex_unchecked(
        "0x54f43cf29b80cc83aef36f3195b73cb165ad12553eae147b4cce62adbf0b180",
    );
    assert_eq!(
        calculate_transaction_commitment(&[transaction_1, transaction_2], V_0_13_2).unwrap(),
        expected
    );
}

//     /// Source:
//     /// https://github.com/starkware-libs/starknet-api/blob/5565e5282f5fead364a41e49c173940fd83dee00/src/block_hash/event_commitment_test.rs#L10.
#[test]
fn test_event_commitment_0_13_2() {
    let tx_hash_1 = Felt::from_hex_unchecked("0x5ac644bbd6ae98d3be2d988439854e33f0961e24f349a63b43e16d172bfe747");
    let event_1 = Event {
        from_address: Felt::from_hex_unchecked(
            "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
        ),
        keys: vec![Felt::from_hex_unchecked(
            "0x99cd8bde557814842a3121e8ddfd433a539b8c9f14bf31ebf108d12e6196e9",
        )],
        data: vec![
            Felt::from_hex_unchecked(
                "0x472aa8128e01eb0df145810c9511a92852d62a68ba8198ce5fa414e6337a365",
            ),
            Felt::from_hex_unchecked(
                "0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8",
            ),
            Felt::from_hex_unchecked(
                "0xd07af45c84550",
            ),
            Felt::from_hex_unchecked(
                "0x0",
            ),
        ],
    };
    let tx_hash_2 = Felt::from_hex_unchecked("0x21bc0afe54123b946855e1bf9389d943313df5c5c396fbf0630234a44f6f592");

    let event_2 = Event {
        from_address: Felt::from_hex_unchecked(
            "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
        ),
        keys: vec![Felt::from_hex_unchecked(
            "0x99cd8bde557814842a3121e8ddfd433a539b8c9f14bf31ebf108d12e6196e9",
        )],
        data: vec![
            Felt::from_hex_unchecked(
                "0x472aa8128e01eb0df145810c9511a92852d62a68ba8198ce5fa414e6337a365",
            ),
            Felt::from_hex_unchecked(
                "0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8",
            ),
            Felt::from_hex_unchecked(
                "0x471426f16c4330",
            ),
            Felt::from_hex_unchecked(
                "0x0",
            ),
        ],
    };
    let events: &[(Felt, &[Event])] = &[(tx_hash_1, &[event_1]), (tx_hash_2, &[event_2])];
    let expected = Felt::from_hex_unchecked("0x12dfbe9dbbaba9c34b5a4c0ba622dcd8e2bb0264481c77f073008b59825a758");
    println!("{:?}", calculate_event_commitment(events, V_0_13_2).unwrap());
    assert_eq!(
        calculate_event_commitment(events, V_0_13_2).unwrap(), expected
    );
}

//     // Source:
//     // https://github.com/starkware-libs/starknet-api/blob/5565e5282f5fead364a41e49c173940fd83dee00/src/block_hash/receipt_commitment_test.rs#L16.
#[test]
fn test_receipt_commitment_0_13_2() {
    let receipt_1 = Receipt {
        transaction_hash: Felt::from_hex_unchecked("0x5ac644bbd6ae98d3be2d988439854e33f0961e24f349a63b43e16d172bfe747"),
        actual_fee: Felt::from_hex_unchecked("0xd07af45c84550"),
        l2_to_l1_messages: vec![],
        execution_resources: ExecutionResources {
            data_availability: L1Gas {
                l1_gas: 0,
                l1_data_gas: 192,
            },
            total_gas_consumed: L1Gas {
                l1_gas: 117620,
                l1_data_gas: 192,
            },
            ..Default::default()
        },
        execution_status: ExecutionStatus::Succeeded,
        transaction_index: 0,
    };

    let receipt_2 = Receipt {
        transaction_hash: Felt::from_hex_unchecked("0x21bc0afe54123b946855e1bf9389d943313df5c5c396fbf0630234a44f6f592"),
        actual_fee: Felt::from_hex_unchecked("0x471426f16c4330"),
        l2_to_l1_messages: vec![],
        execution_resources: ExecutionResources {
            data_availability: L1Gas {
                l1_gas: 0,
                l1_data_gas: 192,
            },
            total_gas_consumed: L1Gas {
                l1_gas: 641644,
                l1_data_gas: 192,
            },
            ..Default::default()
        },
        execution_status: ExecutionStatus::Succeeded,
        transaction_index: 1,
    };
    let expected_root = Felt::from_hex_unchecked("0x6f12628d21a8df7f158b631d801fc0dd20034b9e22eca255bddc0c1c1bc283f");
    assert_eq!(
        calculate_receipt_commitment(&[receipt_1, receipt_2]).unwrap(),
        expected_root
    );
}

//     // Source:
//     // https://github.com/starkware-libs/starknet-api/blob/5565e5282f5fead364a41e49c173940fd83dee00/src/block_hash/block_hash_calculator_test.rs#L51
//     #[test]
//     fn test_block_hash_0_13_2() {
//         let header = BlockHeaderData {
//             hash: Default::default(),
//             number: BlockNumber::new_or_panic(1),
//             state_commitment: StateCommitment(2u64.into()),
//             sequencer_address: SequencerAddress(3u64.into()),
//             timestamp: BlockTimestamp::new_or_panic(4),
//             l1_da_mode: L1DataAvailabilityMode::Blob,
//             strk_l1_gas_price: GasPrice(6),
//             eth_l1_gas_price: GasPrice(7),
//             strk_l1_data_gas_price: GasPrice(10),
//             eth_l1_data_gas_price: GasPrice(9),
//             starknet_version: V_0_13_2,
//             starknet_version_str: "10".to_string(),
//             parent_hash: BlockHash(11u64.into()),
//             transaction_commitment: TransactionCommitment(felt!(
//                 "0x72f432efa51e2a34f68404ac5e77514301e26eb53ec89badd8173f4e8561b95"
//             )),
//             transaction_count: 1,
//             event_commitment: EventCommitment(Felt::ZERO),
//             event_count: 0,
//             state_diff_commitment: StateDiffCommitment(felt!(
//                 "0x281f5966e49ad7dad9323826d53d1d27c0c4e6ebe5525e2e2fbca549bfa0a67"
//             )),
//             state_diff_length: 10,
//             receipt_commitment: ReceiptCommitment(felt!(
//                 "0x8e7dfb2772c2ac26e712fb97404355d66db0ba9555f0f64f30d61a56df9c76"
//             )),
//         };
//         let expected_hash = BlockHash(felt!(
//             "0x061e4998d51a248f1d0288d7e17f6287757b0e5e6c5e1e58ddf740616e312134"
//         ));
//         assert_eq!(compute_final_hash(&header).unwrap(), expected_hash);
//     }

//     // Source
//     // https://integration-sepolia.starknet.io/feeder_gateway/get_block?blockNumber=35748
//     #[test]
//     fn test_block_hash_0_13_2_first_integration_block() {
//         let block: Block = serde_json::from_str(v0_13_2::block::SEPOLIA_INTEGRATION_35748).unwrap();
//         let expected_hash = block.block_hash;

//         let state_update: StateUpdate =
//             serde_json::from_str(v0_13_2::state_update::SEPOLIA_INTEGRATION_35748).unwrap();
//         let state_update: pathfinder_common::StateUpdate = state_update.into();
//         let state_diff_length = state_update.state_diff_length();
//         let state_diff_commitment =
//             state_update.compute_state_diff_commitment(StarknetVersion::new(0, 13, 2, 0));

//         assert_eq!(state_diff_length, block.state_diff_length.unwrap());
//         assert_eq!(state_diff_commitment, block.state_diff_commitment.unwrap());

//         let receipts: Vec<_> = block
//             .transaction_receipts
//             .iter()
//             .map(|(receipt, _)| receipt.clone())
//             .collect();
//         assert_eq!(
//             calculate_receipt_commitment(&receipts).unwrap(),
//             block.receipt_commitment.unwrap()
//         );

//         let block_header_data = BlockHeaderData::from_gateway_block(
//             &block,
//             block.state_diff_commitment.unwrap(),
//             block.state_diff_length.unwrap(),
//         )
//         .unwrap();

//         assert_eq!(
//             compute_final_hash(&block_header_data).unwrap(),
//             expected_hash
//         );
//     }
// }
