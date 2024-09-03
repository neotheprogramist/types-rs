use std::str::FromStr;
use std::fmt::Display;

use fake::Dummy;
use anyhow;
use starknet_types_core::felt::Felt;


#[derive(Debug, Clone, PartialEq, Eq, Default, Dummy)]
pub struct BlockHeader {
    pub hash: Felt,
    pub parent_hash: Felt,
    pub number: u64,
    pub timestamp: u64,
    pub eth_l1_gas_price: u128,
    pub strk_l1_gas_price: u128,
    pub eth_l1_data_gas_price: u128,
    pub strk_l1_data_gas_price: u128,
    pub sequencer_address: Felt,
    pub starknet_version: StarknetVersion,
    pub class_commitment: Felt,
    pub event_commitment: Felt,
    pub state_commitment: Felt,
    pub storage_commitment: Felt,
    pub transaction_commitment: Felt,
    pub transaction_count: usize,
    pub event_count: usize,
    pub l1_da_mode: L1DataAvailabilityMode,
    pub receipt_commitment: Felt,
    pub state_diff_commitment: Felt,
    pub state_diff_length: u64,
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Default, Dummy, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "UPPERCASE")]
pub enum L1DataAvailabilityMode {
    #[default]
    Calldata,
    Blob,
}

// #[derive(Debug, Clone, PartialEq, Default, Dummy)]
// pub struct SignedBlockHeader {
//     pub header: BlockHeader,
//     pub signature: BlockCommitmentSignature,
// }

// pub struct BlockHeaderBuilder(BlockHeader);

// impl BlockHeader {
//     /// Creates a [builder](BlockHeaderBuilder) with all fields initialized to
//     /// default values.
//     pub fn builder() -> BlockHeaderBuilder {
//         BlockHeaderBuilder(BlockHeader::default())
//     }

//     /// Creates a [builder](BlockHeaderBuilder) with an incremented block number
//     /// and parent hash set to this block's hash.
//     pub fn child_builder(&self) -> BlockHeaderBuilder {
//         BlockHeaderBuilder(BlockHeader::default())
//             .with_number(self.number + 1)
//             .with_parent_hash(self.hash)
//     }

//     /// Creates a [StateUpdate] with the block hash and state commitment fields
//     /// initialized to match this header.
//     pub fn init_state_update(&self) -> StateUpdate {
//         StateUpdate::default()
//             .with_block_hash(self.hash)
//             .with_state_commitment(self.state_commitment)
//     }
// }

// impl BlockHeaderBuilder {
//     pub fn with_number(mut self, number: BlockNumber) -> Self {
//         self.0.number = number;
//         self
//     }

//     pub fn with_parent_hash(mut self, parent_hash: BlockHash) -> Self {
//         self.0.parent_hash = parent_hash;
//         self
//     }

//     pub fn with_state_commitment(mut self, state_commmitment: StateCommitment) -> Self {
//         self.0.state_commitment = state_commmitment;
//         self
//     }

//     /// Sets the [StateCommitment] by calculating its value from the current
//     /// [StorageCommitment] and [ClassCommitment].
//     pub fn with_calculated_state_commitment(mut self) -> Self {
//         self.0.state_commitment =
//             StateCommitment::calculate(self.0.storage_commitment, self.0.class_commitment);
//         self
//     }

//     pub fn with_timestamp(mut self, timestamp: BlockTimestamp) -> Self {
//         self.0.timestamp = timestamp;
//         self
//     }

//     pub fn with_eth_l1_gas_price(mut self, eth_l1_gas_price: GasPrice) -> Self {
//         self.0.eth_l1_gas_price = eth_l1_gas_price;
//         self
//     }

//     pub fn with_strk_l1_gas_price(mut self, strk_l1_gas_price: GasPrice) -> Self {
//         self.0.strk_l1_gas_price = strk_l1_gas_price;
//         self
//     }

//     pub fn with_eth_l1_data_gas_price(mut self, eth_l1_data_gas_price: GasPrice) -> Self {
//         self.0.eth_l1_data_gas_price = eth_l1_data_gas_price;
//         self
//     }

//     pub fn with_strk_l1_data_gas_price(mut self, strk_l1_data_gas_price: GasPrice) -> Self {
//         self.0.strk_l1_data_gas_price = strk_l1_data_gas_price;
//         self
//     }

//     pub fn with_sequencer_address(mut self, sequencer_address: SequencerAddress) -> Self {
//         self.0.sequencer_address = sequencer_address;
//         self
//     }

//     pub fn with_transaction_commitment(
//         mut self,
//         transaction_commitment: TransactionCommitment,
//     ) -> Self {
//         self.0.transaction_commitment = transaction_commitment;
//         self
//     }

//     pub fn with_event_commitment(mut self, event_commitment: EventCommitment) -> Self {
//         self.0.event_commitment = event_commitment;
//         self
//     }

//     pub fn with_storage_commitment(mut self, storage_commitment: StorageCommitment) -> Self {
//         self.0.storage_commitment = storage_commitment;
//         self
//     }

//     pub fn with_class_commitment(mut self, class_commitment: ClassCommitment) -> Self {
//         self.0.class_commitment = class_commitment;
//         self
//     }

//     pub fn with_starknet_version(mut self, starknet_version: StarknetVersion) -> Self {
//         self.0.starknet_version = starknet_version;
//         self
//     }

//     pub fn with_transaction_count(mut self, transaction_count: usize) -> Self {
//         self.0.transaction_count = transaction_count;
//         self
//     }

//     pub fn with_event_count(mut self, event_count: usize) -> Self {
//         self.0.event_count = event_count;
//         self
//     }

//     pub fn with_l1_da_mode(mut self, l1_da_mode: L1DataAvailabilityMode) -> Self {
//         self.0.l1_da_mode = l1_da_mode;
//         self
//     }

//     pub fn with_receipt_commitment(mut self, receipt_commitment: ReceiptCommitment) -> Self {
//         self.0.receipt_commitment = receipt_commitment;
//         self
//     }

//     pub fn finalize_with_hash(mut self, hash: BlockHash) -> BlockHeader {
//         self.0.hash = hash;
//         self.0
//     }
// }


#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Dummy)]
pub struct StarknetVersion(u8, u8, u8, u8);

impl StarknetVersion {
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        StarknetVersion(a, b, c, d)
    }

    pub fn as_u32(&self) -> u32 {
        u32::from_le_bytes([self.0, self.1, self.2, self.3])
    }

    pub fn from_u32(version: u32) -> Self {
        let [a, b, c, d] = version.to_le_bytes();
        StarknetVersion(a, b, c, d)
    }
}

impl FromStr for StarknetVersion {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Ok(StarknetVersion::new(0, 0, 0, 0));
        }

        let parts: Vec<_> = s.split('.').collect();
        anyhow::ensure!(
            parts.len() == 3 || parts.len() == 4,
            "Invalid version string, expected 3 or 4 parts but got {}",
            parts.len()
        );

        let a = parts[0].parse()?;
        let b = parts[1].parse()?;
        let c = parts[2].parse()?;
        let d = parts.get(3).map(|x| x.parse()).transpose()?.unwrap_or(0);

        Ok(StarknetVersion(a, b, c, d))
    }
}

impl Display for StarknetVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 == 0 && self.1 == 0 && self.2 == 0 && self.3 == 0 {
            return Ok(());
        }
        if self.3 == 0 {
            write!(f, "{}.{}.{}", self.0, self.1, self.2)
        } else {
            write!(f, "{}.{}.{}.{}", self.0, self.1, self.2, self.3)
        }
    }
}