use std::collections::HashMap;

use anyhow::Context;
use bitvec::prelude::Msb0;
use bitvec::vec::BitVec;
use starknet_types_core::felt::Felt;

/// The result of committing a Merkle tree.
#[derive(Default, Debug)]
pub struct TrieUpdate {
    /// New nodes added. Note that these may contain false positives if the
    /// mutations resulted in removing and then re-adding the same nodes within
    /// the tree.
    ///
    /// The last node is the root of the trie.
    pub nodes_added: Vec<(Felt, Node)>,
    /// Nodes committed to storage that have been removed.
    pub nodes_removed: Vec<u64>,
    /// New root commitment of the trie.
    pub root_commitment: Felt,
}

/// The result of inserting a `TrieUpdate`.
#[derive(Debug, PartialEq)]
pub enum RootIndexUpdate {
    Unchanged,
    Updated(u64),
    TrieEmpty,
}

#[derive(Clone, Debug)]
pub enum Node {
    Binary {
        left: NodeRef,
        right: NodeRef,
    },
    Edge {
        child: NodeRef,
        path: BitVec<u8, Msb0>,
    },
    LeafBinary,
    LeafEdge {
        path: BitVec<u8, Msb0>,
    },
}

#[derive(Copy, Clone, Debug)]
pub enum NodeRef {
    // A reference to a node that has already been committed to storage.
    StorageIndex(u64),
    // A reference to a node that has not yet been committed to storage.
    // The index within the `nodes_added` vector is used as a reference.
    Index(usize),
}

#[derive(Clone, Debug, PartialEq)]
pub enum StoredNode {
    Binary { left: u64, right: u64 },
    Edge { child: u64, path: BitVec<u8, Msb0> },
    LeafBinary,
    LeafEdge { path: BitVec<u8, Msb0> },
}

#[derive(Clone, Debug, bincode::Encode, bincode::BorrowDecode)]
enum StoredSerde {
    Binary { left: u64, right: u64 },
    Edge { child: u64, path: Vec<u8> },
    LeafBinary,
    LeafEdge { path: Vec<u8> },
}

impl StoredNode {
    const CODEC_CFG: bincode::config::Configuration = bincode::config::standard();

    /// Writes the [StoredNode] into `buffer` and returns the number of bytes
    /// written.
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, bincode::error::EncodeError> {
        let helper = match self {
            Self::Binary { left, right } => StoredSerde::Binary {
                left: *left,
                right: *right,
            },
            Self::Edge { child, path } => {
                let path_length = path.len() as u8;

                let mut path = path.to_owned();
                path.force_align();
                let mut path = path.into_vec();
                path.push(path_length);

                StoredSerde::Edge {
                    child: *child,
                    path,
                }
            }
            Self::LeafBinary => StoredSerde::LeafBinary,
            Self::LeafEdge { path } => {
                let path_length = path.len() as u8;

                let mut path = path.to_owned();
                path.force_align();
                let mut path = path.into_vec();
                path.push(path_length);

                StoredSerde::LeafEdge { path }
            }
        };
        // Do not use serialize() as this will invoke serialization twice.
        // https://github.com/bincode-org/bincode/issues/401
        bincode::encode_into_slice(helper, buffer, Self::CODEC_CFG)
    }

    fn decode(data: &[u8]) -> Result<Self, bincode::error::DecodeError> {
        let helper = bincode::borrow_decode_from_slice(data, Self::CODEC_CFG)?;

        let node = match helper.0 {
            StoredSerde::Binary { left, right } => Self::Binary { left, right },
            StoredSerde::Edge { child, mut path } => {
                let path_length = path.pop().ok_or(bincode::error::DecodeError::Other(
                    "Edge node's path length is missing",
                ))?;
                let mut path = bitvec::vec::BitVec::from_vec(path);
                path.resize(path_length as usize, false);
                Self::Edge { child, path }
            }
            StoredSerde::LeafBinary => Self::LeafBinary,
            StoredSerde::LeafEdge { mut path } => {
                let path_length = path.pop().ok_or(bincode::error::DecodeError::Other(
                    "Edge node's path length is missing",
                ))?;
                let mut path = bitvec::vec::BitVec::from_vec(path);
                path.resize(path_length as usize, false);
                Self::LeafEdge { path }
            }
        };

        Ok(node)
    }
}

impl Node {
    fn as_stored(&self, storage_indices: &HashMap<usize, u64>) -> anyhow::Result<StoredNode> {
        let node = match self {
            Node::Binary { left, right } => {
                let left = match left {
                    NodeRef::StorageIndex(id) => *id,
                    NodeRef::Index(idx) => *storage_indices
                        .get(idx)
                        .context("Left child index missing")?,
                };

                let right = match right {
                    NodeRef::StorageIndex(id) => *id,
                    NodeRef::Index(idx) => *storage_indices
                        .get(idx)
                        .context("Right child index missing")?,
                };

                StoredNode::Binary { left, right }
            }
            Node::Edge { child, path } => {
                let child = match child {
                    NodeRef::StorageIndex(id) => id,
                    NodeRef::Index(idx) => {
                        storage_indices.get(idx).context("Child index missing")?
                    }
                };

                StoredNode::Edge {
                    child: *child,
                    path: path.clone(),
                }
            }
            Node::LeafEdge { path } => StoredNode::LeafEdge { path: path.clone() },
            Node::LeafBinary => StoredNode::LeafBinary,
        };

        Ok(node)
    }
}
