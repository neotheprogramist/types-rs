//! Starknet utilises a custom Binary Merkle-Patricia Tree to store and organise
//! its state.
//!
//! From an external perspective the tree is similar to a key-value store, where
//! both key and value are [Felts](Felt). The difference is that each tree is
//! immutable, and any mutations result in a new tree with a new root. This
//! mutated variant can then be accessed via the new root, and the old variant
//! via the old root.
//!
//! Trees share common nodes to be efficient. These nodes perform reference
//! counting and will get deleted once all references are gone. State can
//! therefore be tracked over time by mutating the current state, and storing
//! the new root. Old states can be dropped by deleting old roots which are no
//! longer required.
//!
//! #### Tree definition
//!
//! It is important to understand that since all keys are [Felts](Felt), this
//! means all paths to a key are equally long - 251 bits.
//!
//! Starknet defines three node types for a tree.
//!
//! `Leaf nodes` which represent an actual value stored.
//!
//! `Edge nodes` which connect two nodes, and __must be__ a maximal subtree
//! (i.e. be as long as possible). This latter condition is important as it
//! strictly defines a tree (i.e. all trees with the same leaves must have the
//! same nodes). The path of an edge node can therefore be many bits long.
//!
//! `Binary nodes` is a branch node with two children, left and right. This
//! represents only a single bit on the path to a leaf.
//!
//! A tree storing a single key-value would consist of two nodes. The root node
//! would be an edge node with a path equal to the key. This edge node is
//! connected to a leaf node storing the value.
//!
//! #### Implementation details
//!
//! We've defined an additional node type, an `Unresolved node`. This is used to
//! represent a node who's hash is known, but has not yet been retrieved from
//! storage (and we therefore have no further details about it).
//!
//! Our implementation is a mix of nodes from persistent storage and any
//! mutations are kept in-memory. It is done this way to allow many mutations to
//! a tree before committing only the final result to storage. This
//! may be confusing since we just said trees are immutable -- but since we are
//! only changing the in-memory tree, the immutable tree still exists in
//! storage. One can therefore think of the in-memory tree as containing
//! the state changes between tree `N` and `N + 1`.
//!
//! The in-memory tree is built using a graph of `Rc<RefCell<Node>>` which is a
//! bit painful.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::ControlFlow;
use std::rc::Rc;

use super::hash::FeltHash;
use super::trie::{Node, NodeRef, StoredNode, TrieUpdate};
use super::trie_node::TrieNode;
use anyhow::Context;
use bitvec::prelude::{BitSlice, BitVec, Msb0};
use starknet_types_core::felt::Felt;

use super::merkle_node::{BinaryNode, Direction, EdgeNode, InternalNode};
use super::storage::Storage;

/// A Starknet binary Merkle-Patricia tree.
#[derive(Debug, Clone)]
pub struct MerkleTree<H: FeltHash, const HEIGHT: usize> {
    root: Option<Rc<RefCell<InternalNode>>>,
    leaves: HashMap<BitVec<u8, Msb0>, Felt>,
    nodes_removed: Vec<u64>,
    _hasher: std::marker::PhantomData<H>,
    /// If enables, node hashes are verified as they are resolved. This allows
    /// testing for database corruption.
    verify_hashes: bool,
}

impl<H: FeltHash, const HEIGHT: usize> MerkleTree<H, HEIGHT> {
    pub fn new(root: u64) -> Self {
        let root = Some(Rc::new(RefCell::new(InternalNode::Unresolved(root))));
        Self {
            root,
            _hasher: std::marker::PhantomData,
            verify_hashes: false,
            leaves: Default::default(),
            nodes_removed: Default::default(),
        }
    }

    pub fn with_verify_hashes(mut self, verify_hashes: bool) -> Self {
        self.verify_hashes = verify_hashes;
        self
    }

    pub fn empty() -> Self {
        Self {
            root: None,
            _hasher: std::marker::PhantomData,
            verify_hashes: false,
            leaves: Default::default(),
            nodes_removed: Default::default(),
        }
    }

    /// Commits all tree mutations and returns the [changes](TrieUpdate) to the
    /// tree.
    pub fn commit(self, storage: &impl Storage) -> anyhow::Result<TrieUpdate> {
        // Go through tree, collect mutated nodes and calculate their hashes.
        let mut added = Vec::new();
        let mut removed = Vec::new();

        let root_hash = if let Some(root) = self.root.as_ref() {
            match &mut *root.borrow_mut() {
                // If the root node is unresolved that means that there have been no changes made
                // to the tree.
                InternalNode::Unresolved(idx) => storage
                    .hash(*idx)
                    .context("Fetching root node's hash")?
                    .context("Root node's hash is missing")?,
                other => {
                    let (root_hash, _) = self.commit_subtree(
                        other,
                        &mut added,
                        &mut removed,
                        storage,
                        BitVec::new(),
                    )?;
                    root_hash
                }
            }
        } else {
            // An empty trie has a root of zero
            Felt::ZERO
        };

        removed.extend(self.nodes_removed);

        Ok(TrieUpdate {
            nodes_added: added,
            nodes_removed: removed,
            root_commitment: root_hash,
        })
    }

    /// Persists any changes in this subtree to storage.
    ///
    /// This necessitates recursively calculating the hash of, and
    /// in turn persisting, any changed child nodes. This is necessary
    /// as the parent node's hash relies on its childrens hashes.
    ///
    /// In effect, the entire subtree gets persisted.
    fn commit_subtree(
        &self,
        node: &mut InternalNode,
        added: &mut Vec<(Felt, Node)>,
        removed: &mut Vec<u64>,
        storage: &impl Storage,
        mut path: BitVec<u8, Msb0>,
    ) -> anyhow::Result<(Felt, Option<NodeRef>)> {
        let result = match node {
            InternalNode::Unresolved(idx) => {
                // Unresolved nodes are already committed, but we need their hash for subsequent
                // iterations.
                let hash = storage
                    .hash(*idx)
                    .context("Fetching stored node's hash")?
                    .context("Stored node's hash is missing")?;
                (hash, Some(NodeRef::StorageIndex(*idx)))
            }
            InternalNode::Leaf => {
                let hash = if let Some(value) = self.leaves.get(&path) {
                    *value
                } else {
                    storage
                        .leaf(&path)
                        .context("Fetching leaf value from storage")?
                        .context("Leaf value missing from storage")?
                };
                (hash, None)
            }
            InternalNode::Binary(binary) => {
                let mut left_path = path.clone();
                left_path.push(Direction::Left.into());
                let (left_hash, left_child) = self.commit_subtree(
                    &mut binary.left.borrow_mut(),
                    added,
                    removed,
                    storage,
                    left_path,
                )?;
                let mut right_path = path.clone();
                right_path.push(Direction::Right.into());
                let (right_hash, right_child) = self.commit_subtree(
                    &mut binary.right.borrow_mut(),
                    added,
                    removed,
                    storage,
                    right_path,
                )?;
                let hash = BinaryNode::calculate_hash::<H>(left_hash, right_hash);

                let persisted_node = match (left_child, right_child) {
                    (None, None) => Node::LeafBinary,
                    (Some(_), None) | (None, Some(_)) => {
                        anyhow::bail!(
                            "Inconsistent binary children. Both children must be leaves or not \
                             leaves."
                        )
                    }
                    (Some(left), Some(right)) => Node::Binary { left, right },
                };

                if let Some(storage_index) = binary.storage_index {
                    removed.push(storage_index);
                };

                let node_index = added.len();
                added.push((hash, persisted_node));

                (hash, Some(NodeRef::Index(node_index)))
            }
            InternalNode::Edge(edge) => {
                path.extend_from_bitslice(&edge.path);
                let (child_hash, child) = self.commit_subtree(
                    &mut edge.child.borrow_mut(),
                    added,
                    removed,
                    storage,
                    path,
                )?;

                let hash = EdgeNode::calculate_hash::<H>(child_hash, &edge.path);

                let persisted_node = match child {
                    None => Node::LeafEdge {
                        path: edge.path.clone(),
                    },
                    Some(child) => Node::Edge {
                        child,
                        path: edge.path.clone(),
                    },
                };

                let node_index = added.len();
                added.push((hash, persisted_node));
                if let Some(storage_index) = edge.storage_index {
                    removed.push(storage_index);
                };

                (hash, Some(NodeRef::Index(node_index)))
            }
        };

        Ok(result)
    }

    /// Sets the value of a key. To delete a key, set the value to [Felt::ZERO].
    pub fn set(
        &mut self,
        storage: &impl Storage,
        key: BitVec<u8, Msb0>,
        value: Felt,
    ) -> anyhow::Result<()> {
        if value == Felt::ZERO {
            return self.delete_leaf(storage, &key);
        }

        // Changing or inserting a new leaf into the tree will change the hashes
        // of all nodes along the path to the leaf.
        let path = self.traverse(storage, &key)?;

        // There are three possibilities.
        //
        // 1. The leaf exists, in which case we simply change its value.
        //
        // 2. The tree is empty, we insert the new leaf and the root becomes an edge
        //    node connecting to it.
        //
        // 3. The leaf does not exist, and the tree is not empty. The final node in the
        //    traversal will be an edge node who's path diverges from our new leaf
        //    node's.
        //
        //    This edge must be split into a new subtree containing both the existing
        // edge's child and the    new leaf. This requires an edge followed by a
        // binary node and then further edges to both the    current child and
        // the new leaf. Any of these new edges may also end with an empty path in
        //    which case they should be elided. It depends on the common path length of
        // the current edge    and the new leaf i.e. the split may be at the
        // first bit (in which case there is no leading    edge), or the split
        // may be in the middle (requires both leading and post edges), or the
        //    split may be the final bit (no post edge).
        use InternalNode::*;
        match path.last() {
            Some(node) => {
                let updated = match &*node.borrow() {
                    Edge(edge) => {
                        let common = edge.common_path(&key);

                        // Height of the binary node
                        let branch_height = edge.height + common.len();
                        // Height of the binary node's children
                        let child_height = branch_height + 1;

                        // Path from binary node to new leaf
                        let new_path = key[child_height..].to_bitvec();
                        // Path from binary node to existing child
                        let old_path = edge.path[common.len() + 1..].to_bitvec();

                        // The new leaf branch of the binary node.
                        // (this may be edge -> leaf, or just leaf depending).
                        let new = match new_path.is_empty() {
                            true => Rc::new(RefCell::new(InternalNode::Leaf)),
                            false => {
                                let new_edge = InternalNode::Edge(EdgeNode {
                                    storage_index: None,
                                    height: child_height,
                                    path: new_path,
                                    child: Rc::new(RefCell::new(InternalNode::Leaf)),
                                });
                                Rc::new(RefCell::new(new_edge))
                            }
                        };

                        // The existing child branch of the binary node.
                        let old = match old_path.is_empty() {
                            true => edge.child.clone(),
                            false => {
                                let old_edge = InternalNode::Edge(EdgeNode {
                                    storage_index: None,
                                    height: child_height,
                                    path: old_path,
                                    child: edge.child.clone(),
                                });
                                Rc::new(RefCell::new(old_edge))
                            }
                        };

                        let new_direction = Direction::from(key[branch_height]);
                        let (left, right) = match new_direction {
                            Direction::Left => (new, old),
                            Direction::Right => (old, new),
                        };

                        let branch = InternalNode::Binary(BinaryNode {
                            storage_index: None,
                            height: branch_height,
                            left,
                            right,
                        });

                        // We may require an edge leading to the binary node.
                        match common.is_empty() {
                            true => branch,
                            false => InternalNode::Edge(EdgeNode {
                                storage_index: None,
                                height: edge.height,
                                path: common.to_bitvec(),
                                child: Rc::new(RefCell::new(branch)),
                            }),
                        }
                    }
                    // Leaf exists already.
                    Leaf => InternalNode::Leaf,
                    Unresolved(_) | Binary(_) => {
                        unreachable!("The end of a traversion cannot be unresolved or binary")
                    }
                };

                let old_node = node.replace(updated);
                if let Some(index) = old_node.storage_index() {
                    self.nodes_removed.push(index);
                };
            }
            None => {
                // Getting no travel nodes implies that the tree is empty.
                //
                // Create a new leaf node with the value, and the root becomes
                // an edge node connecting to the leaf.
                let edge = InternalNode::Edge(EdgeNode {
                    storage_index: None,
                    height: 0,
                    path: key.to_bitvec(),
                    child: Rc::new(RefCell::new(InternalNode::Leaf)),
                });

                self.root = Some(Rc::new(RefCell::new(edge)));
            }
        }

        self.leaves.insert(key, value);

        Ok(())
    }

    /// Deletes a leaf node from the tree.
    ///
    /// This is not an external facing API; the functionality is instead
    /// accessed by calling [`MerkleTree::set`] with value set to
    /// [`Felt::ZERO`].
    fn delete_leaf(
        &mut self,
        storage: &impl Storage,
        key: &BitSlice<u8, Msb0>,
    ) -> anyhow::Result<()> {
        // Algorithm explanation:
        //
        // The leaf's parent node is either an edge, or a binary node.
        // If it's an edge node, then it must also be deleted. And its parent
        // must be a binary node. In either case we end up with a binary node
        // who's one child is deleted. This changes the binary to an edge node.
        //
        // Note that its possible that there is no binary node -- if the resulting tree
        // would be empty.
        //
        // This new edge node may need to merge with the old binary node's parent node
        // and other remaining child node -- if they're also edges.
        //
        // Then we are done.
        let path = self.traverse(storage, key)?;

        // Do nothing if the leaf does not exist.
        match path.last() {
            Some(node) => match &*node.borrow() {
                InternalNode::Leaf => {}
                _ => return Ok(()),
            },
            None => return Ok(()),
        }

        // Go backwards until we hit a branch node.
        let mut indexes_removed = Vec::new();
        let mut node_iter = path.into_iter().rev().skip_while(|node| {
            let node = node.borrow();
            match *node {
                InternalNode::Binary(_) => false,
                _ => {
                    if let Some(index) = node.storage_index() {
                        indexes_removed.push(index);
                    };
                    true
                }
            }
        });

        match node_iter.next() {
            Some(node) => {
                let new_edge = {
                    // This node must be a binary node due to the iteration condition.
                    let binary = node.borrow().as_binary().cloned().unwrap();
                    // Create an edge node to replace the old binary node
                    // i.e. with the remaining child (note the direction invert),
                    //      and a path of just a single bit.
                    let direction = binary.direction(key).invert();
                    let child = binary.get_child(direction);
                    let path = std::iter::once(bool::from(direction)).collect::<BitVec<_, _>>();
                    let mut edge = EdgeNode {
                        storage_index: None,
                        height: binary.height,
                        path,
                        child,
                    };

                    // Merge the remaining child if it's an edge.
                    self.merge_edges(storage, &mut edge)?;

                    edge
                };
                // Replace the old binary node with the new edge node.
                let old_node = node.replace(InternalNode::Edge(new_edge));
                if let Some(index) = old_node.storage_index() {
                    self.nodes_removed.push(index);
                };
            }
            None => {
                // We reached the root without a hitting binary node. The new tree
                // must therefore be empty.
                self.root = None;
                self.nodes_removed.extend(indexes_removed);
                return Ok(());
            }
        };

        // Check the parent of the new edge. If it is also an edge, then they must
        // merge.
        if let Some(node) = node_iter.next() {
            if let InternalNode::Edge(edge) = &mut *node.borrow_mut() {
                self.merge_edges(storage, edge)?;
            }
        }

        // All nodes below the binary node were deleted
        self.nodes_removed.extend(indexes_removed);

        Ok(())
    }

    /// Returns the value stored at key, or `None` if it does not exist.
    pub fn get(
        &self,
        storage: &impl Storage,
        key: BitVec<u8, Msb0>,
    ) -> anyhow::Result<Option<Felt>> {
        let node = self.traverse(storage, &key)?;
        let node = node.last();

        let Some(node) = node else {
            return Ok(None);
        };

        if *node.borrow() == InternalNode::Leaf {
            if let Some(value) = self.leaves.get(&key) {
                Ok(Some(*value))
            } else {
                storage.leaf(&key)
            }
        } else {
            Ok(None)
        }
    }

    /// Generates a merkle-proof for a given `key`.
    ///
    /// Returns vector of [`TrieNode`] which form a chain from the root to the
    /// key, if it exists, or down to the node which proves that the key
    /// does not exist.
    ///
    /// The nodes are returned in order, root first.
    ///
    /// Verification is performed by confirming that:
    ///   1. the chain follows the path of `key`, and
    ///   2. the hashes are correct, and
    ///   3. the root hash matches the known root
    pub fn get_proof(
        root: u64,
        storage: &impl Storage,
        key: &BitSlice<u8, Msb0>,
    ) -> anyhow::Result<Option<Vec<TrieNode>>> {
        // Manually traverse towards the key.
        let mut nodes = Vec::new();

        let mut next = Some(root);
        let mut height = 0;
        while let Some(index) = next.take() {
            let Some(node) = storage.get(index).context("Resolving node")? else {
                return Ok(None);
            };

            let node = match node {
                StoredNode::Binary { left, right } => {
                    // Choose the direction to go in.
                    next = match key.get(height).map(|b| Direction::from(*b)) {
                        Some(Direction::Left) => Some(left),
                        Some(Direction::Right) => Some(right),
                        None => anyhow::bail!("Key path too short for binary node"),
                    };
                    height += 1;

                    let left = storage
                        .hash(left)
                        .context("Querying left child's hash")?
                        .context("Left child's hash is missing")?;

                    let right = storage
                        .hash(right)
                        .context("Querying right child's hash")?
                        .context("Right child's hash is missing")?;

                    TrieNode::Binary { left, right }
                }
                StoredNode::Edge { child, path } => {
                    let key = key
                        .get(height..height + path.len())
                        .context("Key path is too short for edge node")?;
                    height += path.len();

                    // If the path matches then we continue otherwise the proof is complete.
                    if key == path {
                        next = Some(child);
                    }

                    let child = storage
                        .hash(child)
                        .context("Querying child child's hash")?
                        .context("Child's hash is missing")?;

                    TrieNode::Edge { child, path }
                }
                StoredNode::LeafBinary => {
                    // End of the line, get child hashes.
                    let mut path = key[..height].to_bitvec();
                    path.push(Direction::Left.into());
                    let left = storage
                        .leaf(&path)
                        .context("Querying left leaf hash")?
                        .context("Left leaf is missing")?;
                    path.pop();
                    path.push(Direction::Right.into());
                    let right = storage
                        .leaf(&path)
                        .context("Querying right leaf hash")?
                        .context("Right leaf is missing")?;

                    TrieNode::Binary { left, right }
                }
                StoredNode::LeafEdge { path } => {
                    let mut current_path = key[..height].to_bitvec();
                    // End of the line, get hash of the child.
                    current_path.extend_from_bitslice(&path);
                    let child = storage
                        .leaf(&current_path)
                        .context("Querying leaf hash")?
                        .context("Child leaf is missing")?;

                    TrieNode::Edge { child, path }
                }
            };

            nodes.push(node);
        }

        Ok(Some(nodes))
    }

    /// Traverses from the current root towards destination node.
    /// Returns the list of nodes along the path.
    ///
    /// If the destination node exists, it will be the final node in the list.
    ///
    /// This means that the final node will always be either a the destination
    /// [Leaf](InternalNode::Leaf) node, or an [Edge](InternalNode::Edge)
    /// node who's path suffix does not match the leaf's path.
    ///
    /// The final node can __not__ be a [Binary](InternalNode::Binary) node
    /// since it would always be possible to continue on towards the
    /// destination. Nor can it be an [Unresolved](InternalNode::Unresolved)
    /// node since this would be resolved to check if we can travel further.
    fn traverse(
        &self,
        storage: &impl Storage,
        dst: &BitSlice<u8, Msb0>,
    ) -> anyhow::Result<Vec<Rc<RefCell<InternalNode>>>> {
        let Some(mut current) = self.root.clone() else {
            return Ok(Vec::new());
        };

        let mut height = 0;
        let mut nodes = Vec::new();
        loop {
            use InternalNode::*;

            let current_tmp = current.borrow().clone();

            let next = match current_tmp {
                Unresolved(idx) => {
                    let node = self.resolve(storage, idx, height)?;
                    current.replace(node);
                    current
                }
                Binary(binary) => {
                    nodes.push(current.clone());
                    let next = binary.direction(dst);
                    let next = binary.get_child(next);
                    height += 1;
                    next
                }
                Edge(edge) if edge.path_matches(dst) => {
                    nodes.push(current.clone());
                    height += edge.path.len();
                    edge.child.clone()
                }
                Leaf | Edge(_) => {
                    nodes.push(current);
                    return Ok(nodes);
                }
            };

            current = next;
        }
    }

    /// Retrieves the requested node from storage.
    ///
    /// Result will be either a [Binary](InternalNode::Binary),
    /// [Edge](InternalNode::Edge) or [Leaf](InternalNode::Leaf) node.
    fn resolve(
        &self,
        storage: &impl Storage,
        index: u64,
        height: usize,
    ) -> anyhow::Result<InternalNode> {
        anyhow::ensure!(
            height < HEIGHT,
            "Attempted to resolve a node with height {height} which exceeds the tree height \
             {HEIGHT}"
        );

        let node = storage
            .get(index)?
            .with_context(|| format!("Node {index} at height {height} is missing"))?;

        let node = match node {
            StoredNode::Binary { left, right } => InternalNode::Binary(BinaryNode {
                storage_index: Some(index),
                height,
                left: Rc::new(RefCell::new(InternalNode::Unresolved(left))),
                right: Rc::new(RefCell::new(InternalNode::Unresolved(right))),
            }),
            StoredNode::Edge { child, path } => InternalNode::Edge(EdgeNode {
                storage_index: Some(index),
                height,
                path,
                child: Rc::new(RefCell::new(InternalNode::Unresolved(child))),
            }),
            StoredNode::LeafBinary => InternalNode::Binary(BinaryNode {
                storage_index: Some(index),
                height,
                left: Rc::new(RefCell::new(InternalNode::Leaf)),
                right: Rc::new(RefCell::new(InternalNode::Leaf)),
            }),
            StoredNode::LeafEdge { path } => InternalNode::Edge(EdgeNode {
                storage_index: Some(index),
                height,
                path,
                child: Rc::new(RefCell::new(InternalNode::Leaf)),
            }),
        };

        Ok(node)
    }

    /// This is a convenience function which merges the edge node with its child
    /// __iff__ it is also an edge.
    ///
    /// Does nothing if the child is not also an edge node.
    ///
    /// This can occur when mutating the tree (e.g. deleting a child of a binary
    /// node), and is an illegal state (since edge nodes __must be__ maximal
    /// subtrees).
    fn merge_edges(&mut self, storage: &impl Storage, parent: &mut EdgeNode) -> anyhow::Result<()> {
        let resolved_child = match &*parent.child.borrow() {
            InternalNode::Unresolved(hash) => {
                self.resolve(storage, *hash, parent.height + parent.path.len())?
            }
            other => other.clone(),
        };

        if let Some(child_edge) = resolved_child.as_edge().cloned() {
            parent.path.extend_from_bitslice(&child_edge.path);
            if let Some(storage_index) = child_edge.storage_index {
                self.nodes_removed.push(storage_index);
            }
            parent.child = child_edge.child;
        }

        Ok(())
    }

    /// Visits all of the nodes in the tree in pre-order using the given visitor
    /// function.
    ///
    /// For each node, there will first be a visit for
    /// `InternalNode::Unresolved(hash)` followed by visit at the loaded
    /// node when [`Visit::ContinueDeeper`] is returned. At any time the visitor
    /// function can also return `ControlFlow::Break` to stop the visit with the
    /// given return value, which will be returned as `Some(value))` to the
    /// caller.
    ///
    /// The visitor function receives the node being visited, as well as the
    /// full path to that node.
    ///
    /// Upon successful non-breaking visit of the tree, `None` will be returned.
    #[allow(dead_code)]
    pub fn dfs<X, VisitorFn>(
        &self,
        storage: &impl Storage,
        visitor_fn: &mut VisitorFn,
    ) -> anyhow::Result<Option<X>>
    where
        VisitorFn: FnMut(&InternalNode, &BitSlice<u8, Msb0>) -> ControlFlow<X, Visit>,
    {
        use bitvec::prelude::bitvec;

        #[allow(dead_code)]
        struct VisitedNode {
            node: Rc<RefCell<InternalNode>>,
            path: BitVec<u8, Msb0>,
        }

        let Some(root) = self.root.as_ref() else {
            return Ok(None);
        };

        let mut visiting = vec![VisitedNode {
            node: root.clone(),
            path: bitvec![u8, Msb0;],
        }];

        loop {
            match visiting.pop() {
                None => break,
                Some(VisitedNode { node, path }) => {
                    let current_node = &*node.borrow();
                    match visitor_fn(current_node, &path) {
                        ControlFlow::Continue(Visit::ContinueDeeper) => {
                            // the default, no action, just continue deeper
                        }
                        ControlFlow::Continue(Visit::StopSubtree) => {
                            // make sure we don't add any more to `visiting` on this subtree
                            continue;
                        }
                        ControlFlow::Break(x) => {
                            // early exit
                            return Ok(Some(x));
                        }
                    }
                    match current_node {
                        InternalNode::Binary(b) => {
                            visiting.push(VisitedNode {
                                node: b.right.clone(),
                                path: {
                                    let mut path_right = path.clone();
                                    path_right.push(Direction::Right.into());
                                    path_right
                                },
                            });
                            visiting.push(VisitedNode {
                                node: b.left.clone(),
                                path: {
                                    let mut path_left = path.clone();
                                    path_left.push(Direction::Left.into());
                                    path_left
                                },
                            });
                        }
                        InternalNode::Edge(e) => {
                            visiting.push(VisitedNode {
                                node: e.child.clone(),
                                path: {
                                    let mut extended_path = path.clone();
                                    extended_path.extend_from_bitslice(&e.path);
                                    extended_path
                                },
                            });
                        }
                        InternalNode::Leaf => {}
                        InternalNode::Unresolved(idx) => {
                            visiting.push(VisitedNode {
                                node: Rc::new(RefCell::new(self.resolve(
                                    storage,
                                    *idx,
                                    path.len(),
                                )?)),
                                path,
                            });
                        }
                    };
                }
            }
        }

        Ok(None)
    }
}

/// Direction for the [`MerkleTree::dfs`] as the return value of the visitor
/// function.
#[derive(Default)]
pub enum Visit {
    /// Instructs that the visit should visit any subtrees of the current node.
    /// This is a no-op for [`InternalNode::Leaf`].
    #[default]
    ContinueDeeper,
    /// Returning this value for [`InternalNode::Binary`] or
    /// [`InternalNode::Edge`] will ignore all of the children of the node
    /// for the rest of the iteration. This is useful because two trees often
    /// share a number of subtrees with earlier blocks. Returning this for
    /// [`InternalNode::Leaf`] is a no-op.
    StopSubtree,
}
