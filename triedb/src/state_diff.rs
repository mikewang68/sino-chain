use std::borrow::Borrow;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::sync::RwLock;

use crate::gc::ReachableHashes;
use crate::merkle::nibble::{self, Entry, Nibble, NibbleSlice, NibbleVec};
use crate::merkle::{MerkleNode, MerkleValue};
use crate::walker::inspector::TrieInspector;
use crate::Database;
use primitive_types::H256;
use rlp::Rlp;

#[cfg(feature = "tracing-enable")]
use tracing::instrument;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Insert(H256, Vec<u8>),
    Removal(H256, Vec<u8>),
}

///
/// Representation of node with data field (Leaf, or Branch when value.is_some())
///
#[derive(Debug, Clone, PartialEq, Eq)]
struct DataNode {
    hash: H256,
    data: Vec<u8>,
}

///
/// Represent data diff between data node.
/// Need for child tries processing.
///
#[derive(Debug, Clone, PartialEq, Eq)]
struct DataNodeChange {
    left: Option<DataNode>,
    right: Option<DataNode>,
}

#[derive(Debug, Default)]
pub struct Changes {
    changes: Vec<Change>,
    // inserts: Vec<(H256, Vec<u8>)>,
    // removes: Vec<(H256, Vec<u8>)>,
    data_diff: Vec<DataNodeChange>,
}
impl Changes {
    #[cfg_attr(feature = "tracing-enable", instrument)]
    fn reverse_changes(self) -> Self {
        let changes = self
            .changes
            .into_iter()
            .map(|i| match i {
                Change::Insert(h, d) => Change::Removal(h, d),
                Change::Removal(h, d) => Change::Insert(h, d),
            })
            .collect();

        let data_diff = self
            .data_diff
            .into_iter()
            .map(|changed|
            // Replace left and right
            DataNodeChange {
                left: changed.right,
                right: changed.left,
            })
            .collect();
        Self { changes, data_diff }
    }

    fn extend(&mut self, other: &Changes) {
        self.changes.extend_from_slice(&other.changes);
        self.data_diff.extend_from_slice(&other.data_diff);
    }

    fn remove_node<'a>(&mut self, node: impl Borrow<KeyedMerkleNode<'a>>) {
        if let KeyedMerkleNode::FullEncoded(hash, data) = node.borrow() {
            self.changes.push(Change::Removal(*hash, data.to_vec()))
        } else {
            log::trace!("Skipping to remove inline node")
        }
    }

    fn insert_node<'a>(&mut self, node: impl Borrow<KeyedMerkleNode<'a>>) {
        if let KeyedMerkleNode::FullEncoded(hash, data) = node.borrow() {
            self.changes.push(Change::Insert(*hash, data.to_vec()))
        } else {
            log::trace!("Skipping to insert inline node")
        }
    }
}

#[derive(Debug)]
pub struct DiffFinder<DB, F> {
    pub db: DB,
    child_extractor: F,
}

struct OpCollector<F> {
    changes: RwLock<Changes>,
    func: F,
}
impl<F: Fn(H256, Vec<u8>) -> Change> OpCollector<F> {
    pub fn new(func: F) -> Self {
        Self {
            changes: Default::default(),
            func,
        }
    }
}

impl<F> crate::walker::inspector::TrieInspector for OpCollector<F>
where
    F: Fn(H256, Vec<u8>) -> Change,
{
    fn inspect_node<Data: AsRef<[u8]>>(&self, trie_key: H256, node: Data) -> anyhow::Result<bool> {
        self.changes
            .write()
            .unwrap()
            .changes
            .push((self.func)(trie_key, node.as_ref().to_vec()));
        Ok(true)
    }
}

struct ChildCollector<F> {
    child_hashes: RwLock<Vec<H256>>,
    child_extractor: F,
}

impl<F: FnMut(&[u8]) -> Vec<H256> + Clone> crate::walker::inspector::TrieDataInsectorRaw
    for ChildCollector<F>
{
    fn inspect_data_raw<Data: AsRef<[u8]>>(
        &self,
        _key: Vec<u8>,
        value: Data,
    ) -> anyhow::Result<()> {
        let childs = (self.child_extractor.clone())(value.as_ref());
        self.child_hashes
            .write()
            .unwrap()
            .extend_from_slice(&childs);
        Ok(())
    }
}

trait MerkleValueExt<'a> {
    fn node(&self, database: &'a impl Database) -> Option<KeyedMerkleNode<'a>>;
}
impl<'a> MerkleValueExt<'a> for MerkleValue<'a> {
    fn node(&self, database: &'a impl Database) -> Option<KeyedMerkleNode<'a>> {
        Some(match self {
            Self::Empty => return None,
            Self::Full(n) => KeyedMerkleNode::Partial(n.deref().clone()),
            Self::Hash(h) => {
                let bytes = database.get(*h);
                KeyedMerkleNode::FullEncoded(*h, bytes)
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ComparePathResult {
    // Left NibbleVec contain additional nibbles
    // Example:
    // key1: bb33
    // key2: bb3
    LeftDeeper,
    // Right NibbleVec contain additional nibbles
    // Example:
    // key1: aabb
    // key2: aabb1e
    RightDeeper,
    // Right and Left NibbleVec are the same
    // Example:
    // key1: aabb1e
    // key2: aabb1e
    SamePath,
    // Left and Right paths contain different postfixes, and cannot be compared
    // Example:
    // key1: aabBcc
    // key2: aabEcc
    Uncomparable,
}
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
enum KeyedMerkleNode<'a> {
    // Merkle node is only exist as inlined node
    Partial(MerkleNode<'a>),
    FullEncoded(H256, &'a [u8]),
}

impl<'a> KeyedMerkleNode<'a> {
    fn same_hash(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::FullEncoded(h, _), Self::FullEncoded(h2, _)) => h == h2,
            _ => false,
        }
    }
    fn merkle_node(&self) -> MerkleNode {
        match self {
            Self::Partial(n) => n.clone(),
            Self::FullEncoded(_, n) => {
                let rlp = Rlp::new(n);
                MerkleNode::decode(&rlp).expect("Cannot deserialize value")
            }
        }
    }
}

impl<DB: Database + Send + Sync, F: FnMut(&[u8]) -> Vec<H256> + Clone + Send + Sync>
    DiffFinder<DB, F>
{
    pub fn new(db: DB, child_extractor: F) -> Self {
        DiffFinder {
            db,
            child_extractor,
        }
    }

    #[allow(clippy::result_unit_err)]
    pub fn get_changeset(
        &self,
        start_state_root: H256,
        end_state_root: H256,
    ) -> Result<Vec<Change>, ()> {
        self.compare_roots(
            Default::default(),
            Default::default(),
            start_state_root,
            end_state_root,
        )
        .map(|c| c.changes)
    }

    fn fetch_node(&self, hash: H256) -> KeyedMerkleNode<'_> {
        let bytes = self.db.get(hash);

        KeyedMerkleNode::FullEncoded(hash, bytes)
    }
    fn compare_roots(
        &self,
        left_key: NibbleVec,
        right_key: NibbleVec,
        left_root: H256,
        righ_root: H256,
    ) -> Result<Changes, ()> {
        Ok(
            match (
                left_root == crate::empty_trie_hash(),
                righ_root == crate::empty_trie_hash(),
            ) {
                (true, true) => Changes::default(),
                (true, false) => self.deep_insert(self.fetch_node(righ_root)),
                (false, true) => self.deep_remove(self.fetch_node(left_root)),
                (false, false) => {
                    let left_node = self.fetch_node(left_root);
                    let right_node = self.fetch_node(righ_root);

                    self.compare_nodes(
                        Entry::new(left_key, left_node),
                        Entry::new(right_key, right_node),
                    )
                }
            },
        )
    }

    #[cfg_attr(feature = "tracing-enable", instrument(skip(self)))]
    fn compare_nodes(
        &self,
        left_entry: Entry<KeyedMerkleNode>,
        right_entry: Entry<KeyedMerkleNode>,
    ) -> Changes {
        let mut changes = Changes::default();
        // TODO: check hash is enough there
        if left_entry.value.same_hash(&right_entry.value) {
            // if nodes are same - then left tree already contain this node - no reason to traverse it
            // return empty list
            return changes;
        }

        let branch_level = Self::check_branch_level(&left_entry.nibble, &right_entry.nibble);
        match branch_level {
            // We found two completely different paths
            ComparePathResult::Uncomparable => {
                changes.extend(&self.deep_remove(left_entry.value));
                changes.extend(&self.deep_insert(right_entry.value));
                return changes;
            }
            // We always trying to keep this function on same level, or when right node is deeper.
            // Traverse right side.
            ComparePathResult::LeftDeeper => {
                changes.extend(
                    &self
                        .compare_nodes(right_entry, left_entry)
                        .reverse_changes(),
                );
                return changes;
            }
            ComparePathResult::RightDeeper | ComparePathResult::SamePath => {}
        };
        self.compare_body(branch_level, left_entry, right_entry, changes)
    }
    fn compare_body(
        &self,
        branch_level: ComparePathResult,
        left_entry: Entry<KeyedMerkleNode>,
        right_entry: Entry<KeyedMerkleNode>,
        mut changes: Changes,
    ) -> Changes {
        match (
            left_entry.value.merkle_node(),
            right_entry.value.merkle_node(),
        ) {
            // One leaf was replaced by other. (data changed)
            (MerkleNode::Leaf(lkey, ldata), MerkleNode::Leaf(rkey, rdata)) => {
                if lkey != rkey || ldata != rdata {
                    assert_eq!(
                        left_entry.nibble.len() + lkey.len(),
                        right_entry.nibble.len() + rkey.len(),
                        "Diff work only with fixed sized key"
                    );
                    // if node is not same then it replace of new node
                    changes.extend(&self.deep_remove(left_entry.value));
                    changes.extend(&self.deep_insert(right_entry.value))
                }
            }
            // Leaf was replaced by subtree.
            (MerkleNode::Leaf(_lkey, _ldata), _rnode) => {
                changes.extend(&self.deep_remove(left_entry.value));
                changes.extend(&self.deep_insert(right_entry.value));
            }
            // We found extension at left part that differ from node from right.
            // Go deeper to find any branch or leaf.
            (MerkleNode::Extension(ext_key, mkl_value), _rnode) => {
                changes.remove_node(&left_entry.value);
                let full_key = {
                    let mut lk = left_entry.nibble;
                    lk.extend_from_slice(&ext_key);
                    lk
                };
                changes.extend(
                    &self.compare_nodes(
                        Entry::new(full_key, mkl_value)
                            .try_map(|mkl_value| mkl_value.node(self.db.borrow()))
                            .expect(MERKLE_VALUE_EMPTY_EXT_ERR),
                        right_entry,
                    ),
                );
            }
            // Branches on same level, but values were changed.
            (
                MerkleNode::Branch(left_values, left_data),
                MerkleNode::Branch(right_values, right_data),
            ) if branch_level == ComparePathResult::SamePath => {
                assert!(
                    left_data.is_none(),
                    "We support only fixed sized keys in diff"
                );
                assert!(
                    right_data.is_none(),
                    "We support only fixed sized keys in diff"
                );
                changes.remove_node(&left_entry.value);
                changes.insert_node(&right_entry.value);
                for (idx, (left_value, right_value)) in
                    left_values.iter().zip(right_values).enumerate()
                {
                    let branch_key = {
                        let mut key = right_entry.nibble.clone(); // || left.key is equal to right.key
                        key.push(Nibble::from(idx));
                        key
                    };
                    match (
                        left_value.node(self.db.borrow()),
                        right_value.node(self.db.borrow()),
                    ) {
                        (Some(lnode), Some(rnode)) => changes.extend(&self.compare_nodes(
                            Entry::new(branch_key.clone(), lnode),
                            Entry::new(branch_key.clone(), rnode),
                        )),
                        (Some(lnode), None) => changes.extend(&self.deep_remove(lnode)),
                        (None, Some(rnode)) => changes.extend(&self.deep_insert(rnode)),
                        (None, None) => {}
                    }
                }
            }
            (MerkleNode::Branch(values, maybe_data), _rnode) => {
                changes.remove_node(&left_entry.value);
                changes.extend(&self.walk_branch(
                    Entry::new(left_entry.nibble, values),
                    maybe_data,
                    right_entry,
                ));
            } // We can make shortcut for leaf.
              // (lnode, MerkleNode::Leaf(_lnibbles, rdata)) => {
              //     changes.push(Change::insert(right_node));
              //     changes.extend_from_slice(self.remove_swallow(left_nibble, lnode));
              // }

              // But all this cases:
              // (lnode, MerkleNode::Extension(..)) |
              // (lnode, MerkleNode::Leaf(..)) |
              // (lnode, MerkleNode::Branch(..))
              // were already covered by above match branches.
        }

        changes
    }
    fn deep_op<FN>(&self, node: KeyedMerkleNode, ti: OpCollector<FN>) -> Changes
    where
        OpCollector<FN>: TrieInspector + Sync + Send,
    {
        let merkle_hashes = match node {
            KeyedMerkleNode::FullEncoded(hash, _) => vec![hash],
            KeyedMerkleNode::Partial(node) => {
                ReachableHashes::collect(&node, self.child_extractor.clone()).childs()
            }
        };

        let data_inspector = ChildCollector {
            child_hashes: Default::default(),
            child_extractor: self.child_extractor.clone(),
        };
        let walker = crate::walker::Walker::new_raw(self.db.borrow(), ti, data_inspector);
        let mut hashes_to_traverse = merkle_hashes;
        loop {
            for hash in hashes_to_traverse {
                walker.traverse(hash).unwrap()
            }

            hashes_to_traverse = std::mem::take(
                walker
                    .data_inspector
                    .child_hashes
                    .write()
                    .unwrap()
                    .deref_mut(),
            );
            if hashes_to_traverse.is_empty() {
                break;
            }
        }
        walker
            .trie_inspector
            .changes
            .into_inner()
            .expect("lock poisoned")
    }
    #[cfg_attr(feature = "tracing-enable", instrument(skip(self)))]
    fn deep_insert(&self, node: KeyedMerkleNode) -> Changes {
        let collector = OpCollector::new(Change::Insert);
        self.deep_op(node, collector)
    }

    #[cfg_attr(feature = "tracing-enable", instrument(skip(self)))]
    fn deep_remove(&self, node: KeyedMerkleNode) -> Changes {
        let collector = OpCollector::new(Change::Removal);
        self.deep_op(node, collector)
    }

    fn check_branch_level(left_slice: NibbleSlice, right_slice: NibbleSlice) -> ComparePathResult {
        let common = nibble::common(left_slice, right_slice);
        match (
            common.len() != left_slice.len(),
            common.len() != right_slice.len(),
        ) {
            (true, false) => ComparePathResult::LeftDeeper,
            (false, true) => ComparePathResult::RightDeeper,
            (true, true) => ComparePathResult::Uncomparable,
            (false, false) => ComparePathResult::SamePath,
        }
    }

    // Find branch for right_node and walk deeper into one of branch
    #[cfg_attr(feature = "tracing-enable", instrument(skip(self)))]
    fn walk_branch(
        &self,
        left_entry: Entry<[MerkleValue; 16]>,
        maybe_data: Option<&[u8]>,
        right_entry: Entry<KeyedMerkleNode>,
    ) -> Changes {
        // Found a data in branch - it's a marker that key is not fixed sized.
        assert!(
            maybe_data.is_none(),
            "We support only fixed sized keys in diff"
        );

        let mut changes = Changes::default();

        let mut right_key = right_entry.nibble.clone();
        if let Some(rkey_suffix) = right_entry.value.merkle_node().nibble() {
            right_key.extend_from_slice(&rkey_suffix)
        }

        let (_common, left_postfix, right_postfix) =
            nibble::common_with_sub(&left_entry.nibble, &right_key);
        assert!(
            left_postfix.is_empty(),
            "left tree should have smaller path in order to find changed node in branch."
        );
        let right_nibble = right_postfix[0]; // find first different nibble
        let r_index: usize = right_nibble.into();
        if let Some(conflict_branch) =
            <MerkleValue as MerkleValueExt>::node(&left_entry.value[r_index], self.db.borrow())
        {
            let conflict_key = {
                let mut lk = left_entry.nibble.clone();
                lk.push(right_nibble);
                lk
            };
            changes.extend(
                &self.compare_nodes(Entry::new(conflict_key, conflict_branch), right_entry),
            );
        } else {
            changes.extend(&self.deep_insert(right_entry.value))
        }

        for (index, value) in left_entry.value.iter().enumerate() {
            let branch_key = {
                let mut lk = left_entry.nibble.clone();
                lk.push(Nibble::from(index));
                lk
            };
            if let Some(branch) = value.node(self.db.borrow()) {
                // Compare changed nodes
                if right_nibble == Nibble::from(index) {
                    // Logic mooved before cycle ... conflict_branch
                    continue;
                } else {
                    // mark all remaining nodes as removed
                    changes.extend(&self.deep_remove(branch))
                }
            } else {
                log::trace!("Node {:?} was not found in branch", branch_key);
            }
        }
        changes
    }
}
static MERKLE_VALUE_EMPTY_EXT_ERR: &str = "Extension should never link to empty value";

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;

    use hex_literal::hex;
    use serde::{Deserialize, Serialize};

    use crate::gc::TrieCollection;
    use crate::gc::{DbCounter, RootGuard};
    use crate::mutable::TrieMut;

    use super::*;

    #[cfg(feature = "tracing-enable")]
    fn tracing_sub_init() {
        use tracing::metadata::LevelFilter;
        use tracing_subscriber::fmt::format::FmtSpan;
        let _ = tracing_subscriber::fmt()
            .with_span_events(FmtSpan::ENTER)
            .with_max_level(LevelFilter::TRACE)
            .try_init();
    }
    #[cfg(not(feature = "tracing-enable"))]
    fn tracing_sub_init() {}

    #[derive(Eq, PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
    pub struct DataWithRoot {
        pub root: H256,
    }

    impl DataWithRoot {
        fn get_childs(data: &[u8]) -> Vec<H256> {
            bincode::deserialize::<Self>(data)
                .ok()
                .into_iter()
                .map(|e| e.root)
                .collect()
        }
    }
    impl Default for DataWithRoot {
        fn default() -> Self {
            Self {
                root: crate::empty_trie_hash!(),
            }
        }
    }

    fn no_childs(_: &[u8]) -> Vec<H256> {
        vec![]
    }

    // compare_nodes: (Remove(Extension('aaa')), compare_nodes(2))
    // compare_nodes: reverse(compare_nodes(3))
    // compare_nodes: (Remove(Branch('2['a','b']')), compare_nodes(4))
    // compare_nodes: (Remove(Extension('aa')), compare_nodes(5))
    // compare_nodes: same_node => {}
    // 'aaa' -> ['a', 'b']
    // extension -> branch
    // ['a','b'] -> 'aa' -> ['a', 'b']
    // branch -> extension -> branch
    use crate::gc::testing::MapWithCounterCached;

    fn check_changes(
        changes: &[Change],
        initial_trie_data: &Vec<(&[u8], &[u8])>,
        expected_trie_root: H256,
        expected_trie_data: &Vec<(&[u8], Option<Vec<u8>>)>,
    ) {
        let collection = TrieCollection::new(MapWithCounterCached::default());
        let mut trie = collection.trie_for(crate::empty_trie_hash());
        for (key, value) in initial_trie_data {
            trie.insert(key, value);
        }
        let patch = trie.into_patch();
        let _initial_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        let changes = crate::Change {
            changes: changes
                .iter()
                .map(|change| match change.clone() {
                    Change::Insert(key, val) => (key, Some(val)),
                    Change::Removal(key, _) => (key, None),
                })
                .collect(),
        };
        collection.apply_changes(changes, no_childs);

        let new_trie = collection.trie_for(expected_trie_root);
        for (key, value) in expected_trie_data {
            assert_eq!(TrieMut::get(&new_trie, key), *value);
        }
    }

    #[test]
    fn test_extension_replaced_by_branch_extension() {
        tracing_sub_init();

        let key1 = &hex!("aaab");
        let key2 = &hex!("aaac");
        let key3 = &hex!("bbcc");

        // make data too long for inline
        let value1 = b"same data________________________";
        let value2 = b"same data________________________";
        let value3 = b"same data________________________";

        let collection = TrieCollection::new(MapWithCounterCached::default());

        let mut trie = collection.trie_for(crate::empty_trie_hash());
        trie.insert(key1, value1);
        trie.insert(key2, value2);
        let patch = trie.into_patch();
        let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        let mut trie = collection.trie_for(first_root.root);
        trie.insert(key3, value3);
        let patch = trie.into_patch();
        let last_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        let st = DiffFinder::new(&collection.database, no_childs);
        let changes = st.get_changeset(first_root.root, last_root.root).unwrap();
        log::info!("result change = {:?}", changes);

        let new_collection = TrieCollection::new(MapWithCounterCached::default());
        let mut trie = new_collection.trie_for(crate::empty_trie_hash());
        trie.insert(key1, value1);
        trie.insert(key2, value2);
        let patch = trie.into_patch();
        let _first_root = new_collection.apply_increase(patch, crate::gc::tests::no_childs);
        let changes = crate::Change {
            changes: changes
                .into_iter()
                .map(|change| match change {
                    Change::Insert(key, val) => (key, Some(val)),
                    Change::Removal(key, _) => (key, None),
                })
                .collect(),
        };
        for (key, value) in changes.changes.into_iter().rev() {
            if let Some(value) = value {
                log::info!("change(insert): key={}, value={:?}", key, value);
                new_collection
                    .database
                    .gc_insert_node(key, &value, crate::gc::tests::no_childs);
            }
        }

        let new_trie = new_collection.trie_for(last_root.root);
        assert_eq!(
            TrieMut::get(&new_trie, &hex!("bbcc")),
            Some(b"same data________________________".to_vec())
        );
        assert_eq!(
            TrieMut::get(&new_trie, &hex!("aaab")),
            Some(b"same data________________________".to_vec())
        );
        assert_eq!(
            TrieMut::get(&new_trie, &hex!("aaac")),
            Some(b"same data________________________".to_vec())
        );

        drop(last_root);
        log::info!("second trie dropped")
    }

    #[test]
    fn test_two_empty_trees() {
        tracing_sub_init();

        let collection = TrieCollection::new(MapWithCounterCached::default());

        let trie = collection.trie_for(crate::empty_trie_hash());

        let patch = trie.into_patch();
        let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        let trie = collection.trie_for(first_root.root);
        let patch = trie.into_patch();
        let last_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        let st = DiffFinder::new(&collection.database, no_childs);
        log::info!(
            "result change = {:?}",
            st.get_changeset(first_root.root, last_root.root).unwrap()
        );
        drop(last_root);
        log::info!("second trie dropped")
    }

    #[test]
    fn test_empty_tree_and_leave() {
        tracing_sub_init();

        let collection = TrieCollection::new(MapWithCounterCached::default());

        // Set up initial trie
        let trie = collection.trie_for(crate::empty_trie_hash());
        let patch = trie.into_patch();
        let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        // Set up final trie
        let mut trie = collection.trie_for(first_root.root);
        trie.insert(&hex!("bbcc"), b"same data________________________");
        let patch = trie.into_patch();
        let last_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        // [Insert(0xacb66b810feb4a4e29ba06ed205fcac7cf4841be1a77d0d9ecc84d715c2151d7, [230, 131, 32, 187, 204, 161, 115, 97, 109, 101, 32, 100, 97, 116, 97, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95])];
        let key =
            H256::from_str("0xacb66b810feb4a4e29ba06ed205fcac7cf4841be1a77d0d9ecc84d715c2151d7")
                .unwrap();
        // let val1 = trie.get(key);
        let final_trie = collection.trie_for(last_root.root);
        let val1 = Database::get(&final_trie, key);
        dbg!("{:?}", val1);
        // let val1 = mutable::TrieMut::get(&final_trie, key);

        let val = vec![
            230, 131, 32, 187, 204, 161, 115, 97, 109, 101, 32, 100, 97, 116, 97, 95, 95, 95, 95,
            95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95,
        ];
        // H256::from_slice(&hex!("bbcc"));
        let expected_changeset = vec![Change::Insert(key, val)];

        let diff_finder = DiffFinder::new(&collection.database, no_childs);
        let changeset = diff_finder
            .get_changeset(first_root.root, last_root.root)
            .unwrap();
        let insert = changeset.get(0).unwrap();
        let (k, raw_v) = match &insert {
            &Change::Insert(key, val) => Some((key, val)),
            _ => None,
        }
        .unwrap();

        let rlp = Rlp::new(raw_v);
        let v = MerkleNode::decode(&rlp).unwrap();

        dbg!(v);

        // Take a change from a second trie
        // Create a change for first tree out of it
        let mut changes = crate::Change {
            changes: vec![].into(),
        };
        let rrr = raw_v.clone();
        changes.add_raw(*k, rrr.to_vec());

        // Take previous version of a tree
        let new_collection = TrieCollection::new(MapWithCounterCached::default());
        // Process changes
        for (key, value) in changes.changes.into_iter().rev() {
            if let Some(value) = value {
                log::info!("change(insert): key={}, value={:?}", key, value);
                new_collection
                    .database
                    .gc_insert_node(key, &value, crate::gc::tests::no_childs);
            }
        }

        // compare trie
        let new_trie = new_collection.trie_for(last_root.root);
        assert_eq!(
            TrieMut::get(&new_trie, &hex!("bbcc")),
            Some(b"same data________________________".to_vec())
        );

        log::info!("result change = {:?}", changeset);
        log::info!("second trie dropped");
        assert_eq!(expected_changeset, changeset);

        // TrieCollection { database: AsyncCachedHandle { db: MapWithCounter { counter: {0xacb66b810feb4a4e29ba06ed205fcac7cf4841be1a77d0d9ecc84d715c2151d7: 1}, data: {0xacb66b810feb4a4e29ba06ed205fcac7cf4841be1a77d0d9ecc84d715c2151d7: [230, 131, 32, 187, 204, 161, 115, 97, 109, 101, 32, 100, 97, 116, 97, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95]} }, cache: AsyncCache { cache: UnsafeCell { .. }, map: RwLock { data: {0xacb66b810feb4a4e29ba06ed205fcac7cf4841be1a77d0d9ecc84d715c2151d7: 0}, poisoned: false, .. } } } }
        println!("{:?}", collection);
        // TrieCollection { database: AsyncCachedHandle { db: MapWithCounter { counter: {}, data: {0xacb66b810feb4a4e29ba06ed205fcac7cf4841be1a77d0d9ecc84d715c2151d7: [230, 131, 32, 187, 204, 161, 115, 97, 109, 101, 32, 100, 97, 116, 97, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95]} }, cache: AsyncCache { cache: UnsafeCell { .. }, map: RwLock { data: {}, poisoned: false, .. } } } }
        println!("{:?}", new_collection);
    }

    #[test]
    fn test_leave_node_and_extension_node() {
        tracing_sub_init();

        let key1 = &hex!("aaab");
        let key2 = &hex!("aaac");

        // make data too long for inline
        let value1 = b"same data________________________";
        let value2 = b"same data________________________";

        let collection = TrieCollection::new(MapWithCounterCached::default());

        let mut trie = collection.trie_for(crate::empty_trie_hash());
        trie.insert(key1, value1);

        let patch = trie.into_patch();
        let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        let mut trie = collection.trie_for(first_root.root);

        trie.insert(key2, value2);
        let patch = trie.into_patch();

        let last_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        let st = DiffFinder::new(&collection.database, no_childs);
        log::info!(
            "result change = {:?}",
            st.get_changeset(first_root.root, last_root.root).unwrap()
        );
        drop(last_root);
        log::info!("second trie dropped")
    }

    #[test]
    fn test_two_different_leaf_nodes() {
        tracing_sub_init();

        let key1 = &hex!("aaab");
        let key2 = &hex!("aaac");

        // make data too long for inline
        let value1 = b"same data________________________1";
        let value2 = b"same data________________________2";

        let collection = TrieCollection::new(MapWithCounterCached::default());

        let mut trie1 = collection.trie_for(crate::empty_trie_hash());
        trie1.insert(key1, value1);
        let patch = trie1.into_patch();
        let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        let mut trie2 = collection.trie_for(crate::empty_trie_hash());
        trie2.insert(key2, value2);
        let patch = trie2.into_patch();
        let second_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        let st = DiffFinder::new(&collection.database, no_childs);
        let changes = st.get_changeset(first_root.root, second_root.root).unwrap();
        log::info!("result change = {:?}", changes);

        check_changes(
            &changes,
            &vec![(key1, value1)],
            second_root.root,
            &vec![
                (&hex!("aaab"), None),
                (
                    &hex!("aaac"),
                    Some(b"same data________________________2".to_vec()),
                ),
            ],
        );

        drop(second_root);
        log::info!("second trie dropped")
    }

    #[test]
    fn test_1() {
        tracing_sub_init();

        let keys1 = vec![
            (
                vec![0, 0, 0, 0, 0, 0, 12, 25],
                b"________________________________1",
            ),
            (
                vec![0, 0, 0, 0, 0, 0, 15, 203],
                b"________________________________2",
            ),
            (
                vec![0, 0, 0, 0, 0, 0, 16, 246],
                b"________________________________3",
            ),
        ];
        let keys2 = vec![
            (
                vec![0, 0, 0, 0, 0, 0, 13, 52],
                b"________________________________4",
            ),
            (
                vec![0, 0, 0, 0, 0, 0, 15, 55],
                b"________________________________5",
            ),
            (
                vec![0, 0, 0, 0, 0, 0, 15, 203],
                b"________________________________6",
            ),
        ];

        let collection = TrieCollection::new(MapWithCounterCached::default());

        let mut trie1 = collection.trie_for(crate::empty_trie_hash());
        for (key, value) in &keys1 {
            #[allow(clippy::explicit_auto_deref)]
            trie1.insert(key, *value);
        }
        let patch = trie1.into_patch();
        let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        let mut trie2 = collection.trie_for(crate::empty_trie_hash());
        for (key, value) in &keys2 {
            #[allow(clippy::explicit_auto_deref)]
            trie2.insert(key, *value);
        }
        let patch = trie2.into_patch();
        let second_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        let st = DiffFinder::new(&collection.database, no_childs);
        let changes = st.get_changeset(first_root.root, second_root.root).unwrap();
        log::info!("result change = {:?}", changes);

        check_changes(
            &changes,
            &keys1
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                .collect(),
            second_root.root,
            &vec![
                (&[0, 0, 0, 0, 0, 0, 12, 25], None),
                (&[0, 0, 0, 0, 0, 0, 16, 246], None),
                (
                    &[0, 0, 0, 0, 0, 0, 13, 52],
                    Some(b"________________________________4".to_vec()),
                ),
                (
                    &[0, 0, 0, 0, 0, 0, 15, 55],
                    Some(b"________________________________5".to_vec()),
                ),
                (
                    &[0, 0, 0, 0, 0, 0, 15, 203],
                    Some(b"________________________________6".to_vec()),
                ),
            ],
        );

        drop(second_root);
        log::info!("second trie dropped")
    }

    #[test]
    fn test_2() {
        tracing_sub_init();

        let keys1 = vec![
            (
                vec![0, 0, 0, 0, 0, 0, 12, 25],
                b"________________________________1",
            ),
            (
                vec![0, 0, 0, 0, 0, 0, 15, 203],
                b"________________________________2",
            ),
            (
                vec![0, 0, 0, 0, 0, 0, 16, 246],
                b"________________________________3",
            ),
        ];
        let keys2 = vec![
            (
                vec![0, 0, 0, 0, 0, 0, 13, 52],
                b"________________________________4",
            ),
            (
                vec![0, 0, 0, 0, 0, 0, 15, 203],
                b"________________________________5",
            ),
        ];

        let collection = TrieCollection::new(MapWithCounterCached::default());

        let mut trie1 = collection.trie_for(crate::empty_trie_hash());
        for (key, value) in &keys1 {
            #[allow(clippy::explicit_auto_deref)]
            trie1.insert(key, *value);
        }
        let patch = trie1.into_patch();
        let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        let mut trie2 = collection.trie_for(crate::empty_trie_hash());
        for (key, value) in &keys2 {
            #[allow(clippy::explicit_auto_deref)]
            trie2.insert(key, *value);
        }
        let patch = trie2.into_patch();
        let second_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        let st = DiffFinder::new(&collection.database, no_childs);
        let changes = st.get_changeset(first_root.root, second_root.root).unwrap();
        log::info!("result change = {:?}", changes);

        check_changes(
            &changes,
            &keys1
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                .collect(),
            second_root.root,
            &vec![
                (&[0, 0, 0, 0, 0, 0, 12, 25], None),
                (&[0, 0, 0, 0, 0, 0, 16, 246], None),
                (
                    &[0, 0, 0, 0, 0, 0, 13, 52],
                    Some(b"________________________________4".to_vec()),
                ),
                (
                    &[0, 0, 0, 0, 0, 0, 15, 203],
                    Some(b"________________________________5".to_vec()),
                ),
            ],
        );
        drop(second_root);
        log::info!("second trie dropped")
    }

    #[test]
    fn test_3() {
        tracing_sub_init();

        let keys1 = vec![
            (
                vec![0, 0, 0, 0, 0, 0, 12, 25],
                b"________________________________1",
            ),
            (
                vec![0, 0, 0, 0, 0, 0, 15, 203],
                b"________________________________2",
            ),
            (
                vec![0, 0, 0, 0, 0, 0, 16, 246],
                b"________________________________3",
            ),
        ];
        // One entry removed which eliminates first branch node
        let keys2 = vec![
            (
                vec![0, 0, 0, 0, 0, 0, 12, 25],
                b"________________________________1",
            ),
            (
                vec![0, 0, 0, 0, 0, 0, 15, 203],
                b"________________________________2",
            ),
        ];

        let collection = TrieCollection::new(MapWithCounterCached::default());

        let mut trie1 = collection.trie_for(crate::empty_trie_hash());
        for (key, value) in &keys1 {
            #[allow(clippy::explicit_auto_deref)]
            trie1.insert(key, *value);
        }
        let patch = trie1.into_patch();
        let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        let mut trie2 = collection.trie_for(crate::empty_trie_hash());
        for (key, value) in &keys2 {
            #[allow(clippy::explicit_auto_deref)]
            trie2.insert(key, *value);
        }
        let patch = trie2.into_patch();
        let second_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        let st = DiffFinder::new(&collection.database, no_childs);
        let changes = st.get_changeset(first_root.root, second_root.root).unwrap();
        log::info!("result change = {:?}", changes);

        check_changes(
            &changes,
            &keys1
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                .collect(),
            second_root.root,
            &vec![
                (&[0, 0, 0, 0, 0, 0, 16, 246], None),
                (
                    &[0, 0, 0, 0, 0, 0, 12, 25],
                    Some(b"________________________________1".to_vec()),
                ),
                (
                    &[0, 0, 0, 0, 0, 0, 15, 203],
                    Some(b"________________________________2".to_vec()),
                ),
            ],
        );
        drop(second_root);
        log::info!("second trie dropped")
    }

    #[test]
    fn test_4() {
        tracing_sub_init();

        let keys1 = vec![
            (vec![176, 3, 51, 51], b"________________________________1"),
            (vec![51, 51, 48, 0], b"________________________________2"),
            (vec![3, 51, 51, 51], b"________________________________2"),
            (vec![51, 51, 59, 51], b"________________________________2"),
            (vec![51, 0, 0, 0], b"________________________________3"),
        ];
        // One entry removed which eliminates first branch node
        let keys2 = vec![
            (vec![51, 51, 51, 51], b"________________________________2"),
            (vec![51, 51, 59, 48], b"________________________________2"),
            (vec![243, 51, 51, 51], b"________________________________2"),
            (vec![51, 51, 51, 51], b"________________________________1"),
            (vec![51, 51, 51, 59], b"________________________________1"),
        ];

        let collection = TrieCollection::new(MapWithCounterCached::default());

        let mut trie1 = collection.trie_for(crate::empty_trie_hash());
        for (key, value) in &keys1 {
            #[allow(clippy::explicit_auto_deref)]
            trie1.insert(key, *value);
        }
        let patch = trie1.into_patch();
        let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        let mut trie2 = collection.trie_for(crate::empty_trie_hash());
        for (key, value) in &keys2 {
            #[allow(clippy::explicit_auto_deref)]
            trie2.insert(key, *value);
        }
        let patch = trie2.into_patch();
        let second_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        let st = DiffFinder::new(&collection.database, no_childs);
        let changes = st.get_changeset(first_root.root, second_root.root).unwrap();
        log::info!("result change = {:?}", changes);

        check_changes(
            &changes,
            &keys1
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                .collect(),
            second_root.root,
            &vec![
                (
                    &[51, 51, 51, 51],
                    Some(b"________________________________1".to_vec()),
                ),
                (
                    &[51, 51, 59, 48],
                    Some(b"________________________________2".to_vec()),
                ),
                (
                    &[243, 51, 51, 51],
                    Some(b"________________________________2".to_vec()),
                ),
                (
                    &[51, 51, 51, 59],
                    Some(b"________________________________1".to_vec()),
                ),
                (&[176, 3, 51, 51], None),
            ],
        );
        drop(second_root);
        log::info!("second trie dropped")
    }

    #[test]
    fn test_insert_by_existing_key() {
        tracing_sub_init();

        let keys1 = vec![
            (vec![112, 0, 0, 0], b"________________________________2"),
            (vec![176, 0, 0, 0], b"________________________________1"),
            (vec![0, 0, 0, 0], b"________________________________1"),
            (vec![0, 0, 0, 0], b"________________________________2"),
        ];

        let collection = TrieCollection::new(MapWithCounterCached::default());

        let mut trie1 = collection.trie_for(crate::empty_trie_hash());
        for (key, value) in &keys1 {
            #[allow(clippy::explicit_auto_deref)]
            trie1.insert(key, *value);
        }
        let patch = trie1.into_patch();
        let first_root = collection.apply_increase(patch, crate::gc::tests::no_childs);

        let new_trie = collection.trie_for(first_root.root);
        assert_eq!(
            TrieMut::get(&new_trie, &[112, 0, 0, 0]),
            Some(b"________________________________2".to_vec())
        );
        assert_eq!(
            TrieMut::get(&new_trie, &[176, 0, 0, 0]),
            Some(b"________________________________1".to_vec())
        );
        assert_eq!(
            TrieMut::get(&new_trie, &[0, 0, 0, 0]),
            Some(b"________________________________2".to_vec())
        );
    }

    #[test]
    fn test_diff_with_child_extractor() {
        tracing_sub_init();

        let keys1 = vec![(
            vec![0, 0, 0, 0],
            vec![
                (
                    vec![0, 0, 0, 0],
                    vec![
                        238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![0, 0, 0, 15],
                    vec![
                        238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![0, 0, 3, 0],
                    vec![
                        255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![0, 0, 48, 0],
                    vec![
                        238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![0, 0, 243, 0],
                    vec![
                        238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![0, 7, 240, 0],
                    vec![
                        238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![0, 15, 0, 0],
                    vec![
                        238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![3, 0, 0, 0],
                    vec![
                        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![15, 51, 255, 255],
                    vec![
                        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![240, 255, 240, 127],
                    vec![
                        238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![255, 255, 255, 240],
                    vec![
                        238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
                (
                    vec![255, 255, 255, 255],
                    vec![
                        238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ],
        )];

        let keys2 = vec![
            (
                vec![0, 0, 0, 0],
                vec![
                    (
                        vec![0, 0, 0, 0],
                        vec![
                            255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ],
                    ),
                    (
                        vec![0, 0, 0, 15],
                        vec![
                            238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ],
                    ),
                    (
                        vec![0, 0, 3, 0],
                        vec![
                            255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ],
                    ),
                    (
                        vec![0, 0, 15, 51],
                        vec![
                            238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ],
                    ),
                    (
                        vec![0, 0, 48, 0],
                        vec![
                            238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ],
                    ),
                    (
                        vec![0, 0, 243, 0],
                        vec![
                            238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ],
                    ),
                    (
                        vec![0, 7, 240, 0],
                        vec![
                            238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ],
                    ),
                    (
                        vec![0, 15, 0, 0],
                        vec![
                            238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ],
                    ),
                    (
                        vec![3, 0, 0, 0],
                        vec![
                            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0,
                        ],
                    ),
                    (
                        vec![15, 51, 255, 255],
                        vec![
                            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0,
                        ],
                    ),
                    (
                        vec![240, 255, 240, 127],
                        vec![
                            238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ],
                    ),
                    (
                        vec![255, 255, 255, 240],
                        vec![
                            238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ],
                    ),
                    (
                        vec![255, 255, 255, 255],
                        vec![
                            238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ],
                    ),
                ],
            ),
            (
                vec![0, 0, 0, 48],
                vec![
                    (
                        vec![0, 0, 0, 0],
                        vec![
                            238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ],
                    ),
                    (
                        vec![0, 7, 240, 0],
                        vec![
                            238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ],
                    ),
                    (
                        vec![3, 0, 0, 0],
                        vec![
                            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0,
                        ],
                    ),
                    (
                        vec![0, 0, 15, 255],
                        vec![
                            255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ],
                    ),
                ],
            ),
        ];

        let collection1 = TrieCollection::new(MapWithCounterCached::default());
        let collection2 = TrieCollection::new(MapWithCounterCached::default());
        let mut collection1_trie1 = RootGuard::new(
            &collection1.database,
            crate::empty_trie_hash(),
            DataWithRoot::get_childs,
        );
        let mut collection1_trie2 = RootGuard::new(
            &collection1.database,
            crate::empty_trie_hash(),
            DataWithRoot::get_childs,
        );
        let mut collection2_trie1 = RootGuard::new(
            &collection2.database,
            crate::empty_trie_hash(),
            DataWithRoot::get_childs,
        );

        for (k, storage) in keys1.iter() {
            for (data_key, data) in storage {
                {
                    // Insert to first db
                    let mut account_trie = collection1.trie_for(collection1_trie1.root);
                    let mut account: DataWithRoot = TrieMut::get(&account_trie, k)
                        .map(|d| bincode::deserialize(&d).unwrap())
                        .unwrap_or_default();
                    let mut storage_trie = collection1.trie_for(account.root);
                    storage_trie.insert(data_key, data);
                    let storage_patch = storage_trie.into_patch();
                    log::trace!(
                        "1 Update account root: old {}, new {}",
                        account.root,
                        storage_patch.root
                    );
                    account.root = storage_patch.root;
                    account_trie.insert(k, &bincode::serialize(&account).unwrap());
                    let mut account_patch = account_trie.into_patch();
                    account_patch.change.merge_child(&storage_patch.change);

                    collection1_trie1 =
                        collection1.apply_increase(account_patch, DataWithRoot::get_childs);
                }
                {
                    // Insert to second db
                    let mut account_trie = collection2.trie_for(collection2_trie1.root);
                    let mut account: DataWithRoot = TrieMut::get(&account_trie, k)
                        .map(|d| bincode::deserialize(&d).unwrap())
                        .unwrap_or_default();
                    let mut storage_trie = collection2.trie_for(account.root);
                    storage_trie.insert(data_key, data);
                    let storage_patch = storage_trie.into_patch();
                    account.root = storage_patch.root;
                    account_trie.insert(k, &bincode::serialize(&account).unwrap());
                    let mut account_patch = account_trie.into_patch();
                    account_patch.change.merge_child(&storage_patch.change);

                    collection2_trie1 =
                        collection2.apply_increase(account_patch, DataWithRoot::get_childs);
                }
            }
        }

        let mut accounts_map: HashMap<Vec<u8>, HashMap<Vec<u8>, Vec<u8>>> = HashMap::new();
        for (k, storage) in keys2.iter() {
            let account_updates = accounts_map.entry(k.clone()).or_default();
            for (data_key, data) in storage {
                let mut account_trie = collection1.trie_for(collection1_trie2.root);
                let mut account: DataWithRoot = TrieMut::get(&account_trie, k)
                    .map(|d| bincode::deserialize(&d).unwrap())
                    .unwrap_or_default();
                let mut storage_trie = collection1.trie_for(account.root);
                account_updates.insert(data_key.clone(), data.clone());
                storage_trie.insert(data_key, data);
                let storage_patch = storage_trie.into_patch();
                log::trace!(
                    "2 Update account root: old {}, new {}",
                    account.root,
                    storage_patch.root
                );
                account.root = storage_patch.root;
                account_trie.insert(k, &bincode::serialize(&account).unwrap());
                let mut account_patch = account_trie.into_patch();
                account_patch.change.merge_child(&storage_patch.change);

                collection1_trie2 =
                    collection1.apply_increase(account_patch, DataWithRoot::get_childs);
            }
        }

        let st = DiffFinder::new(&collection1.database, DataWithRoot::get_childs);
        let changes = st
            .get_changeset(collection1_trie1.root, collection1_trie2.root)
            .unwrap();
        log::info!("result change = {:?}", changes);
        let changes = crate::Change {
            changes: changes
                .into_iter()
                .map(|change| match change {
                    Change::Insert(key, val) => {
                        println!(
                            "====================== INSERT: {} ======================",
                            key
                        );
                        (key, Some(val))
                    }
                    Change::Removal(key, _) => {
                        println!(
                            "====================== REMOVE: {} ======================",
                            key
                        );
                        (key, None)
                    }
                })
                .collect(),
        };

        for (key, value) in changes.changes.into_iter().rev() {
            if let Some(value) = value {
                collection2
                    .database
                    .gc_insert_node(key, &value, DataWithRoot::get_childs);
            }
        }

        let accounts_storage = collection2.trie_for(collection1_trie2.root);
        for (k, storage) in accounts_map {
            let account: DataWithRoot =
                bincode::deserialize(&TrieMut::get(&accounts_storage, &k).unwrap()).unwrap();

            let account_storage_trie = collection2.trie_for(account.root);
            for data_key in storage.keys() {
                assert_eq!(
                    &storage[data_key][..],
                    &TrieMut::get(&account_storage_trie, data_key).unwrap()
                );
            }
        }
    }
}
