use std::borrow::Borrow;

use primitive_types::H256;
use rlp::Rlp;

use crate::merkle::nibble::NibbleVec;
use crate::merkle::{Branch, Extension, Leaf, MerkleNode, MerkleValue};
use crate::{empty_trie_hash, Database};

use super::no_childs;

pub enum Child<'a> {
    Hash(H256),
    Inline(Box<MerkleNode<'a>>),
}

struct TReachableHashes<'a, F> {
    direct_childs: Vec<(NibbleVec, Child<'a>)>,
    extracted_childs: Vec<H256>,
    // node_key: Option<NibbleVec>,
    child_extractor: F,
}

impl<'a, F> TReachableHashes<'a, F>
where
    F: FnMut(&[u8]) -> Vec<H256>,
{
    pub fn collect(merkle_node: &MerkleNode<'a>, child_extractor: F) -> Self {
        let mut this = Self {
            direct_childs: Default::default(),
            extracted_childs: Default::default(),
            child_extractor,
            // node_key: None,
        };
        this.process_node(merkle_node);
        this
    }

    fn process_node(&mut self, merkle_node: &MerkleNode<'a>) {
        match merkle_node {
            MerkleNode::Leaf(Leaf { data, .. }) => {
                // self.node_key = Some(key.clone());
                self.extracted_childs
                    .extend_from_slice(&(self.child_extractor)(data))
            }
            MerkleNode::Extension(Extension { nibbles, value }) => {
                self.process_value(nibbles.clone(), value);
            }
            MerkleNode::Branch(Branch { childs, data }) => {
                if let Some(d) = data {
                    self.extracted_childs
                        .extend_from_slice(&(self.child_extractor)(d))
                }
                for (index, merkle_value) in childs.iter().enumerate() {
                    self.process_value(vec![index.into()], merkle_value);
                }
            }
        }
    }

    fn process_value(&mut self, prefix: NibbleVec, merkle_value: &MerkleValue<'a>) {
        match merkle_value {
            MerkleValue::Empty => {}
            MerkleValue::Full(merkle_node) => self
                .direct_childs
                .push((prefix, Child::Inline(merkle_node.clone()))),
            MerkleValue::Hash(hash) => self.direct_childs.push((prefix, Child::Hash(*hash))),
        }
    }

    pub fn childs(self) -> (Vec<(NibbleVec, Child<'a>)>, Vec<H256>) {
        let direct = self.direct_childs;
        let extracted = self
            .extracted_childs
            .into_iter()
            // Empty trie is a common default value for most
            // objects that contain submap, filtering it will reduce collissions.
            .filter(|i| *i != empty_trie_hash!())
            .collect();
        (direct, extracted)
    }
}

#[derive(Debug)]
enum NodeType {
    Leaf_,
    Extsn,
    Brnch,
    Empty,
    Embed,
}
pub struct Node {
    hash: Option<H256>,
    node_type: NodeType,
    key: NibbleDisplay,
    value: Option<Vec<u8>>,
}
struct NibbleDisplay(NibbleVec);

impl std::fmt::Display for NibbleDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let vec: Vec<char> = self.0.iter().map(|el| (*el).into()).collect();
        let string: String = vec.iter().collect();

        write!(f, "{}", string)
    }
}

impl std::fmt::Display for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let hash = match self.hash {
            Some(hash) => format!("{}", hash),
            None => "None".to_owned(),
        };
        let value: String = match &self.value {
            Some(s) => {
                let val = hexutil::to_hex(s);
                let mut res = " : ".to_owned();
                res.push_str(&val);
                res
            }
            None => "".to_owned(),
        };
        write!(
            f,
            "[{}] - {:?} <0x{}> {}",
            hash, self.node_type, self.key, value
        )
    }
}
pub trait DebugPrintExt {
    fn print(&self);
}

impl<T: std::fmt::Display> DebugPrintExt for termtree::Tree<T> {
    fn print(&self) {
        log::info!("\n{}", self);
    }
}

pub fn draw<D: Database, F>(
    db: &D,
    root: Child,
    mut key: NibbleVec,
    child_extractor: F,
) -> termtree::Tree<Node>
where
    F: FnMut(&[u8]) -> Vec<H256> + Clone,
{
    let zero: H256 = H256::from_slice(&[0u8; 32]);
    if let Child::Hash(root) = &root {
        if *root == empty_trie_hash() {
            return termtree::Tree::new(Node {
                hash: Some(empty_trie_hash()),
                node_type: NodeType::Empty,
                key: NibbleDisplay(vec![]),
                value: None,
            });
        }
    }
    let (hash, node, inline) = match root {
        Child::Hash(hash) => {
            let value = db.borrow().get(hash);
            (hash, MerkleNode::decode(&Rlp::new(value)).unwrap(), false)
        }
        Child::Inline(node) => (zero, (*node).clone(), true),
    };

    let (subkey, node_type, value) = match &node {
        MerkleNode::Leaf(Leaf { nibbles, data }) => {
            (nibbles.clone(), NodeType::Leaf_, Some(data.to_vec()))
        }
        MerkleNode::Extension(..) => (vec![], NodeType::Extsn, None),
        MerkleNode::Branch(Branch { data, .. }) => {
            (vec![], NodeType::Brnch, data.map(|slice| slice.to_vec()))
        }
    };

    key.extend(subkey.into_iter());
    let mut result = termtree::Tree::new(Node {
        hash: (!inline).then_some(hash),
        node_type,
        key: NibbleDisplay(key.clone()),
        value,
    });

    let (direct, extracted) = TReachableHashes::collect(&node, child_extractor.clone()).childs();

    for (suffix, child) in direct {
        let mut child_key = key.clone();
        child_key.extend(suffix.into_iter());
        result.push(draw(db, child, child_key, child_extractor.clone()));
    }
    for hash in extracted {
        let link_node = Node {
            hash: None,
            node_type: NodeType::Embed,
            key: NibbleDisplay(vec![]),
            value: Some(hash.as_bytes().to_vec()),
        };
        let mut link_tree = termtree::Tree::new(link_node);
        link_tree.push(draw(db, Child::Hash(hash), vec![], no_childs));
        result.push(link_tree);
    }
    result
}
