use rlp::{self, Rlp};

use crate::{
    merkle::{nibble::NibbleVec, Branch, Extension, Leaf, MerkleNode, MerkleValue},
    Database,
};

pub fn get_by_value<'a, D: Database>(
    merkle: MerkleValue<'a>,
    nibble: NibbleVec,
    database: &'a D,
) -> Option<&'a [u8]> {
    match merkle {
        MerkleValue::Empty => None,
        MerkleValue::Full(subnode) => get_by_node(subnode.as_ref().clone(), nibble, database),
        MerkleValue::Hash(h) => {
            let subnode = MerkleNode::decode(&Rlp::new(database.get(h)))
                .expect("Unable to decode Node value");
            get_by_node(subnode, nibble, database)
        }
    }
}

pub fn get_by_node<'a, D: Database>(
    node: MerkleNode<'a>,
    nibble: NibbleVec,
    database: &'a D,
) -> Option<&'a [u8]> {
    match node {
        MerkleNode::Leaf(Leaf {
            nibbles: node_nibble,
            data: node_value,
        }) => {
            if node_nibble == nibble {
                Some(node_value)
            } else {
                None
            }
        }
        MerkleNode::Extension(Extension {
            nibbles: node_nibble,
            value: node_value,
        }) => {
            if nibble.starts_with(&node_nibble) {
                get_by_value(node_value, nibble[node_nibble.len()..].into(), database)
            } else {
                None
            }
        }
        MerkleNode::Branch(Branch {
            childs: node_nodes,
            data: node_additional,
        }) => {
            if nibble.is_empty() {
                node_additional
            } else {
                let ni: usize = nibble[0].into();
                get_by_value(node_nodes[ni].clone(), nibble[1..].into(), database)
            }
        }
    }
}
