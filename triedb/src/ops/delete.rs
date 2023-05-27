use rlp::{self, Rlp};

use crate::{
    merkle::{
        nibble::{Nibble, NibbleVec},
        Branch, Extension, Leaf, MerkleNode, MerkleValue,
    },
    Change, Database,
};

fn find_and_remove_child<'a, D: Database>(
    merkle: MerkleValue<'a>,
    database: &'a D,
) -> (MerkleNode<'a>, Change) {
    let mut change = Change::default();

    let node = match merkle {
        MerkleValue::Empty => panic!(),
        MerkleValue::Full(ref sub_node) => sub_node.as_ref().clone(),
        MerkleValue::Hash(h) => {
            let sub_node =
                MerkleNode::decode(&Rlp::new(database.get(h))).expect("Unable to decode value");
            change.remove_node(&sub_node);
            sub_node
        }
    };

    (node, change)
}

fn collapse_extension(
    mut node_nibble: NibbleVec,
    subnode: MerkleNode<'_>,
) -> (MerkleNode<'_>, Change) {
    let mut change = Change::default();

    let node = match subnode {
        MerkleNode::Leaf(Leaf {
            nibbles: mut sub_nibble,
            data: sub_value,
        }) => {
            node_nibble.append(&mut sub_nibble);
            MerkleNode::leaf(node_nibble, sub_value)
        }
        MerkleNode::Extension(Extension {
            nibbles: mut sub_nibble,
            value: sub_value,
        }) => {
            debug_assert!(sub_value != MerkleValue::Empty);

            node_nibble.append(&mut sub_nibble);
            MerkleNode::extension(node_nibble, sub_value)
        }
        branch => {
            let subvalue = change.add_value(&branch);
            MerkleNode::extension(node_nibble, subvalue)
        }
    };

    (node, change)
}

fn nonempty_node_count<'a, 'b>(
    nodes: &'b [MerkleValue<'a>; 16],
    additional: &'b Option<&'a [u8]>,
) -> usize {
    additional.iter().count() + nodes.iter().filter(|v| v != &&MerkleValue::Empty).count()
}

fn collapse_branch<'a, D: Database>(
    node_nodes: [MerkleValue<'a>; 16],
    node_additional: Option<&'a [u8]>,
    database: &'a D,
) -> (MerkleNode<'a>, Change) {
    let mut change = Change::default();

    let value_count = nonempty_node_count(&node_nodes, &node_additional);

    let node = match value_count {
        0 => panic!(),
        1 if node_additional.is_some() =>
            MerkleNode::leaf(NibbleVec::new(), node_additional.unwrap()),
        1 /* value in node_nodes */ => {
            let (subindex, subvalue) = node_nodes.iter().enumerate()
                .find(|&(_, v)| v != &MerkleValue::Empty)
                .map(|(i, v)| (i, v.clone())).unwrap();
            let subnibble =  Nibble::from(subindex);

            let (subnode, subchange) = find_and_remove_child(subvalue, database);
            change.merge(&subchange);

            match subnode {
                MerkleNode::Leaf(Leaf{nibbles: mut leaf_nibble, data: leaf_value}) => {
                    leaf_nibble.insert(0, subnibble);
                    MerkleNode::leaf(leaf_nibble, leaf_value)
                },
                MerkleNode::Extension(Extension{ nibbles: mut ext_nibble, value: ext_value}) => {
                    debug_assert!(ext_value != MerkleValue::Empty);

                    ext_nibble.insert(0, subnibble);
                    MerkleNode::extension(ext_nibble, ext_value)
                },
                branch => {
                    let subvalue = change.add_value(&branch);
                    MerkleNode::extension(vec![subnibble], subvalue)
                },
            }
        },
        _ /* value_count > 1 */ =>
            MerkleNode::branch(node_nodes, node_additional),
    };

    (node, change)
}

pub fn delete_by_child<'a, D: Database>(
    merkle: MerkleValue<'a>,
    nibble: NibbleVec,
    database: &'a D,
) -> (Option<MerkleNode<'a>>, Change) {
    let mut change = Change::default();

    let new = match merkle {
        MerkleValue::Empty => None,
        MerkleValue::Full(ref sub_node) => {
            let (new_node, subchange) = delete_by_node(sub_node.as_ref().clone(), nibble, database);
            change.merge(&subchange);
            new_node
        }
        MerkleValue::Hash(h) => {
            let sub_node = MerkleNode::decode(&Rlp::new(database.get(h)))
                .expect("Unable to decode Node value");
            change.remove_node(&sub_node);
            let (new_node, subchange) = delete_by_node(sub_node, nibble, database);
            change.merge(&subchange);
            new_node
        }
    };

    (new, change)
}

pub fn delete_by_node<'a, D: Database>(
    node: MerkleNode<'a>,
    nibble: NibbleVec,
    database: &'a D,
) -> (Option<MerkleNode<'a>>, Change) {
    let mut change = Change::default();

    let new = match node {
        MerkleNode::Leaf(Leaf {
            nibbles: node_nibble,
            data: node_value,
        }) => {
            if node_nibble == nibble {
                None
            } else {
                Some(MerkleNode::leaf(node_nibble, node_value))
            }
        }
        MerkleNode::Extension(Extension {
            nibbles: node_nibble,
            value: node_value,
        }) => {
            if nibble.starts_with(&node_nibble) {
                let (subnode, subchange) =
                    delete_by_child(node_value, nibble[node_nibble.len()..].into(), database);
                change.merge(&subchange);

                match subnode {
                    Some(subnode) => {
                        let (new, subchange) = collapse_extension(node_nibble, subnode);
                        change.merge(&subchange);

                        Some(new)
                    }
                    None => None,
                }
            } else {
                Some(MerkleNode::extension(node_nibble, node_value))
            }
        }
        MerkleNode::Branch(Branch {
            childs: mut node_nodes,
            data: mut node_additional,
        }) => {
            let needs_collapse;

            if nibble.is_empty() {
                node_additional = None;
                needs_collapse = true;
            } else {
                let ni: usize = nibble[0].into();
                let (new_subnode, subchange) =
                    delete_by_child(node_nodes[ni].clone(), nibble[1..].into(), database);
                change.merge(&subchange);

                match new_subnode {
                    Some(new_subnode) => {
                        let new_subvalue = change.add_value(&new_subnode);

                        node_nodes[ni] = new_subvalue;
                        needs_collapse = false;
                    }
                    None => {
                        node_nodes[ni] = MerkleValue::Empty;
                        needs_collapse = true;
                    }
                }
            }

            if needs_collapse {
                let value_count = nonempty_node_count(&node_nodes, &node_additional);
                if value_count > 0 {
                    let (new, subchange) = collapse_branch(node_nodes, node_additional, database);
                    change.merge(&subchange);

                    Some(new)
                } else {
                    None
                }
            } else {
                Some(MerkleNode::branch(node_nodes, node_additional))
            }
        }
    };

    (new, change)
}
