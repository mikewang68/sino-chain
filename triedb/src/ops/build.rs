use std::collections::HashMap;

use crate::{
    merkle::{
        empty_nodes,
        nibble::{self, Nibble, NibbleVec},
        MerkleNode, MerkleValue,
    },
    Change,
};

fn make_submap<'a, 'b: 'a, T: Iterator<Item = (&'a NibbleVec, &'a &'b [u8])>>(
    common_len: usize,
    map: T,
) -> HashMap<NibbleVec, &'b [u8]> {
    let mut submap = HashMap::new();
    for (key, &value) in map {
        submap.insert(key[common_len..].into(), value);
    }
    submap
}

pub fn build_value(node: MerkleNode<'_>) -> (MerkleValue<'_>, Change) {
    let mut change = Change::default();
    let value = change.add_value(&node);

    (value, change)
}

pub fn build_node<'a>(map: &HashMap<NibbleVec, &'a [u8]>) -> (MerkleNode<'a>, Change) {
    let mut change = Change::default();

    assert!(!map.is_empty());
    if map.len() == 1 {
        let key = map.keys().next().unwrap();
        return (MerkleNode::leaf(key.clone(), map.get(key).unwrap()), change);
    }

    debug_assert!(map.len() > 1);
    let common = nibble::common_all(map.keys().map(|v| v.as_ref()));

    if !common.is_empty() {
        let submap = make_submap(common.len(), map.iter());
        debug_assert!(!submap.is_empty());

        let (node, subchange) = build_node(&submap);
        change.merge(&subchange);

        let (value, subchange) = build_value(node);
        change.merge(&subchange);

        (MerkleNode::extension(common.into(), value), change)
    } else {
        let mut nodes: [MerkleValue<'_>; 16] = empty_nodes();

        for (i, node) in nodes.iter_mut().enumerate() {
            let nibble = Nibble::from(i);

            let submap = make_submap(
                1,
                map.iter()
                    .filter(|&(key, _value)| !key.is_empty() && key[0] == nibble),
            );

            if !submap.is_empty() {
                let (sub_node, subchange) = build_node(&submap);
                change.merge(&subchange);

                let (value, subchange) = build_value(sub_node);
                change.merge(&subchange);

                *node = value;
            }
        }

        let additional = map
            .iter()
            .find(|&(key, _value)| key.is_empty())
            .map(|(_key, value)| *value);

        (MerkleNode::branch(nodes, additional), change)
    }
}
