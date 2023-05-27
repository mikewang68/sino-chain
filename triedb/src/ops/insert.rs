use rlp::{self, Rlp};

use crate::{
    merkle::{
        empty_nodes,
        nibble::{Entry, NibbleVec},
        Branch, Extension, Leaf, MerkleNode, MerkleValue,
    },
    Change, Database,
};

fn value_and_leaf_branch<'a>(
    a: Entry<MerkleValue<'a>>,
    b: Entry<&'a [u8]>,
) -> (MerkleNode<'a>, Change) {
    debug_assert!(!a.nibble.is_empty());

    let mut change = Change::default();
    let mut additional = None;
    let mut nodes: [MerkleValue<'_>; 16] = empty_nodes();

    let ai: usize = a.nibble[0].into();
    let asub: NibbleVec = a.nibble[1..].into();

    if !asub.is_empty() {
        let branch = change.add_value(&MerkleNode::extension(asub, a.value));
        nodes[ai] = branch;
    } else {
        nodes[ai] = a.value;
    }

    if b.nibble.is_empty() {
        additional = Some(b.value);
    } else {
        let bi: usize = b.nibble[0].into();
        debug_assert!(ai != bi);

        let bsub = b.nibble[1..].into();
        let branch = change.add_value(&MerkleNode::leaf(bsub, b.value));

        nodes[bi] = branch;
    }

    (MerkleNode::branch(nodes, additional), change)
}

fn two_leaf_branch<'a>(a: Entry<&'a [u8]>, b: Entry<&'a [u8]>) -> (MerkleNode<'a>, Change) {
    debug_assert!(b.nibble.is_empty() || !a.nibble.starts_with(&b.nibble));
    debug_assert!(a.nibble.is_empty() || !b.nibble.starts_with(&a.nibble));

    let mut change = Change::default();
    let mut additional = None;
    let mut nodes: [MerkleValue<'_>; 16] = empty_nodes();

    if a.nibble.is_empty() {
        additional = Some(a.value);
    } else {
        let ai: usize = a.nibble[0].into();
        let asub: NibbleVec = a.nibble[1..].into();
        let branch = change.add_value(&MerkleNode::leaf(asub, a.value));
        nodes[ai] = branch;
    }

    if b.nibble.is_empty() {
        additional = Some(b.value);
    } else {
        let bi: usize = b.nibble[0].into();
        let bsub: NibbleVec = b.nibble[1..].into();
        let branch = change.add_value(&MerkleNode::leaf(bsub, b.value));
        nodes[bi] = branch;
    }

    (MerkleNode::branch(nodes, additional), change)
}

pub fn get_value<'a, D: Database>(
    node: MerkleNode<'a>,
    inserted: Entry<&'a [u8]>,
    database: &'a D,
    change: &mut Change,
) -> MerkleValue<'a> {
    let (new_node, subchange) = insert_by_node(node, inserted, database);
    change.merge(&subchange);
    change.add_value(&new_node)
}

pub fn insert_by_value<'a, D: Database>(
    merkle: MerkleValue<'a>,
    inserted: Entry<&'a [u8]>,
    database: &'a D,
) -> (MerkleValue<'a>, Change) {
    let mut change = Change::default();

    let new = match merkle {
        MerkleValue::Empty => change.add_value(&MerkleNode::leaf(inserted.nibble, inserted.value)),
        MerkleValue::Full(ref sub_node) => {
            let sub_node = sub_node.as_ref().clone();
            get_value(sub_node, inserted, database, &mut change)
        }
        MerkleValue::Hash(h) => {
            let sub_node = MerkleNode::decode(&Rlp::new(database.get(h)))
                .expect("Unable to decide Node value");
            change.remove_node(&sub_node);
            get_value(sub_node, inserted, database, &mut change)
        }
    };

    (new, change)
}

mod insert_by_node {
    use crate::merkle::nibble;
    use crate::merkle::nibble::NibbleVec;
    use crate::merkle::MerkleNode;
    use crate::merkle::MerkleValue;
    use crate::Change;
    use crate::Database;

    use super::insert_by_value;
    use super::two_leaf_branch;
    use super::value_and_leaf_branch;
    use super::Entry;

    pub fn leaf<'a>(
        key: NibbleVec,
        value: &'a [u8],
        inserted: Entry<&'a [u8]>,
    ) -> (MerkleNode<'a>, Change) {
        let mut change = Change::default();

        let new = if key == inserted.nibble {
            MerkleNode::leaf(inserted.nibble, inserted.value)
        } else {
            let (common, inserted_key_sub, key_sub) =
                nibble::common_with_sub(&inserted.nibble, &key);

            let (branch, subchange) = two_leaf_branch(
                Entry::new(key_sub, value),
                Entry::new(inserted_key_sub, inserted.value),
            );
            change.merge(&subchange);
            if !common.is_empty() {
                MerkleNode::extension(common.into(), change.add_value(&branch))
            } else {
                branch
            }
        };
        (new, change)
    }
    pub fn extension<'a, D: Database>(
        key: NibbleVec,
        value: MerkleValue<'a>,
        inserted: Entry<&'a [u8]>,
        database: &'a D,
    ) -> (MerkleNode<'a>, Change) {
        let mut change = Change::default();
        let new = if inserted.nibble.starts_with(&key) {
            let (subvalue, subchange) = insert_by_value(
                value.clone(),
                Entry::new(inserted.nibble[key.len()..].into(), inserted.value),
                database,
            );
            change.merge(&subchange);

            MerkleNode::extension(key, subvalue)
        } else {
            let (common, inserted_key_sub, key_sub) =
                nibble::common_with_sub(&inserted.nibble, &key);

            let (branch, subchange) = value_and_leaf_branch(
                Entry::new(key_sub, value.clone()),
                Entry::new(inserted_key_sub, inserted.value),
            );
            change.merge(&subchange);
            if !common.is_empty() {
                MerkleNode::extension(common.into(), change.add_value(&branch))
            } else {
                branch
            }
        };
        (new, change)
    }

    pub fn branch<'a, D: Database>(
        nodes: [MerkleValue<'a>; 16],
        value: Option<&'a [u8]>,
        inserted: Entry<&'a [u8]>,
        database: &'a D,
    ) -> (MerkleNode<'a>, Change) {
        let mut change = Change::default();
        let mut nodes = nodes.clone();
        let new = if inserted.nibble.is_empty() {
            MerkleNode::branch(nodes, Some(inserted.value))
        } else {
            let ni: usize = inserted.nibble[0].into();
            let prev = nodes[ni].clone();
            let (new, subchange) = insert_by_value(
                prev,
                Entry::new(inserted.nibble[1..].into(), inserted.value),
                database,
            );
            change.merge(&subchange);

            nodes[ni] = new;
            MerkleNode::branch(nodes, value)
        };
        (new, change)
    }
}

pub fn insert_by_node<'a, D: Database>(
    node: MerkleNode<'a>,
    inserted: Entry<&'a [u8]>,
    database: &'a D,
) -> (MerkleNode<'a>, Change) {
    let (new, change) = match node {
        MerkleNode::Leaf(Leaf {
            nibbles: key,
            data: value,
        }) => insert_by_node::leaf(key, value, inserted),
        MerkleNode::Extension(Extension {
            nibbles: key,
            value,
        }) => insert_by_node::extension(key, value, inserted, database),
        MerkleNode::Branch(Branch {
            childs: nodes,
            data: value,
        }) => insert_by_node::branch(nodes, value, inserted, database),
    };

    (new, change)
}

pub fn insert_by_empty(nibble: NibbleVec, value: &[u8]) -> (MerkleNode<'_>, Change) {
    let new = MerkleNode::leaf(nibble, value);
    (new, Change::default())
}
