use std::collections::HashSet;
use std::str::FromStr;

use primitive_types::H256;
use rlp::Rlp;
use serde_json::json;

use crate::cache::SyncCache;
use crate::debug::DebugPrintExt;
use crate::empty_trie_hash;
use crate::gc::DbCounter;
use crate::gc::MapWithCounterCachedParam;
use crate::gc::TrieCollection;
use crate::merkle::MerkleNode;
use crate::mutable::TrieMut;
use crate::{debug, diff};

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
fn tracing_sub_init() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();
}

fn no_childs(_: &[u8]) -> Vec<H256> {
    vec![]
}

type SyncDashMap = MapWithCounterCachedParam<SyncCache>;

// compare_nodes: (Remove(Extension('aaa')), compare_nodes(2))
// compare_nodes: reverse(compare_nodes(3))
// compare_nodes: (Remove(Branch('2['a','b']')), compare_nodes(4))
// compare_nodes: (Remove(Extension('aa')), compare_nodes(5))
// compare_nodes: same_node => {}
// 'aaa' -> ['a', 'b']
// extension -> branch
// ['a','b'] -> 'aa' -> ['a', 'b']
// branch -> extension -> branch
use super::Change;

#[test]
fn test_extension_replaced_by_branch_extension() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();
    tracing_sub_init();

    let j = json!([
        [
            "0xaaab",
            "0x73616d6520646174615f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f"
        ],
        [
            "0xaaac",
            "0x73616d6520646174615f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f"
        ]
    ]);

    let entries1: debug::EntriesHex = serde_json::from_value(j).unwrap();
    let j = json!([[
        "0xbbcc",
        "0x73616d6520646174615f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f"
    ]]);

    let entries2: debug::EntriesHex = serde_json::from_value(j).unwrap();

    let collection = TrieCollection::new(SyncDashMap::default());

    let mut trie = collection.trie_for(crate::empty_trie_hash());

    for (key, value) in &entries1.data {
        trie.insert(key, value.as_ref().unwrap());
    }
    let patch = trie.into_patch();
    let first_root = collection.apply_increase(patch, crate::debug::no_childs);
    debug::draw(
        &collection.database,
        debug::Child::Hash(first_root.root),
        vec![],
        no_childs,
    )
    .print();

    let mut trie = collection.trie_for(first_root.root);
    for (key, value) in &entries2.data {
        trie.insert(key, value.as_ref().unwrap());
    }
    let patch = trie.into_patch();
    let last_root = collection.apply_increase(patch, crate::debug::no_childs);

    debug::draw(
        &collection.database,
        debug::Child::Hash(last_root.root),
        vec![],
        no_childs,
    )
    .print();

    let changes = diff(
        &collection.database,
        no_childs,
        first_root.root,
        last_root.root,
    )
    .unwrap();
    log::info!("result change = {:#?}", changes);

    let new_collection = TrieCollection::new(SyncDashMap::default());
    let mut trie = new_collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &entries1.data {
        trie.insert(key, value.as_ref().unwrap());
    }
    let patch = trie.into_patch();
    let _first_root = new_collection.apply_increase(patch, crate::debug::no_childs);
    let changes = crate::Change {
        changes: changes
            .into_iter()
            .map(|change| match change {
                Change::Insert(key, val) => (key, Some(val)),
                Change::Removal(key, _) => (key, None),
            })
            .collect(),
    };
    // ERROR: order is _ucked up
    for (key, value) in changes.changes.into_iter().rev() {
        if let Some(value) = value {
            log::info!("change(insert): key={}, value={:?}", key, value);
            new_collection
                .database
                .gc_insert_node(key, &value, crate::debug::no_childs);
        }
    }

    let new_trie = new_collection.trie_for(last_root.root);

    assert_eq!(
        TrieMut::get(&new_trie, &entries2.data[0].0),
        entries2.data[0].1.as_ref().map(|val| val.to_vec())
    );
    assert_eq!(
        TrieMut::get(&new_trie, &entries1.data[0].0),
        entries1.data[0].1.as_ref().map(|val| val.to_vec())
    );
    assert_eq!(
        TrieMut::get(&new_trie, &entries1.data[1].0),
        entries1.data[1].1.as_ref().map(|val| val.to_vec())
    );

    drop(last_root);
    log::info!("second trie dropped")
}

#[test]
fn test_two_empty_trees() {
    tracing_sub_init();

    let collection = TrieCollection::new(SyncDashMap::default());

    let trie = collection.trie_for(crate::empty_trie_hash());

    let patch = trie.into_patch();
    let first_root = collection.apply_increase(patch, crate::debug::no_childs);

    let trie = collection.trie_for(first_root.root);
    let patch = trie.into_patch();
    let last_root = collection.apply_increase(patch, crate::debug::no_childs);

    let changes = diff(
        &collection.database,
        no_childs,
        first_root.root,
        last_root.root,
    )
    .unwrap();
    assert!(changes.is_empty());
    drop(last_root);
    log::info!("second trie dropped")
}

#[test]
fn test_empty_tree_and_leaf() {
    tracing_sub_init();

    let collection = TrieCollection::new(SyncDashMap::default());

    // Set up initial trie
    let trie = collection.trie_for(crate::empty_trie_hash());
    let patch = trie.into_patch();
    let first_root = collection.apply_increase(patch, crate::debug::no_childs);

    // Set up final trie
    let mut trie = collection.trie_for(first_root.root);

    let j = json!([[
        "0xbbcc",
        "0x73616d6520646174615f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f"
    ]]);

    let entries: debug::EntriesHex = serde_json::from_value(j).unwrap();

    for (key, value) in &entries.data {
        trie.insert(key, value.as_ref().unwrap());
    }
    let patch = trie.into_patch();
    let last_root = collection.apply_increase(patch, crate::debug::no_childs);

    debug::draw(
        &collection.database,
        debug::Child::Hash(last_root.root),
        vec![],
        no_childs,
    )
    .print();

    // [Insert(0xacb66b810feb4a4e29ba06ed205fcac7cf4841be1a77d0d9ecc84d715c2151d7, [230, 131, 32, 187, 204, 161, 115, 97, 109, 101, 32, 100, 97, 116, 97, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95])];
    let key = H256::from_str("0xacb66b810feb4a4e29ba06ed205fcac7cf4841be1a77d0d9ecc84d715c2151d7")
        .unwrap();

    let val = hexutil::read_hex(
        "0xe68320bbcca173616d6520646174615f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f",
    )
    .unwrap();

    // H256::from_slice(&hex!("bbcc"));
    let expected_changeset = vec![Change::Insert(key, val.into())];

    let changeset = diff(
        &collection.database,
        no_childs,
        first_root.root,
        last_root.root,
    )
    .unwrap();
    let insert = changeset.get(0).unwrap();
    let (k, raw_v) = match &insert {
        &Change::Insert(key, val) => Some((key, val)),
        _ => None,
    }
    .unwrap();

    let rlp = Rlp::new(raw_v);
    let v = MerkleNode::decode(&rlp).unwrap();

    log::info!("{:?}", v);

    // Take a change from a second trie
    // Create a change for first tree out of it
    let mut changes = crate::Change {
        changes: vec![].into(),
    };
    let rrr = raw_v.clone();
    changes.add_raw(*k, rrr.to_vec());

    // Take previous version of a tree
    let new_collection = TrieCollection::new(SyncDashMap::default());
    // Process changes
    for (key, value) in changes.changes.into_iter().rev() {
        if let Some(value) = value {
            log::info!("change(insert): key={}, value={:?}", key, value);
            new_collection
                .database
                .gc_insert_node(key, &value, crate::debug::no_childs);
        }
    }

    // compare trie
    let new_trie = new_collection.trie_for(last_root.root);
    assert_eq!(
        TrieMut::get(&new_trie, &entries.data[0].0),
        entries.data[0].1
    );

    log::info!("result change = {:?}", changeset);
    log::info!("second trie dropped");
    assert_eq!(expected_changeset, changeset);
}

#[test]
fn test_insert_by_existing_key() {
    tracing_sub_init();

    let j = json!([
        [
            "0x70000000",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ],
        [
            "0xb0000000",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"
        ],
        [
            "0x00000000",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31"
        ],
        [
            "0x00000000",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ]
    ]);
    let entries: debug::EntriesHex = serde_json::from_value(j).unwrap();

    let collection = TrieCollection::new(SyncDashMap::default());

    let mut trie1 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &entries.data {
        trie1.insert(key, value.as_ref().unwrap());
    }
    let patch = trie1.into_patch();
    let first_root = collection.apply_increase(patch, crate::debug::no_childs);

    debug::draw(
        &collection.database,
        debug::Child::Hash(first_root.root),
        vec![],
        no_childs,
    )
    .print();

    let new_trie = collection.trie_for(first_root.root);
    assert_eq!(
        TrieMut::get(&new_trie, &entries.data[0].0),
        entries.data[0].1.as_ref().map(|val| val.to_vec())
    );
    assert_eq!(
        TrieMut::get(&new_trie, &entries.data[1].0),
        entries.data[1].1.as_ref().map(|val| val.to_vec())
    );
    assert_eq!(
        TrieMut::get(&new_trie, &entries.data[3].0),
        entries.data[3].1.as_ref().map(|val| val.to_vec())
    );
}

#[test]
fn test_leaf_replaced_by_branch() {
    tracing_sub_init();
    let first = json!([[
        "0x70",
        [[
            "0x01",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ]]
    ],]);

    let second = json!([
        [
            "0x70",
            [
                [
                    "0x01",
                    "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
                ],
                [
                    "0x02",
                    "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f38"
                ]
            ]
        ],
        [
            "0x70000030",
            [[
                "0x02",
                "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f33"
            ]]
        ],
    ]);
    fn child_collecting(data: &[u8]) -> Vec<H256> {
        vec![H256::from_slice(data)]
    }
    let first_entries: debug::InnerEntriesHex = serde_json::from_value(first).unwrap();
    let second_entries: debug::InnerEntriesHex = serde_json::from_value(second).unwrap();

    let collection = TrieCollection::new(SyncDashMap::default());

    let mut trie1 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &first_entries.data {
        let val = trie1.get(key);
        let key_root = val
            .map(|v| H256::from_slice(&v))
            .unwrap_or_else(empty_trie_hash);
        let mut inner_trie = collection.trie_for(key_root);
        for (key, value) in &value.data {
            inner_trie.insert(key, value.as_ref().unwrap())
        }
        let patch = inner_trie.into_patch();
        let g = collection.apply_increase(patch, no_childs);
        trie1.insert(key, g.leak_root().as_bytes());
    }
    let patch = trie1.into_patch();
    let first_root = collection.apply_increase(patch, child_collecting);

    let mut new_trie = collection.trie_for(first_root.root);
    for (key, value) in &second_entries.data {
        let val = new_trie.get(key);
        let key_root = val
            .map(|v| H256::from_slice(&v))
            .unwrap_or_else(empty_trie_hash);
        let mut inner_trie = collection.trie_for(key_root);
        for (k, value) in &value.data {
            inner_trie.insert(k, value.as_ref().unwrap())
        }
        let patch = inner_trie.into_patch();
        let g = collection.apply_increase(patch, no_childs);
        let root = g.leak_root();
        new_trie.insert(key, root.as_bytes());
    }
    let patch = new_trie.into_patch();
    let second_root = collection.apply_increase(patch, child_collecting);

    let new_trie = collection.trie_for(second_root.root);
    for (key, values) in &second_entries.data {
        let val = new_trie.get(key);
        let key_root = val
            .map(|v| H256::from_slice(&v))
            .unwrap_or_else(empty_trie_hash);
        let inner_trie = collection.trie_for(key_root);
        for (k, v) in &values.data {
            assert_eq!(&inner_trie.get(k), v)
        }
    }

    debug::draw(
        &collection.database,
        debug::Child::Hash(first_root.root),
        vec![],
        child_collecting,
    )
    .print();

    debug::draw(
        &collection.database,
        debug::Child::Hash(second_root.root),
        vec![],
        child_collecting,
    )
    .print();

    let changes = diff(
        &collection.database,
        child_collecting,
        first_root.root,
        second_root.root,
    )
    .unwrap();
    let (removes, inserts) = super::verify::tests::split_changes(changes.clone());
    // assert that there is no duplicates
    assert_eq!(removes.len() + inserts.len(), changes.len());

    let common: HashSet<H256> = removes.intersection(&inserts).copied().collect();
    assert!(common.is_empty());
}

#[test]
fn test_same_tree_inline() {
    tracing_sub_init();
    let first = json!([["0x70", "0x32"], ["0x70000030", "0x33"],]);

    let second = json!([
        [
            "0x70",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32"
        ],
        [
            "0x70000030",
            "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f33"
        ],
    ]);
    fn child_collecting(data: &[u8]) -> Vec<H256> {
        if data.len() == 32 {
            vec![H256::from_slice(data)]
        } else {
            vec![]
        }
    }
    let first_entries: debug::EntriesHex = serde_json::from_value(first).unwrap();
    let second_entries: debug::EntriesHex = serde_json::from_value(second).unwrap();

    let collection = TrieCollection::new(SyncDashMap::default());

    let mut trie1 = collection.trie_for(crate::empty_trie_hash());
    for (key, value) in &first_entries.data {
        trie1.insert(key, value.as_ref().unwrap());
    }
    let patch = trie1.into_patch();
    let first_root = collection.apply_increase(patch, child_collecting);

    let mut new_trie = collection.trie_for(first_root.root);
    for (key, value) in &second_entries.data {
        new_trie.insert(key, value.as_ref().unwrap());
    }
    let patch = new_trie.into_patch();
    let second_root = collection.apply_increase(patch, child_collecting);

    let new_trie = collection.trie_for(second_root.root);
    for (key, values) in &second_entries.data {
        assert_eq!(&new_trie.get(key), values)
    }

    debug::draw(
        &collection.database,
        debug::Child::Hash(first_root.root),
        vec![],
        child_collecting,
    )
    .print();

    debug::draw(
        &collection.database,
        debug::Child::Hash(second_root.root),
        vec![],
        child_collecting,
    )
    .print();

    let changes = diff(
        &collection.database,
        child_collecting,
        first_root.root,
        second_root.root,
    )
    .unwrap();
    let (removes, inserts) = super::verify::tests::split_changes(changes.clone());
    // assert that there is no duplicates
    assert_eq!(removes.len() + inserts.len(), changes.len());

    let common: HashSet<H256> = removes.intersection(&inserts).copied().collect();
    assert!(common.is_empty());
}
