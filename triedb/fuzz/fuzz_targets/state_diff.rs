#![no_main]

use arbitrary::{Arbitrary, Error, Result, Unstructured};
use libfuzzer_sys::{arbitrary, fuzz_target};

#[derive(Copy, Clone, Eq, Hash, PartialEq, Debug)]
pub struct Key(pub [u8; 4]);
#[derive(Copy, Clone, Eq, Hash, PartialEq, Debug)]
pub struct FixedData(pub [u8; 32]);

use primitive_types::H256;
use std::collections::HashMap;
use triedb::debug::DebugPrintExt;

use triedb::gc::SyncDashMap;
use triedb::gc::TrieCollection;
use triedb::merkle::nibble::{into_key, Nibble};
use triedb::TrieMut;
use triedb::{debug, empty_trie_hash};
use triedb::{diff, verify_diff};

pub fn no_childs(_: &[u8]) -> Vec<H256> {
    vec![]
}

impl<'a> Arbitrary<'a> for Key {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        // Get an iterator of arbitrary `T`s.
        let nibble: Result<Vec<_>> = std::iter::from_fn(|| {
            Some(
                u.choose(&[
                    Nibble::N0,
                    Nibble::N3,
                    Nibble::N7,
                    Nibble::N11,
                    Nibble::N15,
                ])
                .map(|c| *c),
            )
        })
        .take(8)
        .collect();
        let mut key = [0; 4];

        let vec_data = into_key(&nibble?);
        assert_eq!(key.len(), vec_data.len());
        key.copy_from_slice(&vec_data);

        Ok(Key(key))
    }
}

impl<'a> Arbitrary<'a> for FixedData {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let mut fixed = [0; 32]; // increase possibility of conflict.

        fixed[0] = *u.choose(&[0xff, 0x01, 0x00, 0xee])?;

        Ok(FixedData(fixed))
    }
}

#[derive(Debug)]
pub struct MyArgs {
    changes: Vec<(Key, FixedData)>,

    changes2: Vec<(Key, FixedData)>,
}

impl<'a> Arbitrary<'a> for MyArgs {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let changes: Vec<(Key, FixedData)> = u.arbitrary()?;
        if changes.len() < 5 {
            return Err(Error::NotEnoughData);
        }

        let changes2: Vec<(Key, FixedData)> = u.arbitrary()?;
        if changes2.len() < 5 {
            return Err(Error::NotEnoughData);
        }

        Ok(MyArgs { changes, changes2 })
    }
}


fn test_state_diff(changes: Vec<(Key, FixedData)>, changes2: Vec<(Key, FixedData)>) {
    let _ = env_logger::Builder::new().parse_filters("error").try_init();
    let collection1 = TrieCollection::new(SyncDashMap::default());
    let collection2 = TrieCollection::new(SyncDashMap::default());

    // Insert first trie into collections
    let mut collection1_trie1 = collection1.trie_for(crate::empty_trie_hash());
    // create trie from 'changes' in both DBs
    for (key, value) in changes.iter() {
        collection1_trie1.insert(&key.0, &value.0);
    }
    let patch = collection1_trie1.into_patch();
    let collection1_trie1 = collection1.apply_increase(patch.clone(), no_childs);
    let _collection2_trie1 = collection2.apply_increase(patch, no_childs);

    debug::draw(
        &collection1.database,
        debug::Child::Hash(collection1_trie1.root),
        vec![],
        no_childs,
    )
    .print();

    // Insert second trie into first collection and into HashMap to be able to check results
    let mut kv_map: HashMap<Key, FixedData> = HashMap::new();
    let mut collection1_trie2 = collection1.trie_for(crate::empty_trie_hash());
    // create trie from 'changes2' in the first DB
    for (key, value) in changes2.iter() {
        kv_map.insert(*key, *value);
        collection1_trie2.insert(&key.0, &value.0);
    }
    let patch = collection1_trie2.into_patch();
    let collection1_trie2 = collection1.apply_increase(patch, no_childs);

    debug::draw(
        &collection1.database,
        debug::Child::Hash(collection1_trie2.root),
        vec![],
        no_childs,
    )
    .print();

    // Get diff between two tries in the first collection

    if collection1_trie1.root == collection1_trie2.root {
        return;
    }
    let changes = diff(
        &collection1.database,
        no_childs,
        collection1_trie1.root,
        collection1_trie2.root,
    )
    .unwrap();

    let verify_result = verify_diff(
        &collection2.database,
        collection1_trie2.root,
        changes,
        no_childs,
        true,
    );
    if let Err(x) = &verify_result {
        log::info!("{:?}", x);
    }
    assert!(verify_result.is_ok());

    // Apply changes over the initial trie in the second collection
    let apply_result = collection2.apply_diff_patch(verify_result.unwrap(), no_childs);
    assert!(apply_result.is_ok());

    // Compare contents of HashMap and final trie in the second collection
    let trie = collection2.trie_for(collection1_trie2.root);
    for (key, value) in kv_map {
        assert_eq!(&value.0[..], &TrieMut::get(&trie, &key.0).unwrap());
    }
}

fuzz_target!(|arg: MyArgs| { test_state_diff(arg.changes, arg.changes2) });
