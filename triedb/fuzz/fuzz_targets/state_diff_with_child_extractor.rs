#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use libfuzzer_sys::{arbitrary, fuzz_target};

#[derive(Copy, Clone, Eq, Hash, PartialEq, Debug)]
pub struct Key(pub [u8; 4]);
#[derive(Copy, Clone, Eq, Hash, PartialEq, Debug)]
pub struct FixedData(pub [u8; 32]);

use triedb::debug::DebugPrintExt;
use triedb::debug::child_extractor::DataWithRoot;
use std::collections::HashMap;

use triedb::{empty_trie_hash, debug};

use triedb::gc::SyncDashMap;
use triedb::gc::{RootGuard, TrieCollection};
use triedb::merkle::nibble::{into_key, Nibble};

use triedb::TrieMut;
use triedb::{diff, verify_diff};

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
    changes: Vec<(Key, Vec<(Key, FixedData)>)>,

    changes2: Vec<(Key, Vec<(Key, FixedData)>)>,
}

impl<'a> Arbitrary<'a> for MyArgs {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let mut changes: Vec<(Key, Vec<(Key, FixedData)>)> = vec![];
        let mut changes2: Vec<(Key, Vec<(Key, FixedData)>)> = vec![];

        for _ in 0..3 {
            let account: Key = u.arbitrary()?;
            let mut storage = vec![];
            for _ in 0..3 {
                let key: Key = u.arbitrary()?;
                let val: FixedData = u.arbitrary()?;
                storage.push((key, val));
            }
            changes.push((account, storage))
        }

        for _ in 0..3 {
            let account: Key = u.arbitrary()?;
            let mut storage = vec![];
            for _ in 0..3 {
                let key: Key = u.arbitrary()?;
                let val: FixedData = u.arbitrary()?;
                storage.push((key, val));
            }
            changes2.push((account, storage))
        }



        Ok(MyArgs { changes, changes2 })
    }
}

fn test_state_diff(
    changes: Vec<(Key, Vec<(Key, FixedData)>)>,
    changes2: Vec<(Key, Vec<(Key, FixedData)>)>,
) {
    let _ = env_logger::Builder::new().parse_filters("error").try_init();
    let collection1 = TrieCollection::new(SyncDashMap::default());
    let collection2 = TrieCollection::new(SyncDashMap::default());

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
    let mut _collection2_trie1 = RootGuard::new(
        &collection2.database,
        crate::empty_trie_hash(),
        DataWithRoot::get_childs,
    );

    // Insert first trie into collections
    for (account_key, storage) in changes.iter() {
        for (data_key, data) in storage {
            {
                collection1_trie1 = debug::child_extractor::insert_element(
                    &collection1,
                    &account_key.0,
                    &data_key.0,
                    &data.0,
                    collection1_trie1.root,
                    DataWithRoot::get_childs,
                );
            }
            {
                _collection2_trie1 = debug::child_extractor::insert_element(
                    &collection2,
                    &account_key.0,
                    &data_key.0,
                    &data.0,
                    _collection2_trie1.root,
                    DataWithRoot::get_childs,
                );
            }
        }
    }

    // Insert second trie into first collection and into HashMap to be able to check results
    let mut accounts_map: HashMap<Key, HashMap<Key, FixedData>> = HashMap::new();

    for (account_key, storage) in changes2.iter() {
        let account_updates = accounts_map.entry(*account_key).or_default();
        for (data_key, data) in storage {
            account_updates.insert(*data_key, *data);
        }
    }
    for (account_key, storage) in changes2.iter() {

        for (data_key, data) in storage {
            {
                collection1_trie2 = debug::child_extractor::insert_element(
                    &collection1,
                    &account_key.0,
                    &data_key.0,
                    &data.0,
                    collection1_trie2.root,
                    DataWithRoot::get_childs,
                );
            }
        }
    }
    debug::draw(
        &collection1.database,
        debug::Child::Hash(collection1_trie1.root),
        vec![],
        DataWithRoot::get_childs,
    )
    .print();

    debug::draw(
        &collection1.database,
        debug::Child::Hash(collection1_trie2.root),
        vec![],
        DataWithRoot::get_childs,
    )
    .print();

    if collection1_trie1.root == collection1_trie2.root {
        return;
    }
    // Get diff between two tries in the first collection
    let changes = diff(
        &collection1.database,
        DataWithRoot::get_childs,
        collection1_trie1.root,
        collection1_trie2.root,
    )
    .unwrap();

    let verify_result = verify_diff(
        &collection2.database,
        collection1_trie2.root,
        changes,
        DataWithRoot::get_childs,
        true,
    );
    if let Err(x) = &verify_result {
        log::error!("{:?}", x);
    }
    assert!(verify_result.is_ok());
    // Apply changes over the initial trie in the second collection
    let apply_result = collection2.apply_diff_patch(verify_result.unwrap(), DataWithRoot::get_childs);
    assert!(apply_result.is_ok());

    // Compare contents of HashMap and final trie in the second collection
    let accounts_storage = collection2.trie_for(collection1_trie2.root);
    for (k, storage) in accounts_map {
        let account: DataWithRoot =
            bincode::deserialize(&TrieMut::get(&accounts_storage, &k.0).unwrap())
                .unwrap();

        let account_storage_trie = collection2.trie_for(account.root);
        for data_key in storage.keys() {
            assert_eq!(
                &storage[data_key].0[..],
                &TrieMut::get(&account_storage_trie, &data_key.0).unwrap()
            );
        }
    }
}

fuzz_target!(|arg: MyArgs| { test_state_diff(arg.changes, arg.changes2) });
