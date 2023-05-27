#![no_main]

use arbitrary::{Arbitrary, Error, Result, Unstructured};
use libfuzzer_sys::{arbitrary, fuzz_target};

#[derive(Copy, Clone, Eq, Hash, PartialEq, Debug)]
pub struct Key(pub [u8; 4]);
#[derive(Copy, Clone, Eq, Hash, PartialEq, Debug)]
pub struct FixedData(pub [u8; 32]);

use triedb::debug::child_extractor::DataWithRoot;
use std::collections::HashMap;
use tempfile::tempdir;
use triedb::empty_trie_hash;
use triedb::gc::{RootGuard, TrieCollection};
use triedb::merkle::nibble::{into_key, Nibble};
use triedb::rocksdb::{merge_counter, RocksDatabaseHandleGC, RocksHandle};
use triedb::rocksdb_lib::{ColumnFamilyDescriptor, IteratorMode, OptimisticTransactionDB, Options};
use triedb::TrieMut;
type DB = OptimisticTransactionDB;

fn default_opts() -> Options {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);
    opts
}

fn counter_cf_opts() -> Options {
    let mut opts = default_opts();
    opts.set_merge_operator_associative("inc_counter", merge_counter);
    opts
}

impl<'a> Arbitrary<'a> for Key {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        // Get an iterator of arbitrary `T`s.
        let nibble: Result<Vec<_>> = std::iter::from_fn(|| {
            Some(
                u.choose(&[Nibble::N0, Nibble::N3, Nibble::N7, Nibble::N11, Nibble::N15])
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

//         let nibble: Vec<_> = std::iter::from_fn(|| {
//             g.choose(&[Nibble::N0, Nibble::N3, Nibble::N7, Nibble::N11, Nibble::N15])
//                 .copied()
//         })
//         .take(4)
//         .collect();
//         let mut key = [0; 2];

//         let vec_data = into_key(&nibble);
//         assert_eq!(key.len(), vec_data.len());
//         key.copy_from_slice(&vec_data);

//         Self(key)
//     }
// }

// /// RLP encoded data should be more or equal 32 bytes, this prevent node data to be inlined.
// /// There is two kind of datas, 1st byte == 0xff and == 0x00, remaining always stay 0x00
// #[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Eq, Debug)]
// pub struct FixedData(pub [u8; 32]);

// impl Arbitrary for FixedData {
//     fn arbitrary(g: &mut Gen) -> Self {
//         let mut fixed = [0; 32]; // increase possibility of conflict.
//         if <bool>::arbitrary(g) {
//             fixed[0] = 0xff
//         }
//         Self(fixed)
//     }

#[derive(Debug)]
pub struct MyArgs {
    changes: Vec<(Key, Vec<(Key, FixedData)>)>,

    changes2: Vec<(Key, Vec<(Key, FixedData)>)>,
}

impl<'a> Arbitrary<'a> for MyArgs {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let changes: Vec<(Key, Vec<(Key, FixedData)>)> = u.arbitrary()?;
        if changes.len() < 5 {
            return Err(Error::NotEnoughData);
        }
        for change in &changes {
            if change.1.len() < 5 {
                return Err(Error::NotEnoughData);
            }
        }

        let changes2: Vec<(Key, Vec<(Key, FixedData)>)> = u.arbitrary()?;
        if changes2.len() < 5 {
            return Err(Error::NotEnoughData);
        }
        for change in &changes2 {
            if change.1.len() < 5 {
                return Err(Error::NotEnoughData);
            }
        }

        Ok(MyArgs { changes, changes2 })
    }
}

fuzz_target!(|arg: MyArgs| { qc_handles_inner_roots(arg.changes, arg.changes2) });


fn routine(db: std::sync::Arc<DB>, changes: Vec<(Key, Vec<(Key, FixedData)>)>) {
    let cf = db.cf_handle("counter").unwrap();
    let collection = TrieCollection::new(RocksHandle::new(RocksDatabaseHandleGC::new(&*db, cf)));

    let mut top_level_root = RootGuard::new(
        &collection.database,
        crate::empty_trie_hash(),
        DataWithRoot::get_childs,
    );

    let mut accounts_map: HashMap<Key, HashMap<Key, FixedData>> = HashMap::new();
    {
        for (k, storage) in changes.iter() {
            let account_updates = accounts_map.entry(*k).or_insert(HashMap::default());

            for (data_key, data) in storage {
                let mut account_trie = collection.trie_for(top_level_root.root);

                let mut account: DataWithRoot = TrieMut::get(&account_trie, &k.0)
                    .map(|d| bincode::deserialize(&d).unwrap())
                    .unwrap_or_default();
                let mut storage_trie = collection.trie_for(account.root);
                account_updates.insert(*data_key, *data);
                storage_trie.insert(&data_key.0, &data.0);

                let storage_patch = storage_trie.into_patch();
                account.root = storage_patch.root;

                account_trie.insert(&k.0, &bincode::serialize(&account).unwrap());

                let mut account_patch = account_trie.into_patch();

                account_patch.change.merge_child(&storage_patch.change);

                top_level_root = collection.apply_increase(account_patch, DataWithRoot::get_childs);
            }
        }
    };

    let accounts_storage = collection.trie_for(top_level_root.root);

    // println!("accounts_map = {}", accounts_map.len());
    for (bob_key, storage) in accounts_map {
        // println!("storage_len = {}", storage.len());
        let bob_account: DataWithRoot =
            bincode::deserialize(&TrieMut::get(&accounts_storage, &bob_key.0).unwrap()).unwrap();

        let bob_storage_trie = collection.trie_for(bob_account.root);
        for k in storage.keys() {
            assert_eq!(
                &storage[k].0[..],
                &TrieMut::get(&bob_storage_trie, &k.0).unwrap()
            );
        }
    }
    // check cleanup db
    drop(top_level_root);
}

fn qc_handles_inner_roots(
    changes: Vec<(Key, Vec<(Key, FixedData)>)>,
    changes2: Vec<(Key, Vec<(Key, FixedData)>)>,
) {
    let _ = env_logger::Builder::new().parse_filters("warn").try_init();
    let dir = tempdir().unwrap();
    let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
    let db = DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap();
    let db = std::sync::Arc::new(db);
    let cloned_db = db.clone();
    let th1 = std::thread::spawn(move || routine(cloned_db, changes));
    let cloned_db = db.clone();
    let th2 = std::thread::spawn(move || routine(cloned_db, changes2));
    th1.join().unwrap();
    th2.join().unwrap();

    let cf = db.cf_handle("counter").unwrap();
    assert_eq!(db.iterator(IteratorMode::Start).count(), 0);

    for item in db.iterator_cf(cf, IteratorMode::Start) {
        let (k, v) = item.unwrap();
        println!("{:?}=>{:?}", hexutil::to_hex(&k), hexutil::to_hex(&v))
    }
    assert_eq!(db.iterator_cf(cf, IteratorMode::Start).count(), 0);
}
