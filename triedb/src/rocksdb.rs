//! RocksDB adaptor for TrieDB.

//use asterix to avoid unresolved import https://github.com/rust-analyzer/rust-analyzer/issues/7459#issuecomment-907714513
use derivative::*;
use std::borrow::Borrow;

use crate::{
    cache::{Cache, SyncCache},
    merkle::MerkleNode,
};

use log::*;
use primitive_types::H256;
use rlp::Rlp;
use rocksdb_lib::{
    ColumnFamily, DBAccess, MergeOperands, OptimisticTransactionDB, ReadOptions, Transaction,
};

// We use optimistica transaction, to allow regular `get` operation execute without lock timeouts.
pub type DB = OptimisticTransactionDB;
use crate::{
    cache::CachedHandle,
    gc::{DbCounter, ReachableHashes},
    CachedDatabaseHandle,
};

const EXCLUSIVE: bool = true;

#[derive(Derivative)]
#[derivative(Debug)]
pub struct RocksDatabaseHandleGC<'a, D> {
    db: D,

    #[derivative(Debug = "ignore")]
    counter_cf: Option<&'a ColumnFamily>,
}

impl<'a, D> RocksDatabaseHandleGC<'a, D> {
    pub fn new(db: D, counter_cf: &'a ColumnFamily) -> Self {
        RocksDatabaseHandleGC {
            db,
            counter_cf: counter_cf.into(),
        }
    }
    pub fn without_counter(db: D) -> Self {
        RocksDatabaseHandleGC {
            db,
            counter_cf: None,
        }
    }

    pub fn remove_counter(
        &self,
        b: &mut Transaction<DB>,
        key: H256,
    ) -> Result<(), rocksdb_lib::Error> {
        if let Some(counter_cf) = self.counter_cf {
            b.delete_cf(counter_cf, key)?
        }
        Ok(())
    }

    pub fn create_counter(
        &self,
        b: &mut Transaction<DB>,
        key: H256,
    ) -> Result<(), rocksdb_lib::Error> {
        if let Some(counter_cf) = self.counter_cf {
            if b.get_for_update_cf(counter_cf, key, EXCLUSIVE)?.is_none() {
                b.put_cf(counter_cf, key, serialize_counter(0))?
            }
        }
        Ok(())
    }

    pub fn increase_atomic(&self, key: H256) -> Result<(), rocksdb_lib::Error>
    where
        D: Borrow<DB>,
    {
        if let Some(counter_cf) = self.counter_cf {
            self.db
                .borrow()
                .merge_cf(counter_cf, key.as_ref(), serialize_counter(1))?
        }
        Ok(())
    }
    pub fn decrease_atomic(&self, key: H256) -> Result<(), rocksdb_lib::Error>
    where
        D: Borrow<DB>,
    {
        if let Some(counter_cf) = self.counter_cf {
            self.db
                .borrow()
                .merge_cf(counter_cf, key.as_ref(), serialize_counter(-1))?
        }
        Ok(())
    }
    pub fn increase(&self, b: &mut Transaction<DB>, key: H256) -> Result<(), rocksdb_lib::Error> {
        if let Some(counter_cf) = self.counter_cf {
            let mut value = self.get_counter_in_tx(b, key)?;
            value += 1;
            b.put_cf(counter_cf, key.as_ref(), serialize_counter(value))?;
            trace!("increase node {}=>{}", key, value);
        }
        Ok(())
    }
    pub fn decrease(&self, b: &mut Transaction<DB>, key: H256) -> Result<i64, rocksdb_lib::Error> {
        if let Some(counter_cf) = self.counter_cf {
            let mut value = self.get_counter_in_tx(b, key)?;
            value -= 1;
            b.put_cf(counter_cf, key.as_ref(), serialize_counter(value))?;
            trace!("decrease node {}=>{}", key, value);
            return Ok(value);
        }
        Ok(1) // report one reference remaining, to report that this is not latest link
    }
    pub fn get_counter_in_tx(
        &self,
        b: &mut Transaction<DB>,
        key: H256,
    ) -> Result<i64, rocksdb_lib::Error> {
        if let Some(counter_cf) = self.counter_cf {
            b.get_for_update_cf(counter_cf, key.as_ref(), EXCLUSIVE)
                .map(|s| s.map(|s| deserialize_counter(&s)).unwrap_or_default())
        } else {
            Ok(1) // report two, to make sure that after decrement there still will be atleast one reference
        }
    }
}

pub fn merge_counter(
    key: &[u8],
    existing_val: Option<&[u8]>,
    operands: &MergeOperands,
) -> Option<Vec<u8>> {
    let mut val = existing_val.map(deserialize_counter).unwrap_or_default();
    assert_eq!(key.len(), 32);
    for op in operands.iter() {
        let diff = deserialize_counter(op);
        // this assertion is incorrect because rocks can merge multiple values into one.
        // assert!(diff == -1 || diff == 1);
        val += diff;
    }
    Some(serialize_counter(val).to_vec())
}
fn serialize_counter(counter: i64) -> [u8; 8] {
    counter.to_le_bytes()
}

fn deserialize_counter(counter: &[u8]) -> i64 {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(counter);
    i64::from_le_bytes(bytes)
}

impl<'a, D: Borrow<DB>> CachedDatabaseHandle for RocksDatabaseHandleGC<'a, D> {
    fn get(&self, key: H256) -> Vec<u8> {
        self.db
            .borrow()
            .get(key.as_ref())
            .expect("Error on reading database")
            .unwrap_or_else(|| panic!("Value for {:?} not found in database", key))
    }
}

/// Retry is used because optimistic transactions can fail if other thread change some value.
macro_rules! retry {
    {$($tokens:tt)*} => {
        const NUM_RETRY: usize = 500; // ~10ms-100ms
        #[allow(unused_mut)]
        let mut retry = move || -> Result<_, anyhow::Error> {
            let result = { $($tokens)* };
            Ok(result)
        };
        let mut e = None; //use option because rust think that this variable can be uninit
        for retry_count in 0..NUM_RETRY {
            e = Some(retry().map(|v|(v, retry_count)));
            match e.as_ref().unwrap() {
                Ok(_) => break,
                Err(e) => log::trace!("Error during transaction execution retry_count:{} reason:{}", retry_count + 1,  e)

            }
        }
        let (result, num_retry) = e.unwrap()
        .expect(&format!("Failed to retry operation for {} times", NUM_RETRY));
        if num_retry > 1 && num_retry < NUM_RETRY - 1 { log::warn!("Error transaction execution failed multiple time retry_count:{}", num_retry + 1)}
        result

    };
}

// `counter_cf: Option<&'a ColumnFamily>` as is doesn't allow type to become `Sync`
pub struct RocksDatabaseHandle<'a, D> {
    db: &'a D,
}

impl<'a, D> RocksDatabaseHandle<'a, D> {
    pub fn new(db: &'a D) -> Self {
        RocksDatabaseHandle { db }
    }
}

impl<'a, D: DBAccess> CachedDatabaseHandle for RocksDatabaseHandle<'a, D> {
    fn get(&self, key: H256) -> Vec<u8> {
        self.db
            .get_opt(key.as_ref(), &ReadOptions::default())
            .expect("Error on reading database")
            .unwrap_or_else(|| panic!("Value for {:?} not found in database", key))
    }
}

pub type RocksHandle<'a, D> = CachedHandle<RocksDatabaseHandleGC<'a, D>, Cache>;
pub type SyncRocksHandle<'a, D> = CachedHandle<RocksDatabaseHandle<'a, D>, SyncCache>;

impl<'a, D, C> DbCounter for CachedHandle<RocksDatabaseHandleGC<'a, D>, C>
where
    D: Borrow<DB>,
{
    // Insert value into db.
    // Check if value exist before, if not exist, increment child counter.
    fn gc_insert_node<F>(&self, key: H256, value: &[u8], mut child_extractor: F)
    where
        F: FnMut(&[u8]) -> Vec<H256>,
    {
        let rlp = Rlp::new(value);
        let node = MerkleNode::decode(&rlp).expect("Data should be decodable node");
        let childs = ReachableHashes::collect(&node, &mut child_extractor).childs();
        retry! {
            let db = self.db.db.borrow();
            let mut tx = db.transaction();
            // let mut write_batch = WriteBatch::default();
            if tx
                .get_for_update(key.as_ref(), EXCLUSIVE)
                .map_err(|e| anyhow::format_err!("Cannot get key {}", e))?
                .is_none()
            {
                trace!("inserting node {}=>{:?}", key, node);
                for hash in childs.0.iter().chain(&childs.1) {
                    self.db.increase(&mut tx, *hash)?;
                }

                tx.put(key.as_ref(), value)?;
                self.db.create_counter(&mut tx, key)?;
                tx.commit()?;
            }
        }
    }
    fn gc_count(&self, key: H256) -> usize {
        let db = self.db.db.borrow();
        let mut tx = db.transaction();
        self.db
            .get_counter_in_tx(&mut tx, key)
            .expect("Cannot read value") as usize
    }

    // Return true if node data is exist, and it counter more than 0;
    fn node_exist(&self, key: H256) -> bool {
        self.db
            .db
            .borrow()
            .get(key.as_ref())
            .unwrap_or_default()
            .is_some()
            && self.gc_count(key) > 0
    }

    // atomic operation:
    // 1. check if key counter didn't increment in other thread.
    // 2. remove key if counter == 0.
    // 3. find all childs
    // 4. decrease child counters
    // 5. return list of childs with counter == 0
    fn gc_try_cleanup_node<F>(&self, key: H256, mut child_extractor: F) -> (Vec<H256>, Vec<H256>)
    where
        F: FnMut(&[u8]) -> Vec<H256>,
    {
        let db = self.db.db.borrow();
        if self.db.counter_cf.is_none() {
            return (vec![], vec![]);
        };

        let mut orig_nodes = (Vec::with_capacity(16), Vec::new());

        let nodes = &mut orig_nodes;
        // To make second retry execute faster, cache child keys.
        let mut cached_childs = None;
        trace!("try removing node {}", key);
        retry! {
            //TODO: retry
            nodes.0.clear();
            nodes.1.clear();

            let mut tx = db.transaction();
            if let Some(value) = tx.get_for_update(key.as_ref(), EXCLUSIVE)? {
                let count = self.db.get_counter_in_tx(&mut tx, key)?;
                if count > 0 {
                    trace!("ignore removing node {}, counter: {}", key, count);
                    return Ok(());
                }
                tx.delete(key.as_ref())?;
                self.db.remove_counter(&mut tx, key)?;


                let childs = cached_childs.take().unwrap_or_else(||{
                    let rlp = Rlp::new(&value);
                    let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
                    ReachableHashes::collect(&node, &mut child_extractor).childs()
                });

                for hash in childs.0.iter(){
                    let child_count = self.db.decrease(&mut tx, *hash)?;
                    if child_count <= 0 {
                        nodes.0.push(*hash);
                    }
                }
                for hash in childs.1.iter(){
                    let child_count = self.db.decrease(&mut tx, *hash)?;
                    if child_count <= 0 {
                        nodes.1.push(*hash);
                    }
                }
                cached_childs = Some(childs);

                tx.commit()?;
            }
            ()
        }
        orig_nodes
    }

    fn gc_pin_root(&self, key: H256) {
        trace!("Pin root:{}", key);
        retry! {
            let db = self.db.db.borrow();
            let mut tx = db.transaction();
            self.db.increase(&mut tx, key)?;
            tx.commit()?;
        }
    }

    fn gc_unpin_root(&self, key: H256) -> bool {
        trace!("Unpin root:{}", key);
        retry! {
            let db = self.db.db.borrow();
            let mut tx = db.transaction();
            self.db.decrease(&mut tx, key)?;
            tx.commit()?;
            self.gc_count(key) == 0
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};
    use std::fmt::Write as _;
    use std::io::Write;
    use std::sync::Arc;

    use crate::debug::child_extractor::DataWithRoot;
    use crate::gc::TrieCollection;
    use crate::merkle::MerkleNode;
    use hex_literal::hex;
    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;
    use rlp::Rlp;
    use rocksdb_lib::IteratorMode;
    use rocksdb_lib::{ColumnFamilyDescriptor, Options};
    use tempfile::tempdir;

    use super::*;
    use crate::gc::tests::{FixedData, FixedKey};
    use crate::gc::RootGuard;
    use crate::impls::tests::{Data, K};
    use crate::mutable::TrieMut;
    use crate::ops::debug::tests::*;
    use crate::Database;

    pub type YetAnotherDB = rocksdb_lib::DBWithThreadMode<rocksdb_lib::SingleThreaded>;

    fn no_childs(_: &[u8]) -> Vec<H256> {
        vec![]
    }

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

    #[test]
    fn it_counts_childs_as_expected_and_cleanup_correctly() {
        let key1 = &hex!("bbaa");
        let key2 = &hex!("ffaa");
        let key3 = &hex!("bbcc");

        // make data too long for inline
        let value1 = b"same data________________________";
        let value2 = b"same data________________________";
        let value3 = b"other data_______________________";
        let value3_1 = b"changed data_____________________";
        let value2_1 = b"changed data_____________________";

        let dir = tempdir().unwrap();
        let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
        let db = DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap();

        let cf = db.cf_handle("counter").unwrap();

        let collection = TrieCollection::new(RocksHandle::new(RocksDatabaseHandleGC::new(&db, cf)));

        let mut trie = collection.trie_for(crate::empty_trie_hash());
        trie.insert(key1, value1);
        trie.insert(key2, value2);
        trie.insert(key3, value3);
        let patch = trie.into_patch();
        assert_eq!(collection.database.gc_count(patch.root), 0);
        let root_guard = collection.apply_increase(patch, no_childs);
        assert_eq!(collection.database.gc_count(root_guard.root), 1);

        // CHECK CHILDS counts
        println!("root={}", root_guard.root);
        let node = collection.database.get(root_guard.root);
        let rlp = Rlp::new(node);
        let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
        let childs = ReachableHashes::collect(&node, no_childs).childs();
        assert_eq!(childs.0.len(), 2); // "bb..", "ffaa", check test doc comments

        for child in &childs.0 {
            assert_eq!(collection.database.gc_count(*child), 1);
        }

        let mut trie = collection.trie_for(root_guard.root);
        assert_eq!(TrieMut::get(&trie, key1), Some(value1.to_vec()));
        assert_eq!(TrieMut::get(&trie, key2), Some(value2.to_vec()));
        assert_eq!(TrieMut::get(&trie, key3), Some(value3.to_vec()));

        trie.insert(key3, value3_1);
        assert_eq!(TrieMut::get(&trie, key3), Some(value3_1.to_vec()));
        let patch = trie.into_patch();

        assert_eq!(collection.database.gc_count(patch.root), 0);
        let another_root_guard = collection.apply_increase(patch, no_childs);
        assert_eq!(collection.database.gc_count(another_root_guard.root), 1);

        let node = collection.database.get(another_root_guard.root);
        let rlp = Rlp::new(node);
        let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
        let another_root_childs = ReachableHashes::collect(&node, no_childs).childs();
        assert_eq!(another_root_childs.0.len(), 2); // "bb..", "ffaa", check test doc comments

        let first_set: BTreeSet<_> = childs.0.into_iter().collect();
        let another_set: BTreeSet<_> = another_root_childs.0.into_iter().collect();

        let diff_child: Vec<_> = another_set.intersection(&first_set).collect();
        assert_eq!(diff_child.len(), 1);

        assert_eq!(collection.database.gc_count(*diff_child[0]), 2);

        for child in first_set.symmetric_difference(&another_set) {
            assert_eq!(collection.database.gc_count(*child), 1);
        }

        // Adding one dublicate

        let mut trie = collection.trie_for(another_root_guard.root);

        // adding dublicate value should not affect RC
        trie.insert(key1, value1);

        let patch = trie.into_patch();
        assert_eq!(patch.root, another_root_guard.root);

        // adding one more changed element, and make additional conflict.

        let mut trie = collection.trie_for(another_root_guard.root);

        trie.insert(key2, value2_1);

        let patch = trie.into_patch();

        let latest_root_guard = collection.apply_increase(patch, no_childs);

        collection.database.gc_pin_root(latest_root_guard.root);

        let node = collection.database.get(latest_root_guard.root);
        let rlp = Rlp::new(node);
        let node = MerkleNode::decode(&rlp).expect("Unable to decode Merkle Node");
        let latest_root_childs = ReachableHashes::collect(&node, no_childs).childs();
        assert_eq!(latest_root_childs.0.len(), 2); // "bb..", "ffaa", check test doc comments

        let latest_set: BTreeSet<_> = latest_root_childs.0.into_iter().collect();
        assert_eq!(latest_set.intersection(&first_set).count(), 0);

        // check only newest childs

        let diffs: Vec<_> = latest_set.difference(&another_set).collect();

        assert_eq!(diffs.len(), 1);
        for child in &diffs {
            assert_eq!(collection.database.gc_count(**child), 1);
        }

        let intersections: Vec<_> = latest_set.intersection(&another_set).collect();

        assert_eq!(intersections.len(), 1);
        for child in &intersections {
            assert_eq!(collection.database.gc_count(**child), 2);
        }

        // TRY cleanup first root.

        let root = root_guard.root;
        collection.database.gc_pin_root(root);
        drop(root_guard);
        assert!(collection.database.gc_unpin_root(root));

        let mut elems = collection.database.gc_cleanup_layer(&[root], no_childs).0;
        assert_eq!(elems.len(), 1);
        while !elems.is_empty() {
            // perform additional check, that all removed elements should be also removed from db.
            let cloned_elems = elems.clone();
            elems = collection.database.gc_cleanup_layer(&elems, no_childs).0;
            for child in cloned_elems {
                assert!(collection.database.db.db.get(child).unwrap().is_none());
            }
        }

        // this should not affect latest roots elements
        let sym_diffs: Vec<_> = latest_set.symmetric_difference(&another_set).collect();
        assert_eq!(sym_diffs.len(), 2);
        for child in &sym_diffs {
            assert_eq!(collection.database.gc_count(**child), 1);
        }

        assert_eq!(intersections.len(), 1);
        for child in &intersections {
            assert_eq!(collection.database.gc_count(**child), 2);
        }
        // but affect first root diffs
        assert_eq!(collection.database.gc_count(*diff_child[0]), 1);

        // and also remove all nodes from first root
        let first_root_keys: Vec<_> = first_set.difference(&another_set).collect();
        assert_eq!(first_root_keys.len(), 1);
        for child in first_root_keys {
            assert_eq!(collection.database.gc_count(*child), 0);

            assert!(collection.database.db.db.get(child).unwrap().is_none());
        }
    }

    #[quickcheck]
    fn qc_handles_several_key_changes(
        kvs_1: HashMap<FixedKey, FixedData>,
        kvs_2: HashMap<FixedKey, FixedData>,
    ) -> TestResult {
        if kvs_1.is_empty() || kvs_2.is_empty() {
            return TestResult::discard();
        }

        let dir = tempdir().unwrap();
        let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
        let db = DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap();

        let cf = db.cf_handle("counter").unwrap();

        let collection = TrieCollection::new(RocksHandle::new(RocksDatabaseHandleGC::new(&db, cf)));

        let mut root = crate::empty_trie_hash();
        let mut roots = Vec::new();

        for (k, data) in kvs_1.iter() {
            let mut trie = collection.trie_for(root);
            trie.insert(&k.0, &data.0);

            let patch = trie.into_patch();
            let root_guard = collection.apply_increase(patch, no_childs);
            root = root_guard.root;
            roots.push(root_guard);
        }

        let last_root_guard = roots.pop().unwrap();

        // perform cleanup of all intermediate roots
        drop(roots);

        // expect for kvs to be available
        let trie = collection.trie_for(root);
        for k in kvs_1.keys() {
            assert_eq!(&kvs_1[k].0[..], &TrieMut::get(&trie, &k.0).unwrap());
        }

        let mut roots = Vec::new();

        for (k, data) in kvs_2.iter() {
            let mut trie = collection.trie_for(root);
            trie.insert(&k.0, &data.0);
            let patch = trie.into_patch();
            let root_guard = collection.apply_increase(patch, no_childs);
            root = root_guard.root;
            roots.push(root_guard);
        }

        let second_collection_root_guard = roots.pop().unwrap();
        // perform cleanup of all intermediate roots
        drop(roots);

        let trie = collection.trie_for(last_root_guard.root);
        for k in kvs_1.keys() {
            assert_eq!(&kvs_1[k].0[..], &TrieMut::get(&trie, &k.0).unwrap());
        }

        let trie = collection.trie_for(second_collection_root_guard.root);
        for k in kvs_2.keys() {
            assert_eq!(&kvs_2[k].0[..], &TrieMut::get(&trie, &k.0).unwrap());
        }

        drop(last_root_guard);
        drop(second_collection_root_guard);

        use rocksdb_lib::IteratorMode;
        assert_eq!(db.iterator(IteratorMode::Start).count(), 0);

        println!("Debug cf");

        for item in db.iterator_cf(cf, IteratorMode::Start) {
            let (k, v) = item.unwrap();
            println!("{:?}=>{:?}", hexutil::to_hex(&k), hexutil::to_hex(&v))
        }
        assert_eq!(db.iterator_cf(cf, IteratorMode::Start).count(), 0);

        TestResult::passed()
    }

    #[test]
    #[should_panic]
    fn test_secondary_open_panic() {
        let dir = tempdir().unwrap();
        let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
        let _db = DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap();

        let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
        let _second_db = DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap();
    }

    #[test]
    fn test_secondary_open_should_not_panic() {
        let dir = tempdir().unwrap();
        let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
        let _db = DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap();

        let secondary_path = dir.as_ref().join("secondary");
        let _second_db = YetAnotherDB::open_cf_as_secondary(
            &default_opts(),
            dir.as_ref(),
            secondary_path.as_path(),
            ["counter"],
        )
        .unwrap();
    }
    #[test]
    fn test_secondary_open_keys() {
        let _ = env_logger::Builder::new().parse_filters("info").try_init();
        let key1 = &hex!("bbaa");
        let key2 = &hex!("ffaa");
        let key3 = &hex!("bbcc");

        // make data too long for inline
        let value1 = b"same data________________________";
        let value2 = b"same data________________________";
        let value3 = b"other data_______________________";

        let dir = tempdir().unwrap();
        let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
        let db = DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap();

        let cf = db.cf_handle("counter").unwrap();

        let rocks_handle_primary = RocksHandle::new(RocksDatabaseHandleGC::new(&db, cf));
        let collection = TrieCollection::new(rocks_handle_primary);

        let mut trie = collection.trie_for(crate::empty_trie_hash());
        trie.insert(key1, value1);
        trie.insert(key2, value2);
        trie.insert(key3, value3);
        let patch = trie.into_patch();
        let root_guard = collection.apply_increase(patch, no_childs);
        root_guard.leak_root();
        drop(collection);

        let keys: Vec<_> = [
            "0xdf42730b6b88285f489aecc74b2a2abf13c46464a4607115a8d6810d7450441b",
            "0x8a5ffd47c08a95606dbb1f6c1304c84ebac07e4fb190d5429f73ccd9d892df6a",
            "0xdf7d03aafaec7d2728cea82903cac520546254151519d9a46803051918cdaf82",
            "0xf94d27f6720120a25a9fcf0e2e7677cd0aa15b780b9caa51952e6a90d33236fa",
            "0xcbbdeaee35b1a04fb30f96d496584cb187c1a6c79183bb08ed2976278c324870",
            "0x8dfaead6d8e85b86daed51bae8f4b870aaabc7bb1ff3210660a7c282237e4321",
        ]
        .iter()
        .map(|string| H256::from_slice(&hexutil::read_hex(string).unwrap()))
        .collect();
        let rocks_handle_primary = RocksHandle::new(RocksDatabaseHandleGC::new(&db, cf));

        let secondary_path = dir.as_ref().join("secondary");
        let second_db = YetAnotherDB::open_cf_as_secondary(
            &default_opts(),
            dir.as_ref(),
            secondary_path.as_path(),
            ["counter"],
        )
        .unwrap();
        let rocks_handle_secondary = SyncRocksHandle::new(RocksDatabaseHandle::new(&second_db));
        for key in keys.clone() {
            assert_eq!(
                rocks_handle_primary.get(key),
                rocks_handle_secondary.get(key)
            );
        }

        rocks_handle_primary.get(keys[0]);
    }

    // todo implement data with child collection.
    #[quickcheck]
    fn qc_handles_inner_roots(
        alice_key: FixedKey,
        alice_chages: Vec<(FixedKey, FixedData)>,
        bob_key: FixedKey,
        bob_storage: HashMap<FixedKey, FixedData>,
    ) -> TestResult {
        qc_handles_inner_roots_body(alice_key, alice_chages, bob_key, bob_storage)
    }

    fn qc_handles_inner_roots_body(
        alice_key: FixedKey,
        alice_chages: Vec<(FixedKey, FixedData)>,
        bob_key: FixedKey,
        bob_storage: HashMap<FixedKey, FixedData>,
    ) -> TestResult {
        if alice_chages.is_empty() || bob_storage.is_empty() {
            return TestResult::discard();
        }

        let dir = tempdir().unwrap();
        let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
        let db = DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap();

        let cf = db.cf_handle("counter").unwrap();

        let collection = TrieCollection::new(RocksHandle::new(RocksDatabaseHandleGC::new(&db, cf)));

        let mut top_level_root = collection.empty_guard(DataWithRoot::get_childs);

        let mut alice_storage_mem = HashMap::new();
        {
            for (k, data) in alice_chages.iter() {
                alice_storage_mem.insert(*k, *data);

                let mut account_trie = collection.trie_for(top_level_root.root);

                let mut alice_account: DataWithRoot = TrieMut::get(&account_trie, &alice_key.0)
                    .map(|d| bincode::deserialize(&d).unwrap())
                    .unwrap_or_default();

                let mut storage_trie = collection.trie_for(alice_account.root);
                storage_trie.insert(&k.0, &data.0);

                let storage_patch = storage_trie.into_patch();

                alice_account.root = storage_patch.root;

                account_trie.insert(&alice_key.0, &bincode::serialize(&alice_account).unwrap());

                let mut account_patch = account_trie.into_patch();

                account_patch.change.merge_child(&storage_patch.change);
                top_level_root = collection.apply_increase(account_patch, DataWithRoot::get_childs);
            }
        };

        {
            for (k, data) in bob_storage.iter() {
                let mut account_trie = collection.trie_for(top_level_root.root);

                let mut bob_account: DataWithRoot = TrieMut::get(&account_trie, &bob_key.0)
                    .map(|d| bincode::deserialize(&d).unwrap())
                    .unwrap_or_default();

                let mut storage_trie = collection.trie_for(bob_account.root);
                storage_trie.insert(&k.0, &data.0);

                let storage_patch = storage_trie.into_patch();

                bob_account.root = storage_patch.root;

                account_trie.insert(&bob_key.0, &bincode::serialize(&bob_account).unwrap());

                let mut account_patch = account_trie.into_patch();

                account_patch.change.merge_child(&storage_patch.change);
                top_level_root = collection.apply_increase(account_patch, DataWithRoot::get_childs);
            }
        };

        let accounts_storage = collection.trie_for(top_level_root.root);
        let alice_account: DataWithRoot =
            bincode::deserialize(&TrieMut::get(&accounts_storage, &alice_key.0).unwrap()).unwrap();
        let bob_account: DataWithRoot =
            bincode::deserialize(&TrieMut::get(&accounts_storage, &bob_key.0).unwrap()).unwrap();

        let alice_storage_trie = collection.trie_for(alice_account.root);
        for k in alice_storage_mem.keys() {
            assert_eq!(
                &alice_storage_mem[k].0[..],
                &TrieMut::get(&alice_storage_trie, &k.0).unwrap()
            );
        }

        let bob_storage_trie = collection.trie_for(bob_account.root);
        for k in bob_storage.keys() {
            assert_eq!(
                &bob_storage[k].0[..],
                &TrieMut::get(&bob_storage_trie, &k.0).unwrap()
            );
        }

        // check cleanup db
        drop(top_level_root);

        println!("Debug DB");
        for item in db.iterator(IteratorMode::Start) {
            let (k, v) = item.unwrap();
            println!("{:?}=>{:?}", hexutil::to_hex(&k), hexutil::to_hex(&v))
        }
        assert_eq!(db.iterator(IteratorMode::Start).count(), 0);

        println!("Debug cf");
        for item in db.iterator_cf(cf, IteratorMode::Start) {
            let (k, v) = item.unwrap();
            println!("{:?}=>{:?}", hexutil::to_hex(&k), hexutil::to_hex(&v))
        }
        assert_eq!(db.iterator_cf(cf, IteratorMode::Start).count(), 0);

        TestResult::passed()
    }

    #[test]
    fn test_from_qc() {
        tracing_sub_init();
        let mut bob_storage = HashMap::new();
        bob_storage.insert(
            FixedKey([127, 3, 123, 251]),
            FixedData([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
        );

        let alice_changes = vec![(
            FixedKey([119, 55, 15, 0]),
            FixedData([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
        )];

        qc_handles_inner_roots_body(
            FixedKey([123, 127, 55, 115]),
            alice_changes,
            FixedKey([247, 7, 176, 187]),
            bob_storage,
        );
    }

    #[quickcheck]
    fn qc_handles_several_roots_via_gc(
        kvs_1: HashMap<K, Data>,
        kvs_2: HashMap<K, Data>,
    ) -> TestResult {
        if kvs_1.is_empty() || kvs_2.is_empty() {
            return TestResult::discard();
        }
        let dir = tempdir().unwrap();
        let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
        let db = DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap();

        let cf = db.cf_handle("counter").unwrap();

        let collection = TrieCollection::new(RocksHandle::new(RocksDatabaseHandleGC::new(&db, cf)));

        let mut root = crate::empty_trie_hash();
        let mut root_guards = vec![];

        for (k, data) in kvs_1.iter() {
            let mut trie = collection.trie_for(root);
            trie.insert(&k.to_bytes(), &bincode::serialize(data).unwrap());

            let patch = trie.into_patch();
            let root_guard = collection.apply_increase(patch, no_childs);
            root = root_guard.root;

            root_guards.push(root_guard);
        }

        let mut root_guard = root_guards.pop().unwrap();

        drop(root_guards);
        // expect for kvs to be available
        let trie = collection.trie_for(root);
        for k in kvs_1.keys() {
            assert_eq!(
                kvs_1[k],
                bincode::deserialize(&TrieMut::get(&trie, &k.to_bytes()).unwrap()).unwrap()
            );
        }

        for (k, data) in kvs_2.iter() {
            let mut trie = collection.trie_for(root);
            trie.insert(&k.to_bytes(), &bincode::serialize(data).unwrap());
            let patch = trie.into_patch();
            root_guard = collection.apply_increase(patch, no_childs);
            root = root_guard.root;
        }

        let trie = collection.trie_for(root);
        for k in kvs_2.keys() {
            assert_eq!(
                kvs_2[k],
                bincode::deserialize(&TrieMut::get(&trie, &k.to_bytes()).unwrap()).unwrap()
            );
        }

        drop(root_guard);

        assert_eq!(db.iterator(IteratorMode::Start).count(), 0);

        println!("Debug cf");
        for item in db.iterator_cf(cf, IteratorMode::Start) {
            let (k, v) = item.unwrap();
            println!("{:?}=>{:?}", hexutil::to_hex(&k), hexutil::to_hex(&v))
        }
        assert_eq!(db.iterator_cf(cf, IteratorMode::Start).count(), 0);

        TestResult::passed()
    }

    #[test]
    fn two_threads_conflict() {
        let _ = env_logger::Builder::new().parse_filters("trace").try_init();
        let dir = tempdir().unwrap();
        let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
        let shared_db =
            Arc::new(DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap());

        fn routine(db: std::sync::Arc<DB>) {
            let cf = db.cf_handle("counter").unwrap();
            let collection =
                TrieCollection::new(RocksHandle::new(RocksDatabaseHandleGC::new(&*db, cf)));

            let key1 = &hex!("bbaa");
            let key2 = &hex!("ffaa");
            let key3 = &hex!("bbcc");

            // make data too long for inline
            let value1 = b"same data________________________";
            let value2 = b"same data________________________";
            let value3 = b"other data_______________________";
            let value3_1 = b"changed data_____________________";
            let mut trie = collection.trie_for(crate::empty_trie_hash());
            trie.insert(key1, value1);
            trie.insert(key2, value2);
            trie.insert(key3, value3);
            let patch = trie.into_patch();
            let mut root_guard = collection.apply_increase(patch, no_childs);

            let mut trie = collection.trie_for(root_guard.root);
            assert_eq!(TrieMut::get(&trie, key1), Some(value1.to_vec()));
            assert_eq!(TrieMut::get(&trie, key2), Some(value2.to_vec()));
            assert_eq!(TrieMut::get(&trie, key3), Some(value3.to_vec()));

            trie.insert(key3, value3_1);
            assert_eq!(TrieMut::get(&trie, key3), Some(value3_1.to_vec()));
            let patch = trie.into_patch();

            root_guard = collection.apply_increase(patch, no_childs);

            let mut trie = collection.trie_for(root_guard.root);
            assert_eq!(TrieMut::get(&trie, key1), Some(value1.to_vec()));
            assert_eq!(TrieMut::get(&trie, key2), Some(value2.to_vec()));
            assert_eq!(TrieMut::get(&trie, key3), Some(value3_1.to_vec()));

            trie.delete(key2);
            let patch = trie.into_patch();
            root_guard = collection.apply_increase(patch, no_childs);

            let trie = collection.trie_for(root_guard.root);

            assert_eq!(TrieMut::get(&trie, key2), None);
        }

        let cloned_db = shared_db.clone();
        let th1 = std::thread::spawn(move || {
            for _i in 0..100 {
                routine(cloned_db.clone())
            }
        });
        let cloned_db = shared_db.clone();
        let th2 = std::thread::spawn(move || {
            for _i in 0..100 {
                routine(cloned_db.clone())
            }
        });
        th1.join().unwrap();
        th2.join().unwrap();

        let cf = shared_db.cf_handle("counter").unwrap();
        assert_eq!(shared_db.iterator(IteratorMode::Start).count(), 0);

        for item in shared_db.iterator_cf(cf, IteratorMode::Start) {
            let (k, v) = item.unwrap();
            println!("{:?}=>{:?}", hexutil::to_hex(&k), hexutil::to_hex(&v))
        }
        assert_eq!(shared_db.iterator_cf(cf, IteratorMode::Start).count(), 0);
    }

    #[test]
    fn two_threads_data_from_fuzz() {
        let hex_0 = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let hex_1 = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let hex_238 = [
            238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        let hex_255 = [
            238, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        let changes1 = vec![
            (
                FixedKey([119, 0, 0, 3]),
                vec![
                    (FixedKey([11, 119, 0, 119]), FixedData(hex_1)),
                    (FixedKey([3, 51, 51, 183]), FixedData(hex_1)),
                    (FixedKey([0, 0, 255, 240]), FixedData(hex_1)),
                    (FixedKey([255, 255, 255, 255]), FixedData(hex_238)),
                    (FixedKey([255, 255, 255, 255]), FixedData(hex_238)),
                    (FixedKey([0, 0, 7, 55]), FixedData(hex_238)),
                ],
            ),
            (
                FixedKey([112, 7, 119, 0]),
                vec![
                    (FixedKey([51, 51, 183, 112]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 48]), FixedData(hex_238)),
                    (FixedKey([112, 119, 0, 0]), FixedData(hex_238)),
                    (FixedKey([255, 255, 255, 255]), FixedData(hex_238)),
                    (FixedKey([255, 255, 240, 48]), FixedData(hex_238)),
                    (FixedKey([3, 112, 183, 112]), FixedData(hex_238)),
                    (FixedKey([119, 0, 51, 51]), FixedData(hex_238)),
                ],
            ),
            (
                FixedKey([112, 0, 0, 0]),
                vec![
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 240, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 11, 119]), FixedData(hex_238)),
                    (FixedKey([0, 48, 0, 0]), FixedData(hex_1)),
                ],
            ),
            (
                FixedKey([0, 0, 55, 11]),
                vec![
                    (FixedKey([112, 7, 119, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 3, 0]), FixedData(hex_238)),
                    (FixedKey([7, 112, 0, 0]), FixedData(hex_238)),
                    (FixedKey([255, 255, 255, 255]), FixedData(hex_238)),
                    (FixedKey([255, 255, 3, 0]), FixedData(hex_238)),
                    (FixedKey([55, 11, 119, 0]), FixedData(hex_1)),
                    (FixedKey([112, 3, 51, 51]), FixedData(hex_0)),
                    (FixedKey([112, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 15, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 183, 112]), FixedData(hex_238)),
                    (FixedKey([3, 0, 0, 3]), FixedData(hex_255)),
                    (FixedKey([0, 0, 0, 7]), FixedData(hex_1)),
                    (FixedKey([11, 119, 7, 15]), FixedData(hex_0)),
                ],
            ),
            (
                FixedKey([112, 0, 0, 0]),
                vec![
                    (FixedKey([112, 119, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 48, 0]), FixedData(hex_238)),
                    (FixedKey([7, 112, 0, 0]), FixedData(hex_238)),
                    (FixedKey([7, 7, 0, 7]), FixedData(hex_1)),
                    (FixedKey([119, 119, 247, 176]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_1)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                ],
            ),
        ];
        let changes2 = vec![
            (
                FixedKey([15, 0, 0, 0]),
                vec![
                    (FixedKey([0, 11, 119, 0]), FixedData(hex_238)),
                    (FixedKey([48, 0, 0, 48]), FixedData(hex_238)),
                    (FixedKey([0, 3, 112, 183]), FixedData(hex_1)),
                    (FixedKey([15, 187, 0, 0]), FixedData(hex_255)),
                    (FixedKey([0, 3, 0, 7]), FixedData(hex_238)),
                    (FixedKey([112, 0, 0, 255]), FixedData(hex_238)),
                    (FixedKey([255, 255, 255, 255]), FixedData(hex_238)),
                    (FixedKey([255, 3, 0, 0]), FixedData(hex_1)),
                    (FixedKey([11, 119, 0, 119]), FixedData(hex_1)),
                    (FixedKey([3, 51, 51, 183]), FixedData(hex_1)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([15, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 183, 112, 0]), FixedData(hex_238)),
                ],
            ),
            (
                FixedKey([0, 0, 48, 0]),
                vec![
                    (FixedKey([0, 0, 7, 0]), FixedData(hex_238)),
                    (FixedKey([112, 119, 119, 247]), FixedData(hex_0)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([123, 176, 15, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 183]), FixedData(hex_1)),
                    (FixedKey([0, 3, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 55]), FixedData(hex_238)),
                ],
            ),
            (
                FixedKey([112, 7, 119, 0]),
                vec![
                    (FixedKey([0, 0, 0, 48]), FixedData(hex_238)),
                    (FixedKey([112, 119, 0, 0]), FixedData(hex_238)),
                    (FixedKey([255, 255, 255, 255]), FixedData(hex_238)),
                    (FixedKey([255, 255, 240, 48]), FixedData(hex_238)),
                    (FixedKey([3, 112, 183, 112]), FixedData(hex_238)),
                    (FixedKey([119, 0, 51, 51]), FixedData(hex_238)),
                ],
            ),
            (
                FixedKey([112, 0, 0, 0]),
                vec![
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 240, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 11, 119]), FixedData(hex_238)),
                    (FixedKey([0, 48, 0, 0]), FixedData(hex_1)),
                ],
            ),
            (
                FixedKey([0, 0, 0, 0]),
                vec![
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([119, 112, 183, 112]), FixedData(hex_1)),
                    (FixedKey([255, 240, 112, 0]), FixedData(hex_238)),
                    (FixedKey([0, 7, 7, 112]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 3]), FixedData(hex_238)),
                    (FixedKey([0, 0, 119, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 119, 176]), FixedData(hex_238)),
                    (FixedKey([119, 7, 119, 183]), FixedData(hex_1)),
                    (FixedKey([0, 0, 0, 0]), FixedData(hex_238)),
                    (FixedKey([0, 0, 0, 3]), FixedData(hex_238)),
                    (FixedKey([0, 0, 11, 119]), FixedData(hex_238)),
                    (FixedKey([119, 112, 3, 51]), FixedData(hex_238)),
                    (FixedKey([183, 112, 0, 0]), FixedData(hex_0)),
                ],
            ),
        ];

        fn routine(db: std::sync::Arc<DB>, changes: Vec<(FixedKey, Vec<(FixedKey, FixedData)>)>) {
            let cf = db.cf_handle("counter").unwrap();
            let collection =
                TrieCollection::new(RocksHandle::new(RocksDatabaseHandleGC::new(&*db, cf)));

            let mut top_level_root = RootGuard::new(
                &collection.database,
                crate::empty_trie_hash(),
                DataWithRoot::get_childs,
            );

            let mut accounts_map: HashMap<FixedKey, HashMap<FixedKey, FixedData>> = HashMap::new();
            {
                for (k, storage) in changes.iter() {
                    let account_storage_mem =
                        accounts_map.entry(*k).or_insert_with(HashMap::default);

                    for (data_key, data) in storage {
                        let mut account_trie = collection.trie_for(top_level_root.root);

                        let mut account: DataWithRoot = TrieMut::get(&account_trie, &k.0)
                            .map(|d| bincode::deserialize(&d).unwrap())
                            .unwrap_or_default();
                        let mut storage_trie = collection.trie_for(account.root);
                        account_storage_mem.insert(*data_key, *data);

                        storage_trie.insert(&data_key.0, &data.0);

                        let storage_patch = storage_trie.into_patch();
                        account.root = storage_patch.root;

                        account_trie.insert(&k.0, &bincode::serialize(&account).unwrap());

                        let mut account_patch = account_trie.into_patch();

                        let mut roots = String::new();
                        for (key, v) in storage_patch.change.changes.iter().rev() {
                            write!(roots, "=>{}({})", key, v.is_some() as i32).unwrap();
                        }
                        trace!("storage_root:{}", roots);
                        let mut roots = String::new();
                        for (key, v) in account_patch.change.changes.iter().rev() {
                            write!(roots, "=>{}({})", key, v.is_some() as i32).unwrap();
                        }
                        trace!("account_root:{}", roots);
                        account_patch.change.merge_child(&storage_patch.change);

                        let mut roots = String::new();
                        for (key, v) in account_patch.change.changes.iter().rev() {
                            write!(roots, "=>{}({})", key, v.is_some() as i32).unwrap();
                        }
                        trace!("full_root:{}", roots);

                        top_level_root =
                            collection.apply_increase(account_patch, DataWithRoot::get_childs);
                    }
                }
            };

            let accounts_storage = collection.trie_for(top_level_root.root);

            // println!("accounts_map = {}", accounts_map.len());
            for (bob_key, storage) in accounts_map {
                // println!("storage_len = {}", storage.len());
                let bob_account: DataWithRoot =
                    bincode::deserialize(&TrieMut::get(&accounts_storage, &bob_key.0).unwrap())
                        .unwrap();

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

        let _ = env_logger::Builder::new()
            .parse_filters("trace")
            .format(|buf, record| {
                let handle = std::thread::current();
                writeln!(
                    buf,
                    "[{}]{}=>{}",
                    record.target(),
                    handle.name().unwrap_or_default(),
                    record.args()
                )
            })
            .try_init();
        let dir = tempdir().unwrap();
        let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
        let db = DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap();
        let db = std::sync::Arc::new(db);
        let cloned_db = db.clone();
        let th1 = std::thread::Builder::new()
            .name("1".into())
            .spawn(move || {
                for _ in 0..100 {
                    routine(cloned_db.clone(), changes1.clone())
                }
            })
            .unwrap();
        let cloned_db = db.clone();
        let th2 = std::thread::Builder::new()
            .name("2".into())
            .spawn(move || {
                for _ in 0..100 {
                    routine(cloned_db.clone(), changes2.clone())
                }
            })
            .unwrap();
        th1.join().unwrap();
        th2.join().unwrap();

        // let changestested = vec![(
        //     Key([15, 0, 0, 0]),
        //     vec![
        //         (Key([0, 11, 119, 0]), FixedData(hex_238)),
        //         (Key([48, 0, 0, 48]), FixedData(hex_238)),
        //         (Key([0, 3, 112, 183]), FixedData(hex_1)),
        //     ],
        // )];
        // routine(cloned_db.clone(), changestested.clone());

        let cf = db.cf_handle("counter").unwrap();
        assert_eq!(db.iterator(IteratorMode::Start).count(), 0);

        for item in db.iterator_cf(cf, IteratorMode::Start) {
            let (k, v) = item.unwrap();
            println!("{:?}=>{:?}", hexutil::to_hex(&k), hexutil::to_hex(&v))
        }
        assert_eq!(db.iterator_cf(cf, IteratorMode::Start).count(), 0);
    }
}
