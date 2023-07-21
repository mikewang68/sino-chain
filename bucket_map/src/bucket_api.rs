use {
    crate::{
        bucket::Bucket, 
        bucket_item::BucketItem, 
        bucket_map::BucketMapError,
        bucket_stats::BucketMapStats, MaxSearch, RefCount,
        index_entry::IndexEntry,
        bucket_storage::{BucketStorage, Uid, DEFAULT_CAPACITY_POW2, UID_UNLOCKED},
    },
    sdk::pubkey::Pubkey,
    std::{
        // ops::RangeBounds,
        collections::hash_map::DefaultHasher,
        path::PathBuf,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc, RwLock, RwLockWriteGuard,
        },
        hash::{Hash, Hasher},
    },
    core::ops::RangeBounds,
};

type LockedBucket<T> = RwLock<Option<Bucket<T>>>;
pub struct BucketApi<T: Clone + Copy> {
    drives: Arc<Vec<PathBuf>>,
    max_search: MaxSearch,
    pub stats: Arc<BucketMapStats>,

    bucket: LockedBucket<T>,
    count: Arc<AtomicU64>,
}

impl<T: Clone + Copy> BucketApi<T> {
    pub fn delete_key(&self, key: &Pubkey) {
        let mut bucket = self.get_write_bucket();
        if let Some(bucket) = bucket.as_mut() {
            bucket.delete_key(key)
        }
    }

    fn bucket_find_entry<'a>(
        index: &'a BucketStorage,
        key: &Pubkey,
        random: u64,
    ) -> Option<(&'a IndexEntry, u64)> {
        let ix = Self::bucket_index_ix(index, key, random);
        for i in ix..ix + index.max_search() {
            let ii = i % index.capacity();
            if index.uid(ii) == UID_UNLOCKED {
                continue;
            }
            let elem: &IndexEntry = index.get(ii);
            if elem.key == *key {
                return Some((elem, ii));
            }
        }
        None
    }

    fn bucket_index_ix(index: &BucketStorage, key: &Pubkey, random: u64) -> u64 {
        let uid = IndexEntry::key_uid(key);
        let mut s = DefaultHasher::new();
        uid.hash(&mut s);
        //the locally generated random will make it hard for an attacker
        //to deterministically cause all the pubkeys to land in the same
        //location in any bucket on all validators
        random.hash(&mut s);
        let ix = s.finish();
        ix % index.capacity()
        //debug!(            "INDEX_IX: {:?} uid:{} loc: {} cap:{}",            key,            uid,            location,            index.capacity()        );
    }

    pub fn update<F>(&self, key: &Pubkey, updatefn: F)
    where
        F: FnMut(Option<(&[T], RefCount)>) -> Option<(Vec<T>, RefCount)>,
    {
        let mut bucket = self.get_write_bucket();
        bucket.as_mut().unwrap().update(key, updatefn)
    }

    /// Get the items for bucket
    pub fn items_in_range<R>(&self, range: &Option<&R>) -> Vec<BucketItem<T>>
    where
        R: RangeBounds<Pubkey>,
    {
        self.bucket
            .read()
            .unwrap()
            .as_ref()
            .map(|bucket| bucket.items_in_range(range))
            .unwrap_or_default()
    }

        /// Get the values for Pubkey `key`
    pub fn read_value(&self, key: &Pubkey) -> Option<(Vec<T>, RefCount)> {
        self.bucket.read().unwrap().as_ref().and_then(|bucket| {
            bucket
                .read_value(key)
                .map(|(value, ref_count)| (value.to_vec(), ref_count))
        })
    }

    pub fn try_write(
        &self,
        pubkey: &Pubkey,
        value: (&[T], RefCount),
    ) -> Result<(), BucketMapError> {
        let mut bucket = self.get_write_bucket();
        bucket.as_mut().unwrap().try_write(pubkey, value.0, value.1)
    }

    fn get_write_bucket(&self) -> RwLockWriteGuard<Option<Bucket<T>>> {
        let mut bucket = self.bucket.write().unwrap();
        if bucket.is_none() {
            *bucket = Some(Bucket::new(
                Arc::clone(&self.drives),
                self.max_search,
                Arc::clone(&self.stats),
            ));
        } else {
            let write = bucket.as_mut().unwrap();
            write.handle_delayed_grows();
            self.count.store(write.bucket_len(), Ordering::Relaxed);
        }
        bucket
    }

    pub fn new(
        drives: Arc<Vec<PathBuf>>,
        max_search: MaxSearch,
        stats: Arc<BucketMapStats>,
        count: Arc<AtomicU64>,
    ) -> Self {
        Self {
            drives,
            max_search,
            stats,
            bucket: RwLock::default(),
            count,
        }
    }

    pub fn grow(&self, err: BucketMapError) {
        // grows are special - they get a read lock and modify 'reallocated'
        // the grown changes are applied the next time there is a write lock taken
        if let Some(bucket) = self.bucket.read().unwrap().as_ref() {
            bucket.grow(err)
        }
    }

}