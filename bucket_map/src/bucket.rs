use {
    crate::{
        // bucket_item::BucketItem,
        bucket_map::BucketMapError,
        bucket_stats::BucketMapStats,
        bucket_storage::{
            BucketStorage, 
            Uid, 
            // DEFAULT_CAPACITY_POW2, UID_UNLOCKED
        },
        index_entry::IndexEntry,
        MaxSearch, RefCount,
    },
    rand::{thread_rng, Rng},
    measure::measure::Measure,
    sdk::pubkey::Pubkey,
    std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
        marker::PhantomData,
        ops::RangeBounds,
        path::PathBuf,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    },
};

/// A Header UID of 0 indicates that the header is unlocked
pub(crate) const UID_UNLOCKED: Uid = 0;
pub const DEFAULT_CAPACITY_POW2: u8 = 5;

// >= 2 instances of BucketStorage per 'bucket' in the bucket map. 1 for index, >= 1 for data
pub struct Bucket<T> {
    drives: Arc<Vec<PathBuf>>,
    //index
    pub index: BucketStorage,
    //random offset for the index
    random: u64,
    //storage buckets to store SlotSlice up to a power of 2 in len
    pub data: Vec<BucketStorage>,
    _phantom: PhantomData<T>,
    stats: Arc<BucketMapStats>,

    pub reallocated: Reallocated,
}

impl<T: Clone + Copy> Bucket<T> {
    pub fn read_value(&self, key: &Pubkey) -> Option<(&[T], RefCount)> {
        //debug!("READ_VALUE: {:?}", key);
        let (elem, _) = self.find_entry(key)?;
        elem.read_value(self)
    }

    pub fn find_entry(&self, key: &Pubkey) -> Option<(&IndexEntry, u64)> {
        Self::bucket_find_entry(&self.index, key, self.random)
    }

    fn bucket_find_entry_mut<'a>(
        index: &'a BucketStorage,
        key: &Pubkey,
        random: u64,
    ) -> Option<(&'a mut IndexEntry, u64)> {
        let ix = Self::bucket_index_ix(index, key, random);
        for i in ix..ix + index.max_search() {
            let ii = i % index.capacity();
            if index.uid(ii) == UID_UNLOCKED {
                continue;
            }
            let elem: &mut IndexEntry = index.get_mut(ii);
            if elem.key == *key {
                return Some((elem, ii));
            }
        }
        None
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

    pub fn try_write(
        &mut self,
        key: &Pubkey,
        data: &[T],
        ref_count: u64,
    ) -> Result<(), BucketMapError> {
        let best_fit_bucket = IndexEntry::data_bucket_from_num_slots(data.len() as u64);
        if self.data.get(best_fit_bucket as usize).is_none() {
            // fail early if the data bucket we need doesn't exist - we don't want the index entry partially allocated
            return Err(BucketMapError::DataNoSpace((best_fit_bucket, 0)));
        }
        let index_entry = self.find_entry_mut(key);
        let (elem, elem_ix) = match index_entry {
            None => {
                let ii = self.create_key(key)?;
                let elem: &mut IndexEntry = self.index.get_mut(ii);
                (elem, ii)
            }
            Some(res) => res,
        };
        elem.ref_count = ref_count;
        let elem_uid = self.index.uid(elem_ix);
        let bucket_ix = elem.data_bucket_ix();
        let current_bucket = &self.data[bucket_ix as usize];
        if best_fit_bucket == bucket_ix && elem.num_slots > 0 {
            // in place update
            let elem_loc = elem.data_loc(current_bucket);
            let slice: &mut [T] = current_bucket.get_mut_cell_slice(elem_loc, data.len() as u64);
            assert!(current_bucket.uid(elem_loc) == elem_uid);
            elem.num_slots = data.len() as u64;
            slice.clone_from_slice(data);
            Ok(())
        } else {
            // need to move the allocation to a best fit spot
            let best_bucket = &self.data[best_fit_bucket as usize];
            let cap_power = best_bucket.capacity_pow2;
            let cap = best_bucket.capacity();
            let pos = thread_rng().gen_range(0, cap);
            for i in pos..pos + self.index.max_search() {
                let ix = i % cap;
                if best_bucket.uid(ix) == UID_UNLOCKED {
                    let elem_loc = elem.data_loc(current_bucket);
                    if elem.num_slots > 0 {
                        current_bucket.free(elem_loc, elem_uid);
                    }
                    elem.storage_offset = ix;
                    elem.storage_capacity_when_created_pow2 = best_bucket.capacity_pow2;
                    elem.num_slots = data.len() as u64;
                    //debug!(                        "DATA ALLOC {:?} {} {} {}",                        key, elem.data_location, best_bucket.capacity, elem_uid                    );
                    if elem.num_slots > 0 {
                        best_bucket.allocate(ix, elem_uid).unwrap();
                        let slice = best_bucket.get_mut_cell_slice(ix, data.len() as u64);
                        slice.copy_from_slice(data);
                    }
                    return Ok(());
                }
            }
            Err(BucketMapError::DataNoSpace((best_fit_bucket, cap_power)))
        }
    }

    fn find_entry_mut(&self, key: &Pubkey) -> Option<(&mut IndexEntry, u64)> {
        Self::bucket_find_entry_mut(&self.index, key, self.random)
    }

    fn create_key(&self, key: &Pubkey) -> Result<u64, BucketMapError> {
        Self::bucket_create_key(&self.index, key, IndexEntry::key_uid(key), self.random)
    }

    /// if a bucket was resized previously with a read lock, then apply that resize now
    pub fn handle_delayed_grows(&mut self) {
        if self.reallocated.get_reallocated() {
            // swap out the bucket that was resized previously with a read lock
            let mut items = ReallocatedItems::default();
            std::mem::swap(&mut items, &mut self.reallocated.items.lock().unwrap());

            if let Some((random, bucket)) = items.index.take() {
                self.apply_grow_index(random, bucket);
            } else {
                // data bucket
                let (i, new_bucket) = items.data.take().unwrap();
                self.apply_grow_data(i as usize, new_bucket);
            }
        }
    }

    pub fn new(
        drives: Arc<Vec<PathBuf>>,
        max_search: MaxSearch,
        stats: Arc<BucketMapStats>,
    ) -> Self {
        let index = BucketStorage::new(
            Arc::clone(&drives),
            1,
            std::mem::size_of::<IndexEntry>() as u64,
            max_search,
            Arc::clone(&stats.index),
        );
        Self {
            random: thread_rng().gen(),
            drives,
            index,
            data: vec![],
            _phantom: PhantomData::default(),
            stats,
            reallocated: Reallocated::default(),
        }
    }

    pub fn bucket_len(&self) -> u64 {
        self.index.used.load(Ordering::Relaxed)
    }

    // fn bucket_find_entry_mut<'a>(
    //     index: &'a BucketStorage,
    //     key: &Pubkey,
    //     random: u64,
    // ) -> Option<(&'a mut IndexEntry, u64)> {
    //     let ix = Self::bucket_index_ix(index, key, random);
    //     for i in ix..ix + index.max_search() {
    //         let ii = i % index.capacity();
    //         if index.uid(ii) == UID_UNLOCKED {
    //             continue;
    //         }
    //         let elem: &mut IndexEntry = index.get_mut(ii);
    //         if elem.key == *key {
    //             return Some((elem, ii));
    //         }
    //     }
    //     None
    // }

    fn bucket_create_key(
        index: &BucketStorage,
        key: &Pubkey,
        elem_uid: Uid,
        random: u64,
    ) -> Result<u64, BucketMapError> {
        let ix = Self::bucket_index_ix(index, key, random);
        for i in ix..ix + index.max_search() {
            let ii = i % index.capacity();
            if index.uid(ii) != UID_UNLOCKED {
                continue;
            }
            index.allocate(ii, elem_uid).unwrap();
            let mut elem: &mut IndexEntry = index.get_mut(ii);
            elem.key = *key;
            // These will be overwritten after allocation by callers.
            // Since this part of the mmapped file could have previously been used by someone else, there can be garbage here.
            elem.ref_count = 0;
            elem.storage_offset = 0;
            elem.storage_capacity_when_created_pow2 = 0;
            elem.num_slots = 0;
            //debug!(                "INDEX ALLOC {:?} {} {} {}",                key, ii, index.capacity, elem_uid            );
            return Ok(ii);
        }
        Err(BucketMapError::IndexNoSpace(index.capacity_pow2))
    }

    pub fn apply_grow_index(&mut self, random: u64, index: BucketStorage) {
        self.random = random;
        self.index = index;
    }

    pub fn apply_grow_data(&mut self, ix: usize, bucket: BucketStorage) {
        if self.data.get(ix).is_none() {
            for i in self.data.len()..ix {
                // insert empty data buckets
                self.data.push(BucketStorage::new(
                    Arc::clone(&self.drives),
                    1 << i,
                    Self::elem_size(),
                    self.index.max_search,
                    Arc::clone(&self.stats.data),
                ))
            }
            self.data.push(bucket);
        } else {
            self.data[ix] = bucket;
        }
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

    fn elem_size() -> u64 {
        std::mem::size_of::<T>() as u64
    }

    /// grow the appropriate piece. Note this takes an immutable ref.
    /// The actual grow is set into self.reallocated and applied later on a write lock
    pub fn grow(&self, err: BucketMapError) {
        match err {
            BucketMapError::DataNoSpace((data_index, current_capacity_pow2)) => {
                //debug!("GROWING SPACE {:?}", (data_index, current_capacity_pow2));
                self.grow_data(data_index, current_capacity_pow2);
            }
            BucketMapError::IndexNoSpace(current_capacity_pow2) => {
                //debug!("GROWING INDEX {}", sz);
                self.grow_index(current_capacity_pow2);
            }
        }
    }

    /// grow a data bucket
    /// The application of the new bucket is deferred until the next write lock.
    pub fn grow_data(&self, data_index: u64, current_capacity_pow2: u8) {
        let new_bucket = BucketStorage::new_resized(
            &self.drives,
            self.index.max_search,
            self.data.get(data_index as usize),
            std::cmp::max(current_capacity_pow2 + 1, DEFAULT_CAPACITY_POW2),
            1 << data_index,
            Self::elem_size(),
            &self.stats.data,
        );
        self.reallocated.add_reallocation();
        let mut items = self.reallocated.items.lock().unwrap();
        items.data = Some((data_index, new_bucket));
    }

    pub fn grow_index(&self, current_capacity_pow2: u8) {
        if self.index.capacity_pow2 == current_capacity_pow2 {
            let mut m = Measure::start("grow_index");
            //debug!("GROW_INDEX: {}", current_capacity_pow2);
            let increment = 1;
            for i in increment.. {
                //increasing the capacity by ^4 reduces the
                //likelyhood of a re-index collision of 2^(max_search)^2
                //1 in 2^32
                let index = BucketStorage::new_with_capacity(
                    Arc::clone(&self.drives),
                    1,
                    std::mem::size_of::<IndexEntry>() as u64,
                    // *2 causes rapid growth of index buckets
                    self.index.capacity_pow2 + i, // * 2,
                    self.index.max_search,
                    Arc::clone(&self.stats.index),
                );
                let random = thread_rng().gen();
                let mut valid = true;
                for ix in 0..self.index.capacity() {
                    let uid = self.index.uid(ix);
                    if UID_UNLOCKED != uid {
                        let elem: &IndexEntry = self.index.get(ix);
                        let new_ix = Self::bucket_create_key(&index, &elem.key, uid, random);
                        if new_ix.is_err() {
                            valid = false;
                            break;
                        }
                        let new_ix = new_ix.unwrap();
                        let new_elem: &mut IndexEntry = index.get_mut(new_ix);
                        *new_elem = *elem;
                        /*
                        let dbg_elem: IndexEntry = *new_elem;
                        assert_eq!(
                            Self::bucket_find_entry(&index, &elem.key, random).unwrap(),
                            (&dbg_elem, new_ix)
                        );
                        */
                    }
                }
                if valid {
                    let sz = index.capacity();
                    {
                        let mut max = self.stats.index.max_size.lock().unwrap();
                        *max = std::cmp::max(*max, sz);
                    }
                    let mut items = self.reallocated.items.lock().unwrap();
                    items.index = Some((random, index));
                    self.reallocated.add_reallocation();
                    break;
                }
            }
            m.stop();
            self.stats.index.resizes.fetch_add(1, Ordering::Relaxed);
            self.stats
                .index
                .resize_us
                .fetch_add(m.as_us(), Ordering::Relaxed);
        }
    }

}

#[derive(Default)]
pub struct Reallocated {
    /// > 0 if reallocations are encoded
    pub active_reallocations: AtomicUsize,

    /// actual reallocated bucket
    /// mutex because bucket grow code runs with a read lock
    pub items: Mutex<ReallocatedItems>,
}

impl Reallocated {
    /// Return true IFF a reallocation has occurred.
    /// Calling this takes conceptual ownership of the reallocation encoded in the struct.
    pub fn get_reallocated(&self) -> bool {
        self.active_reallocations
            .compare_exchange(1, 0, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// specify that a reallocation has occurred
    pub fn add_reallocation(&self) {
        assert_eq!(
            0,
            self.active_reallocations.fetch_add(1, Ordering::Relaxed),
            "Only 1 reallocation can occur at a time"
        );
    }
}

#[derive(Default)]
pub struct ReallocatedItems {
    // Some if the index was reallocated
    // u64 is random associated with the new index
    pub index: Option<(u64, BucketStorage)>,
    // Some for a data bucket reallocation
    // u64 is data bucket index
    pub data: Option<(u64, BucketStorage)>,
}

