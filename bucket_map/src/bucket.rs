use {
    crate::{
        // bucket_item::BucketItem,
        // bucket_map::BucketMapError,
        bucket_stats::BucketMapStats,
        bucket_storage::{
            BucketStorage, 
            // Uid, DEFAULT_CAPACITY_POW2, UID_UNLOCKED
        },
        // index_entry::IndexEntry,
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

#[derive(Default)]
pub struct Reallocated {
    /// > 0 if reallocations are encoded
    pub active_reallocations: AtomicUsize,

    /// actual reallocated bucket
    /// mutex because bucket grow code runs with a read lock
    pub items: Mutex<ReallocatedItems>,
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

