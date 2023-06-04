use {
    crate::{
        accounts_index::{
            AccountMapEntry, 
            IndexValue,
        },
        bucket_map_holder::{BucketMapHolder},
        // bucket_map_holder_stats::BucketMapHolderStats,
    },
    bucket_map::bucket_api::BucketApi,
    sdk::{clock::Slot, pubkey::Pubkey},
    std::{
        collections::{
            HashMap,
        },
        fmt::Debug,
        ops::{RangeInclusive},
        sync::{
            atomic::{AtomicBool, AtomicU64, AtomicU8},
            Arc, RwLock, 
        },
    },
};
type K = Pubkey;
type CacheRangesHeld = RwLock<Vec<Option<RangeInclusive<Pubkey>>>>;
pub type SlotT<T> = (Slot, T);


pub enum InsertNewEntryResults {
    DidNotExist,
    ExistedNewEntryZeroLamports,
    ExistedNewEntryNonZeroLamports,
}

#[allow(dead_code)] // temporary during staging
                    // one instance of this represents one bin of the accounts index.
pub struct InMemAccountsIndex<T: IndexValue> {
    last_age_flushed: AtomicU8,

    // backing store
    map_internal: RwLock<HashMap<Pubkey, AccountMapEntry<T>>>,
    storage: Arc<BucketMapHolder<T>>,
    bin: usize,

    bucket: Option<Arc<BucketApi<SlotT<T>>>>,

    // pubkey ranges that this bin must hold in the cache while the range is present in this vec
    pub(crate) cache_ranges_held: CacheRangesHeld,
    // true while ranges are being manipulated. Used to keep an async flush from removing things while a range is being held.
    stop_flush: AtomicU64,
    // set to true when any entry in this bin is marked dirty
    bin_dirty: AtomicBool,
    // set to true while this bin is being actively flushed
    flushing_active: AtomicBool,
}

impl<T: IndexValue> Debug for InMemAccountsIndex<T> {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}
