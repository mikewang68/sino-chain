use {
    crate::{
        accounts_index::{
            AccountMapEntry, 
            IndexValue,
        },
        bucket_map_holder::{Age, BucketMapHolder},
        bucket_map_holder_stats::BucketMapHolderStats,
    },
    measure::measure::Measure,
    bucket_map::bucket_api::BucketApi,
    sdk::{clock::Slot, pubkey::Pubkey},
    std::{
        collections::{
            HashMap,
        },
        fmt::Debug,
        ops::{RangeInclusive},
        sync::{
            atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
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

impl<T: IndexValue> InMemAccountsIndex<T> {
    pub fn new(storage: &Arc<BucketMapHolder<T>>, bin: usize) -> Self {
        Self {
            map_internal: RwLock::default(),
            storage: Arc::clone(storage),
            bin,
            bucket: storage
                .disk
                .as_ref()
                .map(|disk| disk.get_bucket_from_index(bin))
                .map(Arc::clone),
            cache_ranges_held: CacheRangesHeld::default(),
            stop_flush: AtomicU64::default(),
            bin_dirty: AtomicBool::default(),
            flushing_active: AtomicBool::default(),
            // initialize this to max, to make it clear we have not flushed at age 0, the starting age
            last_age_flushed: AtomicU8::new(Age::MAX),
        }
    }

    pub(crate) fn flush(&self) {
        let flushing = self.flushing_active.swap(true, Ordering::Acquire);
        if flushing {
            // already flushing in another thread
            return;
        }

        self.flush_internal();

        self.flushing_active.store(false, Ordering::Release);
    }

    fn flush_internal(&self) {
        let was_dirty = self.bin_dirty.swap(false, Ordering::Acquire);
        let current_age = self.storage.current_age();
        let mut iterate_for_age = self.get_should_age(current_age);
        let startup = self.storage.get_startup();
        if !was_dirty && !iterate_for_age && !startup {
            // wasn't dirty and no need to age, so no need to flush this bucket
            // but, at startup we want to remove from buckets as fast as possible if any items exist
            return;
        }

        // may have to loop if disk has to grow and we have to restart
        loop {
            let mut removes;
            let mut removes_random = Vec::default();
            let disk = self.bucket.as_ref().unwrap();

            let mut flush_entries_updated_on_disk = 0;
            let mut disk_resize = Ok(());
            // scan and update loop
            // holds read lock
            {
                let map = self.map().read().unwrap();
                removes = Vec::with_capacity(map.len());
                let m = Measure::start("flush_scan_and_update"); // we don't care about lock time in this metric - bg threads can wait
                for (k, v) in map.iter() {
                    if self.should_remove_from_mem(current_age, v, startup, true) {
                        removes.push(*k);
                    } else if Self::random_chance_of_eviction() {
                        removes_random.push(*k);
                    } else {
                        // not planning to remove this item from memory now, so don't write it to disk yet
                        continue;
                    }

                    // if we are removing it, then we need to update disk if we're dirty
                    if v.clear_dirty() {
                        // step 1: clear the dirty flag
                        // step 2: perform the update on disk based on the fields in the entry
                        // If a parallel operation dirties the item again - even while this flush is occurring,
                        //  the last thing the writer will do, after updating contents, is set_dirty(true)
                        //  That prevents dropping an item from cache before disk is updated to latest in mem.
                        // happens inside of lock on in-mem cache. This is because of deleting items
                        // it is possible that the item in the cache is marked as dirty while these updates are happening. That is ok.
                        disk_resize =
                            disk.try_write(k, (&v.slot_list.read().unwrap(), v.ref_count()));
                        if disk_resize.is_ok() {
                            flush_entries_updated_on_disk += 1;
                        } else {
                            // disk needs to resize, so mark all unprocessed items as dirty again so we pick them up after the resize
                            v.set_dirty(true);
                            break;
                        }
                    }
                }
                Self::update_time_stat(&self.stats().flush_scan_update_us, m);
            }
            Self::update_stat(
                &self.stats().flush_entries_updated_on_disk,
                flush_entries_updated_on_disk,
            );

            let m = Measure::start("flush_remove_or_grow");
            match disk_resize {
                Ok(_) => {
                    if !self.flush_remove_from_cache(removes, current_age, startup, false)
                        || !self.flush_remove_from_cache(removes_random, current_age, startup, true)
                    {
                        iterate_for_age = false; // did not make it all the way through this bucket, so didn't handle age completely
                    }
                    Self::update_time_stat(&self.stats().flush_remove_us, m);

                    if iterate_for_age {
                        // completed iteration of the buckets at the current age
                        assert_eq!(current_age, self.storage.current_age());
                        self.set_has_aged(current_age);
                    }
                    return;
                }
                Err(err) => {
                    // grow the bucket, outside of all in-mem locks.
                    // then, loop to try again
                    disk.grow(err);
                    Self::update_time_stat(&self.stats().flush_grow_us, m);
                }
            }
        }
    }

    /// true if this bucket needs to call flush for the current age
    /// we need to scan each bucket once per value of age
    fn get_should_age(&self, age: Age) -> bool {
        let last_age_flushed = self.last_age_flushed();
        last_age_flushed != age
    }

    fn map(&self) -> &RwLock<HashMap<Pubkey, AccountMapEntry<T>>> {
        &self.map_internal
    }

    /// return true if 'entry' should be removed from the in-mem index
    fn should_remove_from_mem(
        &self,
        current_age: Age,
        entry: &AccountMapEntry<T>,
        startup: bool,
        update_stats: bool,
    ) -> bool {
        // this could be tunable dynamically based on memory pressure
        // we could look at more ages or we could throw out more items we are choosing to keep in the cache
        if startup || (current_age == entry.age()) {
            // only read the slot list if we are planning to throw the item out
            let slot_list = entry.slot_list.read().unwrap();
            if slot_list.len() != 1 {
                if update_stats {
                    Self::update_stat(&self.stats().held_in_mem_slot_list_len, 1);
                }
                false // keep 0 and > 1 slot lists in mem. They will be cleaned or shrunk soon.
            } else {
                // keep items with slot lists that contained cached items
                let remove = !slot_list.iter().any(|(_, info)| info.is_cached());
                if !remove && update_stats {
                    Self::update_stat(&self.stats().held_in_mem_slot_list_cached, 1);
                }
                remove
            }
        } else {
            false
        }
    }
    
    fn random_chance_of_eviction() -> bool {
        // random eviction
        const N: usize = 1000;
        // 1/N chance of eviction
        thread_rng().gen_range(0, N) == 0
    }

}
