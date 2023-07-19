use {
    crate::{
        accounts_index::{
            AccountMapEntry, 
            AccountMapEntryInner,
            AccountMapEntryMeta,
            IndexValue,
        },
        bucket_map_holder::{Age, BucketMapHolder},
        bucket_map_holder_stats::BucketMapHolderStats,
    },
    rand::{thread_rng,Rng},
    measure::measure::Measure,
    bucket_map::bucket_api::BucketApi,
    sdk::{clock::Slot, pubkey::Pubkey},
    std::{
        collections::{
            hash_map::{Entry},
            HashMap,
        },
        fmt::Debug,
        ops::{RangeInclusive},
        sync::{
            atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
            Arc, RwLock, 
        },
    },
    core::ops::RangeBounds,
};
type K = Pubkey;
type CacheRangesHeld = RwLock<Vec<Option<RangeInclusive<Pubkey>>>>;
pub type SlotT<T> = (Slot, T);
pub type SlotList<T> = Vec<(Slot, T)>;
pub type RefCount = u64;

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
    pub fn items<R>(&self, range: &Option<&R>) -> Vec<(K, AccountMapEntry<T>)>
    where
        R: RangeBounds<Pubkey> + std::fmt::Debug,
    {
        self.start_stop_flush(true);
        self.put_range_in_cache(range); // check range here to see if our items are already held in the cache
        Self::update_stat(&self.stats().items, 1);
        let map = self.map().read().unwrap();
        let mut result = Vec::with_capacity(map.len());
        map.iter().for_each(|(k, v)| {
            if range.map(|range| range.contains(k)).unwrap_or(true) {
                result.push((*k, Arc::clone(v)));
            }
        });
        self.start_stop_flush(false);
        result
    }

    fn put_range_in_cache<R>(&self, range: &Option<&R>)
    where
        R: RangeBounds<Pubkey>,
    {
        assert!(self.get_stop_flush()); // caller should be controlling the lifetime of how long this needs to be present
        let m = Measure::start("range");

        // load from disk
        if let Some(disk) = self.bucket.as_ref() {
            let mut map = self.map().write().unwrap();
            let items = disk.items_in_range(range); // map's lock has to be held while we are getting items from disk
            let future_age = self.storage.future_age_to_flush();
            for item in items {
                let entry = map.entry(item.pubkey);
                match entry {
                    Entry::Occupied(occupied) => {
                        // item already in cache, bump age to future. This helps the current age flush to succeed.
                        occupied.get().set_age(future_age);
                    }
                    Entry::Vacant(vacant) => {
                        vacant.insert(self.disk_to_cache_entry(item.slot_list, item.ref_count));
                        self.stats().insert_or_delete_mem(true, self.bin);
                    }
                }
            }
        }

        Self::update_time_stat(&self.stats().get_range_us, m);
    }

    fn start_stop_flush(&self, stop: bool) {
        if stop {
            self.stop_flush.fetch_add(1, Ordering::Release);
        } else if 1 == self.stop_flush.fetch_sub(1, Ordering::Release) {
            // stop_flush went to 0, so this bucket could now be ready to be aged
            self.storage.wait_dirty_or_aged.notify_one();
        }
    }

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

    /// lookup 'pubkey' in index (in mem or on disk)
    pub fn get(&self, pubkey: &K) -> Option<AccountMapEntry<T>> {
        self.get_internal(pubkey, |entry| (true, entry.map(Arc::clone)))
    }

    fn load_from_disk(&self, pubkey: &Pubkey) -> Option<(SlotList<T>, RefCount)> {
        self.bucket.as_ref().and_then(|disk| {
            let m = Measure::start("load_disk_found_count");
            let entry_disk = disk.read_value(pubkey);
            match &entry_disk {
                Some(_) => {
                    Self::update_time_stat(&self.stats().load_disk_found_us, m);
                    Self::update_stat(&self.stats().load_disk_found_count, 1);
                }
                None => {
                    Self::update_time_stat(&self.stats().load_disk_missing_us, m);
                    Self::update_stat(&self.stats().load_disk_missing_count, 1);
                }
            }
            entry_disk
        })
    }

    fn load_account_entry_from_disk(&self, pubkey: &Pubkey) -> Option<AccountMapEntry<T>> {
        let entry_disk = self.load_from_disk(pubkey)?; // returns None if not on disk

        Some(self.disk_to_cache_entry(entry_disk.0, entry_disk.1))
    }

    /// lookup 'pubkey' in index (in_mem or disk).
    /// call 'callback' whether found or not
    pub(crate) fn get_internal<RT>(
        &self,
        pubkey: &K,
        // return true if item should be added to in_mem cache
        callback: impl for<'a> FnOnce(Option<&AccountMapEntry<T>>) -> (bool, RT),
    ) -> RT {
        self.get_only_in_mem(pubkey, |entry| {
            if let Some(entry) = entry {
                entry.set_age(self.storage.future_age_to_flush());
                callback(Some(entry)).1
            } else {
                // not in cache, look on disk
                let stats = &self.stats();
                let disk_entry = self.load_account_entry_from_disk(pubkey);
                if disk_entry.is_none() {
                    return callback(None).1;
                }
                let disk_entry = disk_entry.unwrap();
                let mut map = self.map().write().unwrap();
                let entry = map.entry(*pubkey);
                match entry {
                    Entry::Occupied(occupied) => callback(Some(occupied.get())).1,
                    Entry::Vacant(vacant) => {
                        let (add_to_cache, rt) = callback(Some(&disk_entry));

                        if add_to_cache {
                            stats.insert_or_delete_mem(true, self.bin);
                            vacant.insert(disk_entry);
                        }
                        rt
                    }
                }
            }
        })
    }

    /// lookup 'pubkey' by only looking in memory. Does not look on disk.
    /// callback is called whether pubkey is found or not
    fn get_only_in_mem<RT>(
        &self,
        pubkey: &K,
        callback: impl for<'a> FnOnce(Option<&'a AccountMapEntry<T>>) -> RT,
    ) -> RT {
        let m = Measure::start("get");
        let map = self.map().read().unwrap();
        let result = map.get(pubkey);
        let stats = self.stats();
        let (count, time) = if result.is_some() {
            (&stats.gets_from_mem, &stats.get_mem_us)
        } else {
            (&stats.gets_missing, &stats.get_missing_us)
        };
        Self::update_time_stat(time, m);
        Self::update_stat(count, 1);

        callback(if let Some(entry) = result {
            entry.set_age(self.storage.future_age_to_flush());
            Some(entry)
        } else {
            drop(map);
            None
        })
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

    fn last_age_flushed(&self) -> Age {
        self.last_age_flushed.load(Ordering::Relaxed)
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

    pub fn update_time_stat(stat: &AtomicU64, mut m: Measure) {
        m.stop();
        let value = m.as_us();
        Self::update_stat(stat, value);
    }

    pub fn stats(&self) -> &BucketMapHolderStats {
        &self.storage.stats
    }

    fn update_stat(stat: &AtomicU64, value: u64) {
        if value != 0 {
            stat.fetch_add(value, Ordering::Relaxed);
        }
    }

    // remove keys in 'removes' from in-mem cache due to age
    // return true if the removal was completed
    fn flush_remove_from_cache(
        &self,
        removes: Vec<Pubkey>,
        current_age: Age,
        startup: bool,
        randomly_evicted: bool,
    ) -> bool {
        let mut completed_scan = true;
        if removes.is_empty() {
            return completed_scan; // completed, don't need to get lock or do other work
        }

        let ranges = self.cache_ranges_held.read().unwrap().clone();
        if ranges.iter().any(|range| range.is_none()) {
            return false; // range said to hold 'all', so not completed
        }

        let mut removed = 0;
        // consider chunking these so we don't hold the write lock too long
        let mut map = self.map().write().unwrap();
        for k in removes {
            if let Entry::Occupied(occupied) = map.entry(k) {
                let v = occupied.get();
                if Arc::strong_count(v) > 1 {
                    // someone is holding the value arc's ref count and could modify it, so do not remove this from in-mem cache
                    completed_scan = false;
                    continue;
                }

                if v.dirty()
                    || (!randomly_evicted
                        && !self.should_remove_from_mem(current_age, v, startup, false))
                {
                    // marked dirty or bumped in age after we looked above
                    // these will be handled in later passes
                    // but, at startup, everything is ready to age out if it isn't dirty
                    continue;
                }

                if ranges.iter().any(|range| {
                    range
                        .as_ref()
                        .map(|range| range.contains(&k))
                        .unwrap_or(true) // None means 'full range', so true
                }) {
                    // this item is held in mem by range, so don't remove
                    completed_scan = false;
                    continue;
                }

                if self.get_stop_flush() {
                    return false; // did NOT complete, told to stop
                }

                // all conditions for removing succeeded, so really remove item from in-mem cache
                removed += 1;
                occupied.remove();
            }
        }
        self.stats()
            .insert_or_delete_mem_count(false, self.bin, removed);
        Self::update_stat(&self.stats().flush_entries_removed_from_mem, removed as u64);

        completed_scan
    }

    /// called after flush scans this bucket at the current age
    fn set_has_aged(&self, age: Age) {
        self.last_age_flushed.store(age, Ordering::Relaxed);
        self.storage.bucket_flushed_at_current_age();
    }

    fn get_stop_flush(&self) -> bool {
        self.stop_flush.load(Ordering::Relaxed) > 0
    }

    // convert from raw data on disk to AccountMapEntry, set to age in future
    fn disk_to_cache_entry(
        &self,
        slot_list: SlotList<T>,
        ref_count: RefCount,
    ) -> AccountMapEntry<T> {
        Arc::new(AccountMapEntryInner::new(
            slot_list,
            ref_count,
            AccountMapEntryMeta::new_dirty(&self.storage),
        ))
    }
}
