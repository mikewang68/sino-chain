use {
    crate::{
        accounts_index_storage::AccountsIndexStorage,
        // ancestors::Ancestors,
        bucket_map_holder::{Age, BucketMapHolder},
        // contains::Contains,
        in_mem_accounts_index::{InMemAccountsIndex, InsertNewEntryResults},
        // inline_spl_token::{self, GenericTokenAccount},
        // inline_spl_token_2022,
        pubkey_bins::PubkeyBinCalculator24,
        secondary_index::*,
        ancestors::Ancestors,
    },
    bv::BitVec,
    log::*,
    ouroboros::self_referencing,
    rand::{thread_rng, Rng},
    measure::measure::Measure,
    sdk::{
        clock::{BankId, Slot},
        pubkey::Pubkey,
    },
    std::{
        collections::{btree_map::BTreeMap, HashSet},
        fmt::Debug,
        ops::{
            Bound,
            Bound::{Excluded, Included, Unbounded},
            Range, RangeBounds,
        },
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
            Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard,
        },
    },
    thiserror::Error,
};

// use velas_account_program::{VAccountStorage, VelasAccountType};
// use velas_relying_party_program::RelyingPartyData;

pub type RefCount = u64;
pub type ScanResult<T> = Result<T, ScanError>;
type LockMapTypeSlice<T> = [RwLock<MapType<T>>];
pub type SlotSlice<'s, T> = &'s [(Slot, T)];
pub type SlotList<T> = Vec<(Slot, T)>;

pub const ITER_BATCH_SIZE: usize = 1000;
pub const BINS_FOR_TESTING: usize = 2; // we want > 1, but each bin is a few disk files with a disk based index, so fewer is better
pub const BINS_FOR_BENCHMARKS: usize = 2;
pub const FLUSH_THREADS_TESTING: usize = 1;
pub const ACCOUNTS_INDEX_CONFIG_FOR_TESTING: AccountsIndexConfig = AccountsIndexConfig {
    bins: Some(BINS_FOR_TESTING),
    flush_threads: Some(FLUSH_THREADS_TESTING),
    drives: None,
    index_limit_mb: None,
    ages_to_stay_in_cache: None,
    scan_results_limit_bytes: None,
};
pub const BINS_DEFAULT: usize = 8192;

enum ScanTypes<R: RangeBounds<Pubkey>> {
    Unindexed(Option<R>),
    Indexed(IndexKey),
}

#[derive(Debug, Clone, Copy)]
pub enum IndexKey {
    ProgramId(Pubkey),
    SplTokenMint(Pubkey),
    SplTokenOwner(Pubkey),
    VelasAccountStorage(Pubkey),
    VelasAccountOwner(Pubkey),
    VelasAccountOperational(Pubkey),
    VelasRelyingOwner(Pubkey),
}

#[derive(Debug, Default)]
pub struct ScanConfig {
    /// checked by the scan. When true, abort scan.
    pub abort: Option<Arc<AtomicBool>>,

    /// true to allow return of all matching items and allow them to be unsorted.
    /// This is more efficient.
    pub collect_all_unsorted: bool,
}

impl ScanConfig{
    pub fn abort(&self) {
        if let Some(abort) = self.abort.as_ref() {
            abort.store(true, Ordering::Relaxed)
        }
    }

    /// true if scan should abort
    pub fn is_aborted(&self) -> bool {
        if let Some(abort) = self.abort.as_ref() {
            abort.load(Ordering::Relaxed)
        } else {
            false
        }
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum ScanError {
    #[error("Node detected it replayed bad version of slot {slot:?} with id {bank_id:?}, thus the scan on said slot was aborted")]
    SlotRemoved { slot: Slot, bank_id: BankId },
    #[error("scan aborted: {0}")]
    Aborted(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountIndex {
    ProgramId,
    SplTokenMint,
    SplTokenOwner,
    VelasAccountStorage,
    VelasAccountOwner,
    VelasAccountOperational,
    VelasRelyingOwner,
}

pub trait IsCached {
    fn is_cached(&self) -> bool;
}

pub trait ZeroLamport {
    fn is_zero_lamport(&self) -> bool;
}

pub trait IndexValue:
    'static + IsCached + Clone + Debug + PartialEq + ZeroLamport + Copy + Default + Sync + Send
{
}

#[derive(Debug, Default, AbiExample, Clone)]
pub struct RollingBitField {
    max_width: u64,
    min: u64,
    max: u64, // exclusive
    bits: BitVec,
    count: usize,
    // These are items that are true and lower than min.
    // They would cause us to exceed max_width if we stored them in our bit field.
    // We only expect these items in conditions where there is some other bug in the system
    //  or in testing when large ranges are created.
    excess: HashSet<u64>,
}
// functionally similar to a hashset
// Relies on there being a sliding window of key values. The key values continue to increase.
// Old key values are removed from the lesser values and do not accumulate.
impl RollingBitField {
    pub fn new(max_width: u64) -> Self {
        assert!(max_width > 0);
        assert!(max_width.is_power_of_two()); // power of 2 to make dividing a shift
        let bits = BitVec::new_fill(false, max_width);
        Self {
            max_width,
            bits,
            count: 0,
            min: 0,
            max: 0,
            excess: HashSet::new(),
        }
    }

    // find the array index
    fn get_address(&self, key: &u64) -> u64 {
        key % self.max_width
    }

    pub fn range_width(&self) -> u64 {
        // note that max isn't updated on remove, so it can be above the current max
        self.max - self.min
    }

    pub fn min(&self) -> Option<u64> {
        if self.is_empty() {
            None
        } else if self.excess.is_empty() {
            Some(self.min)
        } else {
            let mut min = if self.all_items_in_excess() {
                u64::MAX
            } else {
                self.min
            };
            for item in &self.excess {
                min = std::cmp::min(min, *item);
            }
            Some(min)
        }
    }

    pub fn insert(&mut self, key: u64) {
        let mut bits_empty = self.count == 0 || self.all_items_in_excess();
        let update_bits = if bits_empty {
            true // nothing in bits, so in range
        } else if key < self.min {
            // bits not empty and this insert is before min, so add to excess
            if self.excess.insert(key) {
                self.count += 1;
            }
            false
        } else if key < self.max {
            true // fits current bit field range
        } else {
            // key is >= max
            let new_max = key + 1;
            loop {
                let new_width = new_max.saturating_sub(self.min);
                if new_width <= self.max_width {
                    // this key will fit the max range
                    break;
                }

                // move the min item from bits to excess and then purge from min to make room for this new max
                let inserted = self.excess.insert(self.min);
                assert!(inserted);

                let key = self.min;
                let address = self.get_address(&key);
                self.bits.set(address, false);
                self.purge(&key);

                if self.all_items_in_excess() {
                    // if we moved the last existing item to excess, then we are ready to insert the new item in the bits
                    bits_empty = true;
                    break;
                }
            }

            true // moved things to excess if necessary, so update bits with the new entry
        };

        if update_bits {
            let address = self.get_address(&key);
            let value = self.bits.get(address);
            if !value {
                self.bits.set(address, true);
                if bits_empty {
                    self.min = key;
                    self.max = key + 1;
                } else {
                    self.min = std::cmp::min(self.min, key);
                    self.max = std::cmp::max(self.max, key + 1);
                    assert!(
                        self.min + self.max_width >= self.max,
                        "min: {}, max: {}, max_width: {}",
                        self.min,
                        self.max,
                        self.max_width
                    );
                }
                self.count += 1;
            }
        }
    }

    pub fn remove(&mut self, key: &u64) -> bool {
        if key >= &self.min {
            // if asked to remove something bigger than max, then no-op
            if key < &self.max {
                let address = self.get_address(key);
                let get = self.bits.get(address);
                if get {
                    self.count -= 1;
                    self.bits.set(address, false);
                    self.purge(key);
                }
                get
            } else {
                false
            }
        } else {
            // asked to remove something < min. would be in excess if it exists
            let remove = self.excess.remove(key);
            if remove {
                self.count -= 1;
            }
            remove
        }
    }

    fn all_items_in_excess(&self) -> bool {
        self.excess.len() == self.count
    }

    // after removing 'key' where 'key' = min, make min the correct new min value
    fn purge(&mut self, key: &u64) {
        if self.count > 0 && !self.all_items_in_excess() {
            if key == &self.min {
                let start = self.min + 1; // min just got removed
                for key in start..self.max {
                    if self.contains_assume_in_range(&key) {
                        self.min = key;
                        break;
                    }
                }
            }
        } else {
            // The idea is that there are no items in the bitfield anymore.
            // But, there MAY be items in excess. The model works such that items < min go into excess.
            // So, after purging all items from bitfield, we hold max to be what it previously was, but set min to max.
            // Thus, if we lookup >= max, answer is always false without having to look in excess.
            // If we changed max here to 0, we would lose the ability to know the range of items in excess (if any).
            // So, now, with min updated = max:
            // If we lookup < max, then we first check min.
            // If >= min, then we look in bitfield.
            // Otherwise, we look in excess since the request is < min.
            // So, resetting min like this after a remove results in the correct behavior for the model.
            // Later, if we insert and there are 0 items total (excess + bitfield), then we reset min/max to reflect the new item only.
            self.min = self.max;
        }
    }

    fn contains_assume_in_range(&self, key: &u64) -> bool {
        // the result may be aliased. Caller is responsible for determining key is in range.
        let address = self.get_address(key);
        self.bits.get(address)
    }

    // This is the 99% use case.
    // This needs be fast for the most common case of asking for key >= min.
    pub fn contains(&self, key: &u64) -> bool {
        if key < &self.max {
            if key >= &self.min {
                // in the bitfield range
                self.contains_assume_in_range(key)
            } else {
                self.excess.contains(key)
            }
        } else {
            false
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&mut self) {
        let mut n = Self::new(self.max_width);
        std::mem::swap(&mut n, self);
    }

    pub fn max(&self) -> u64 {
        self.max
    }

    pub fn get_all(&self) -> Vec<u64> {
        let mut all = Vec::with_capacity(self.count);
        self.excess.iter().for_each(|slot| all.push(*slot));
        for key in self.min..self.max {
            if self.contains_assume_in_range(&key) {
                all.push(key);
            }
        }
        all
    }
}

impl PartialEq<RollingBitField> for RollingBitField {
    fn eq(&self, other: &Self) -> bool {
        // 2 instances could have different internal data for the same values,
        // so we have to compare data.
        self.len() == other.len() && {
            for item in self.get_all() {
                if !other.contains(&item) {
                    return false;
                }
            }
            true
        }
    }
}

pub enum AccountIndexGetResult<'a, T: IndexValue> {
    Found(ReadAccountMapEntry<T>, usize),
    NotFoundOnFork,
    Missing(AccountMapsReadLock<'a, T>),
}

type AccountMapsReadLock<'a, T> = RwLockReadGuard<'a, MapType<T>>;

#[self_referencing]
pub struct ReadAccountMapEntry<T: IndexValue> {
    owned_entry: AccountMapEntry<T>,
    #[borrows(owned_entry)]
    #[covariant]
    slot_list_guard: RwLockReadGuard<'this, SlotList<T>>,
}

impl<T: IndexValue> ReadAccountMapEntry<T> {
    pub fn from_account_map_entry(account_map_entry: AccountMapEntry<T>) -> Self {
        ReadAccountMapEntryBuilder {
            owned_entry: account_map_entry,
            slot_list_guard_builder: |lock| lock.slot_list.read().unwrap(),
        }
        .build()
    }

    pub fn slot_list(&self) -> &SlotList<T> {
        self.borrow_slot_list_guard()
    }
}

pub type AccountMap<V> = Arc<InMemAccountsIndex<V>>;
type MapType<T> = AccountMap<T>;
type LockMapType<T> = Vec<RwLock<MapType<T>>>;

pub(crate) type AccountMapEntry<T> = Arc<AccountMapEntryInner<T>>;

#[derive(Debug, Default)]
pub struct AccountMapEntryInner<T> {
    ref_count: AtomicU64,
    pub slot_list: RwLock<SlotList<T>>,
    pub meta: AccountMapEntryMeta,
}
impl<T: IndexValue> AccountMapEntryInner<T> {
    /// set dirty to false, return true if was dirty
    pub fn clear_dirty(&self) -> bool {
        self.meta
            .dirty
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }

    pub fn set_dirty(&self, value: bool) {
        self.meta.dirty.store(value, Ordering::Release)
    }

    pub fn ref_count(&self) -> RefCount {
        self.ref_count.load(Ordering::Relaxed)
    }

    pub fn age(&self) -> Age {
        self.meta.age.load(Ordering::Relaxed)
    }

    pub fn dirty(&self) -> bool {
        self.meta.dirty.load(Ordering::Acquire)
    }

    pub fn set_age(&self, value: Age) {
        self.meta.age.store(value, Ordering::Relaxed)
    }

    pub fn new(slot_list: SlotList<T>, ref_count: RefCount, meta: AccountMapEntryMeta) -> Self {
        Self {
            slot_list: RwLock::new(slot_list),
            ref_count: AtomicU64::new(ref_count),
            meta,
        }
    }
}


#[derive(Debug, Default)]
pub struct AccountMapEntryMeta {
    pub dirty: AtomicBool,
    pub age: AtomicU8,
}

impl AccountMapEntryMeta {
    pub fn new_dirty<T: IndexValue>(storage: &Arc<BucketMapHolder<T>>) -> Self {
        AccountMapEntryMeta {
            dirty: AtomicBool::new(true),
            age: AtomicU8::new(storage.future_age_to_flush()),
        }
    }
}


#[derive(Debug)]
pub struct RootsTracker {
    roots: RollingBitField,
    max_root: Slot,
    uncleaned_roots: HashSet<Slot>,
    previous_uncleaned_roots: HashSet<Slot>,
}

impl Default for RootsTracker {
    fn default() -> Self {
        // we expect to keep a rolling set of 400k slots around at a time
        // 4M gives us plenty of extra(?!) room to handle a width 10x what we should need.
        // cost is 4M bits of memory, which is .5MB
        RootsTracker::new(4194304)
    }
}
impl RootsTracker {
    pub fn new(max_width: u64) -> Self {
        Self {
            roots: RollingBitField::new(max_width),
            max_root: 0,
            uncleaned_roots: HashSet::new(),
            previous_uncleaned_roots: HashSet::new(),
        }
    }

    // pub fn min_root(&self) -> Option<Slot> {
    //     self.roots.min()
    // }
}

pub struct AccountsIndexIterator<'a, T: IndexValue> {
    account_maps: &'a LockMapTypeSlice<T>,
    bin_calculator: &'a PubkeyBinCalculator24,
    start_bound: Bound<Pubkey>,
    end_bound: Bound<Pubkey>,
    is_finished: bool,
    collect_all_unsorted: bool,
}

impl<'a, T: IndexValue> Iterator for AccountsIndexIterator<'a, T> {
    type Item = Vec<(Pubkey, AccountMapEntry<T>)>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.is_finished {
            return None;
        }
        let (start_bin, bin_range) = self.bin_start_and_range();
        let mut chunk = Vec::with_capacity(ITER_BATCH_SIZE);
        'outer: for i in self.account_maps.iter().skip(start_bin).take(bin_range) {
            for (pubkey, account_map_entry) in Self::range(
                &i.read().unwrap(),
                (self.start_bound, self.end_bound),
                self.collect_all_unsorted,
            ) {
                if chunk.len() >= ITER_BATCH_SIZE && !self.collect_all_unsorted {
                    break 'outer;
                }
                let item = (pubkey, account_map_entry);
                chunk.push(item);
            }
        }

        if chunk.is_empty() {
            self.is_finished = true;
            return None;
        } else if self.collect_all_unsorted {
            self.is_finished = true;
        }

        self.start_bound = Excluded(chunk.last().unwrap().0);
        Some(chunk)
    }
}

impl<'a, T: IndexValue> AccountsIndexIterator<'a, T> {
    fn range<R>(
        map: &AccountMapsReadLock<T>,
        range: R,
        collect_all_unsorted: bool,
    ) -> Vec<(Pubkey, AccountMapEntry<T>)>
    where
        R: RangeBounds<Pubkey> + std::fmt::Debug,
    {
        let mut result = map.items(&Some(&range));
        if !collect_all_unsorted {
            result.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        }
        result
    }

    fn bin_from_bound(&self, bound: &Bound<Pubkey>, unbounded_bin: usize) -> usize {
        match bound {
            Bound::Included(bound) | Bound::Excluded(bound) => {
                self.bin_calculator.bin_from_pubkey(bound)
            }
            Bound::Unbounded => unbounded_bin,
        }
    }

    fn start_bin(&self) -> usize {
        // start in bin where 'start_bound' would exist
        self.bin_from_bound(&self.start_bound, 0)
    }

    fn end_bin_inclusive(&self) -> usize {
        // end in bin where 'end_bound' would exist
        self.bin_from_bound(&self.end_bound, usize::MAX)
    }

    fn bin_start_and_range(&self) -> (usize, usize) {
        let start_bin = self.start_bin();
        // calculate the max range of bins to look in
        let end_bin_inclusive = self.end_bin_inclusive();
        let bin_range = if start_bin > end_bin_inclusive {
            0 // empty range
        } else if end_bin_inclusive == usize::MAX {
            usize::MAX
        } else {
            // the range is end_inclusive + 1 - start
            // end_inclusive could be usize::MAX already if no bound was specified
            end_bin_inclusive.saturating_add(1) - start_bin
        };
        (start_bin, bin_range)
    }

    pub fn new<R>(
        index: &'a AccountsIndex<T>,
        range: Option<&R>,
        collect_all_unsorted: bool,
    ) -> Self
    where
        R: RangeBounds<Pubkey>,
    {
        Self {
            start_bound: range
                .as_ref()
                .map(|r| Self::clone_bound(r.start_bound()))
                .unwrap_or(Unbounded),
            end_bound: range
                .as_ref()
                .map(|r| Self::clone_bound(r.end_bound()))
                .unwrap_or(Unbounded),
            account_maps: &index.account_maps,
            is_finished: false,
            bin_calculator: &index.bin_calculator,
            collect_all_unsorted,
        }
    }

    fn clone_bound(bound: Bound<&Pubkey>) -> Bound<Pubkey> {
        match bound {
            Unbounded => Unbounded,
            Included(k) => Included(*k),
            Excluded(k) => Excluded(*k),
        }
    }

}

#[derive(Debug)]
pub struct AccountsIndex<T: IndexValue> {
    pub account_maps: LockMapType<T>,
    pub bin_calculator: PubkeyBinCalculator24,
    program_id_index: SecondaryIndex<DashMapSecondaryIndexEntry>,
    spl_token_mint_index: SecondaryIndex<DashMapSecondaryIndexEntry>,
    spl_token_owner_index: SecondaryIndex<RwLockSecondaryIndexEntry>,
    roots_tracker: RwLock<RootsTracker>,
    ongoing_scan_roots: RwLock<BTreeMap<Slot, u64>>,
    // Each scan has some latest slot `S` that is the tip of the fork the scan
    // is iterating over. The unique id of that slot `S` is recorded here (note we don't use
    // `S` as the id because there can be more than one version of a slot `S`). If a fork
    // is abandoned, all of the slots on that fork up to `S` will be removed via
    // `AccountsDb::remove_unrooted_slots()`. When the scan finishes, it'll realize that the
    // results of the scan may have been corrupted by `remove_unrooted_slots` and abort its results.
    //
    // `removed_bank_ids` tracks all the slot ids that were removed via `remove_unrooted_slots()` so any attempted scans
    // on any of these slots fails. This is safe to purge once the associated Bank is dropped and
    // scanning the fork with that Bank at the tip is no longer possible.
    pub removed_bank_ids: Mutex<HashSet<BankId>>,
    // Velas Indices
    velas_account_storage_index: SecondaryIndex<DashMapSecondaryIndexEntry>,
    velas_account_owner_index: SecondaryIndex<DashMapSecondaryIndexEntry>,
    velas_account_operational_index: SecondaryIndex<DashMapSecondaryIndexEntry>,
    velas_relying_party_owner_index: SecondaryIndex<DashMapSecondaryIndexEntry>,

    storage: AccountsIndexStorage<T>,

    /// when a scan's accumulated data exceeds this limit, abort the scan
    pub scan_results_limit_bytes: Option<usize>,
}

impl<T: IndexValue> AccountsIndex<T> {
    /// call func with every pubkey and index visible from a given set of ancestors
    pub(crate) fn index_scan_accounts<F>(
        &self,
        ancestors: &Ancestors,
        scan_bank_id: BankId,
        index_key: IndexKey,
        func: F,
        config: &ScanConfig,
    ) -> Result<(), ScanError>
    where
        F: FnMut(&Pubkey, (&T, Slot)),
    {
        // Pass "" not to log metrics, so RPC doesn't get spammy
        self.do_checked_scan_accounts(
            "",
            ancestors,
            scan_bank_id,
            func,
            ScanTypes::<Range<Pubkey>>::Indexed(index_key),
            config,
        )
    }

    /// call func with every pubkey and index visible from a given set of ancestors
    pub(crate) fn scan_accounts<F>(
        &self,
        ancestors: &Ancestors,
        scan_bank_id: BankId,
        func: F,
        config: &ScanConfig,
    ) -> Result<(), ScanError>
    where
        F: FnMut(&Pubkey, (&T, Slot)),
    {
        // Pass "" not to log metrics, so RPC doesn't get spammy
        self.do_checked_scan_accounts(
            "",
            ancestors,
            scan_bank_id,
            func,
            ScanTypes::Unindexed(None::<Range<Pubkey>>),
            config,
        )
    }

    pub fn max_root(&self) -> Slot {
        self.roots_tracker.read().unwrap().max_root
    }

    fn do_checked_scan_accounts<F, R>(
        &self,
        metric_name: &'static str,
        ancestors: &Ancestors,
        scan_bank_id: BankId,
        func: F,
        scan_type: ScanTypes<R>,
        config: &ScanConfig,
    ) -> Result<(), ScanError>
    where
        F: FnMut(&Pubkey, (&T, Slot)),
        R: RangeBounds<Pubkey> + std::fmt::Debug,
    {
        {
            let locked_removed_bank_ids = self.removed_bank_ids.lock().unwrap();
            if locked_removed_bank_ids.contains(&scan_bank_id) {
                return Err(ScanError::SlotRemoved {
                    slot: ancestors.max_slot(),
                    bank_id: scan_bank_id,
                });
            }
        }

        let max_root = {
            let mut w_ongoing_scan_roots = self
                // This lock is also grabbed by clean_accounts(), so clean
                // has at most cleaned up to the current `max_root` (since
                // clean only happens *after* BankForks::set_root() which sets
                // the `max_root`)
                .ongoing_scan_roots
                .write()
                .unwrap();
            // `max_root()` grabs a lock while
            // the `ongoing_scan_roots` lock is held,
            // make sure inverse doesn't happen to avoid
            // deadlock
            let max_root = self.max_root();
            *w_ongoing_scan_roots.entry(max_root).or_default() += 1;

            max_root
        };

        // First we show that for any bank `B` that is a descendant of
        // the current `max_root`, it must be true that and `B.ancestors.contains(max_root)`,
        // regardless of the pattern of `squash()` behavior, where `ancestors` is the set
        // of ancestors that is tracked in each bank.
        //
        // Proof: At startup, if starting from a snapshot, generate_index() adds all banks
        // in the snapshot to the index via `add_root()` and so `max_root` will be the
        // greatest of these. Thus, so the claim holds at startup since there are no
        // descendants of `max_root`.
        //
        // Now we proceed by induction on each `BankForks::set_root()`.
        // Assume the claim holds when the `max_root` is `R`. Call the set of
        // descendants of `R` present in BankForks `R_descendants`.
        //
        // Then for any banks `B` in `R_descendants`, it must be that `B.ancestors.contains(S)`,
        // where `S` is any ancestor of `B` such that `S >= R`.
        //
        // For example:
        //          `R` -> `A` -> `C` -> `B`
        // Then `B.ancestors == {R, A, C}`
        //
        // Next we call `BankForks::set_root()` at some descendant of `R`, `R_new`,
        // where `R_new > R`.
        //
        // When we squash `R_new`, `max_root` in the AccountsIndex here is now set to `R_new`,
        // and all nondescendants of `R_new` are pruned.
        //
        // Now consider any outstanding references to banks in the system that are descended from
        // `max_root == R_new`. Take any one of these references and call it `B`. Because `B` is
        // a descendant of `R_new`, this means `B` was also a descendant of `R`. Thus `B`
        // must be a member of `R_descendants` because `B` was constructed and added to
        // BankForks before the `set_root`.
        //
        // This means by the guarantees of `R_descendants` described above, because
        // `R_new` is an ancestor of `B`, and `R < R_new < B`, then `B.ancestors.contains(R_new)`.
        //
        // Now until the next `set_root`, any new banks constructed from `new_from_parent` will
        // also have `max_root == R_new` in their ancestor set, so the claim holds for those descendants
        // as well. Once the next `set_root` happens, we once again update `max_root` and the same
        // inductive argument can be applied again to show the claim holds.

        // Check that the `max_root` is present in `ancestors`. From the proof above, if
        // `max_root` is not present in `ancestors`, this means the bank `B` with the
        // given `ancestors` is not descended from `max_root, which means
        // either:
        // 1) `B` is on a different fork or
        // 2) `B` is an ancestor of `max_root`.
        // In both cases we can ignore the given ancestors and instead just rely on the roots
        // present as `max_root` indicates the roots present in the index are more up to date
        // than the ancestors given.
        let empty = Ancestors::default();
        let ancestors = if ancestors.contains_key(&max_root) {
            ancestors
        } else {
            /*
            This takes of edge cases like:

            Diagram 1:

                        slot 0
                          |
                        slot 1
                      /        \
                 slot 2         |
                    |       slot 3 (max root)
            slot 4 (scan)

            By the time the scan on slot 4 is called, slot 2 may already have been
            cleaned by a clean on slot 3, but slot 4 may not have been cleaned.
            The state in slot 2 would have been purged and is not saved in any roots.
            In this case, a scan on slot 4 wouldn't accurately reflect the state when bank 4
            was frozen. In cases like this, we default to a scan on the latest roots by
            removing all `ancestors`.
            */
            &empty
        };

        /*
        Now there are two cases, either `ancestors` is empty or nonempty:

        1) If ancestors is empty, then this is the same as a scan on a rooted bank,
        and `ongoing_scan_roots` provides protection against cleanup of roots necessary
        for the scan, and  passing `Some(max_root)` to `do_scan_accounts()` ensures newer
        roots don't appear in the scan.

        2) If ancestors is non-empty, then from the `ancestors_contains(&max_root)` above, we know
        that the fork structure must look something like:

        Diagram 2:

                Build fork structure:
                        slot 0
                          |
                    slot 1 (max_root)
                    /            \
             slot 2              |
                |            slot 3 (potential newer max root)
              slot 4
                |
             slot 5 (scan)

        Consider both types of ancestors, ancestor <= `max_root` and
        ancestor > `max_root`, where `max_root == 1` as illustrated above.

        a) The set of `ancestors <= max_root` are all rooted, which means their state
        is protected by the same guarantees as 1).

        b) As for the `ancestors > max_root`, those banks have at least one reference discoverable
        through the chain of `Bank::BankRc::parent` starting from the calling bank. For instance
        bank 5's parent reference keeps bank 4 alive, which will prevent the `Bank::drop()` from
        running and cleaning up bank 4. Furthermore, no cleans can happen past the saved max_root == 1,
        so a potential newer max root at 3 will not clean up any of the ancestors > 1, so slot 4
        will not be cleaned in the middle of the scan either. (NOTE similar reasoning is employed for
        assert!() justification in AccountsDb::retry_to_get_account_accessor)
        */
        match scan_type {
            ScanTypes::Unindexed(range) => {
                // Pass "" not to log metrics, so RPC doesn't get spammy
                self.do_scan_accounts(metric_name, ancestors, func, range, Some(max_root), config);
            }
            ScanTypes::Indexed(IndexKey::ProgramId(program_id)) => {
                self.do_scan_secondary_index(
                    ancestors,
                    func,
                    &self.program_id_index,
                    &program_id,
                    Some(max_root),
                    config,
                );
            }
            ScanTypes::Indexed(IndexKey::SplTokenMint(mint_key)) => {
                self.do_scan_secondary_index(
                    ancestors,
                    func,
                    &self.spl_token_mint_index,
                    &mint_key,
                    Some(max_root),
                    config,
                );
            }
            ScanTypes::Indexed(IndexKey::SplTokenOwner(owner_key)) => {
                self.do_scan_secondary_index(
                    ancestors,
                    func,
                    &self.spl_token_owner_index,
                    &owner_key,
                    Some(max_root),
                    config,
                );
            }

            ScanTypes::Indexed(IndexKey::VelasAccountStorage(va_storage_key)) => self
                .do_scan_secondary_index(
                    ancestors,
                    func,
                    &self.velas_account_storage_index,
                    &va_storage_key,
                    Some(max_root),
                    config,
                ),
            ScanTypes::Indexed(IndexKey::VelasAccountOwner(va_owner_key)) => self
                .do_scan_secondary_index(
                    ancestors,
                    func,
                    &self.velas_account_owner_index,
                    &va_owner_key,
                    Some(max_root),
                    config,
                ),
            ScanTypes::Indexed(IndexKey::VelasAccountOperational(va_operational_key)) => self
                .do_scan_secondary_index(
                    ancestors,
                    func,
                    &self.velas_account_operational_index,
                    &va_operational_key,
                    Some(max_root),
                    config,
                ),
            ScanTypes::Indexed(IndexKey::VelasRelyingOwner(va_owner_key)) => self
                .do_scan_secondary_index(
                    ancestors,
                    func,
                    &self.velas_relying_party_owner_index,
                    &va_owner_key,
                    Some(max_root),
                    config,
                ),
        }

        {
            let mut ongoing_scan_roots = self.ongoing_scan_roots.write().unwrap();
            let count = ongoing_scan_roots.get_mut(&max_root).unwrap();
            *count -= 1;
            if *count == 0 {
                ongoing_scan_roots.remove(&max_root);
            }
        }

        // If the fork with tip at bank `scan_bank_id` was removed during our scan, then the scan
        // may have been corrupted, so abort the results.
        let was_scan_corrupted = self
            .removed_bank_ids
            .lock()
            .unwrap()
            .contains(&scan_bank_id);

        if was_scan_corrupted {
            Err(ScanError::SlotRemoved {
                slot: ancestors.max_slot(),
                bank_id: scan_bank_id,
            })
        } else {
            Ok(())
        }
    }

    fn do_scan_secondary_index<
        F,
        SecondaryIndexEntryType: SecondaryIndexEntry + Default + Sync + Send,
    >(
        &self,
        ancestors: &Ancestors,
        mut func: F,
        index: &SecondaryIndex<SecondaryIndexEntryType>,
        index_key: &Pubkey,
        max_root: Option<Slot>,
        config: &ScanConfig,
    ) where
        F: FnMut(&Pubkey, (&T, Slot)),
    {
        for pubkey in index.get(index_key) {
            // Maybe these reads from the AccountsIndex can be batched every time it
            // grabs the read lock as well...
            if let AccountIndexGetResult::Found(list_r, index) =
                self.get(&pubkey, Some(ancestors), max_root)
            {
                let entry = &list_r.slot_list()[index];
                func(&pubkey, (&entry.1, entry.0));
            }
            if config.is_aborted() {
                break;
            }
        }
    }

    // Scan accounts and return latest version of each account that is either:
    // 1) rooted or
    // 2) present in ancestors
    fn do_scan_accounts<F, R>(
        &self,
        metric_name: &'static str,
        ancestors: &Ancestors,
        mut func: F,
        range: Option<R>,
        max_root: Option<Slot>,
        config: &ScanConfig,
    ) where
        F: FnMut(&Pubkey, (&T, Slot)),
        R: RangeBounds<Pubkey> + std::fmt::Debug,
    {
        // TODO: expand to use mint index to find the `pubkey_list` below more efficiently
        // instead of scanning the entire range
        let mut total_elapsed_timer = Measure::start("total");
        let mut num_keys_iterated = 0;
        let mut latest_slot_elapsed = 0;
        let mut load_account_elapsed = 0;
        let mut read_lock_elapsed = 0;
        let mut iterator_elapsed = 0;
        let mut iterator_timer = Measure::start("iterator_elapsed");
        for pubkey_list in self.iter(range.as_ref(), config.collect_all_unsorted) {
            iterator_timer.stop();
            iterator_elapsed += iterator_timer.as_us();
            for (pubkey, list) in pubkey_list {
                num_keys_iterated += 1;
                let mut read_lock_timer = Measure::start("read_lock");
                let list_r = &list.slot_list.read().unwrap();
                read_lock_timer.stop();
                read_lock_elapsed += read_lock_timer.as_us();
                let mut latest_slot_timer = Measure::start("latest_slot");
                if let Some(index) = self.latest_slot(Some(ancestors), list_r, max_root) {
                    latest_slot_timer.stop();
                    latest_slot_elapsed += latest_slot_timer.as_us();
                    let mut load_account_timer = Measure::start("load_account");
                    func(&pubkey, (&list_r[index].1, list_r[index].0));
                    load_account_timer.stop();
                    load_account_elapsed += load_account_timer.as_us();
                }
                if config.is_aborted() {
                    return;
                }
            }
            iterator_timer = Measure::start("iterator_elapsed");
        }

        total_elapsed_timer.stop();
        if !metric_name.is_empty() {
            datapoint_info!(
                metric_name,
                ("total_elapsed", total_elapsed_timer.as_us(), i64),
                ("latest_slot_elapsed", latest_slot_elapsed, i64),
                ("read_lock_elapsed", read_lock_elapsed, i64),
                ("load_account_elapsed", load_account_elapsed, i64),
                ("iterator_elapsed", iterator_elapsed, i64),
                ("num_keys_iterated", num_keys_iterated, i64),
            )
        }
    }

    fn iter<R>(&self, range: Option<&R>, collect_all_unsorted: bool) -> AccountsIndexIterator<T>
    where
        R: RangeBounds<Pubkey>,
    {
        AccountsIndexIterator::new(self, range, collect_all_unsorted)
    }

    pub fn is_root(&self, slot: Slot) -> bool {
        self.roots_tracker.read().unwrap().roots.contains(&slot)
    }

    pub fn new(config: Option<AccountsIndexConfig>) -> Self {
        let scan_results_limit_bytes = config
            .as_ref()
            .and_then(|config| config.scan_results_limit_bytes);
        let (account_maps, bin_calculator, storage) = Self::allocate_accounts_index(config);
        Self {
            account_maps,
            bin_calculator,
            program_id_index: SecondaryIndex::<DashMapSecondaryIndexEntry>::new(
                "program_id_index_stats",
            ),
            spl_token_mint_index: SecondaryIndex::<DashMapSecondaryIndexEntry>::new(
                "spl_token_mint_index_stats",
            ),
            spl_token_owner_index: SecondaryIndex::<RwLockSecondaryIndexEntry>::new(
                "spl_token_owner_index_stats",
            ),
            roots_tracker: RwLock::<RootsTracker>::default(),
            ongoing_scan_roots: RwLock::<BTreeMap<Slot, u64>>::default(),
            removed_bank_ids: Mutex::<HashSet<BankId>>::default(),
            storage,
            scan_results_limit_bytes,

            //Velas indexes
            velas_account_storage_index: SecondaryIndex::<DashMapSecondaryIndexEntry>::new("velas_account_storage_index"),
            velas_account_owner_index: SecondaryIndex::<DashMapSecondaryIndexEntry>::new("velas_account_owner_index"),
            velas_account_operational_index: SecondaryIndex::<DashMapSecondaryIndexEntry>::new("velas_account_operational_index"),
            velas_relying_party_owner_index: SecondaryIndex::<DashMapSecondaryIndexEntry>::new("velas_relying_party_owner_index"),
        }
    }

    fn allocate_accounts_index(
        config: Option<AccountsIndexConfig>,
    ) -> (
        LockMapType<T>,
        PubkeyBinCalculator24,
        AccountsIndexStorage<T>,
    ) {
        let bins = config
            .as_ref()
            .and_then(|config| config.bins)
            .unwrap_or(BINS_DEFAULT);
        // create bin_calculator early to verify # bins is reasonable
        let bin_calculator = PubkeyBinCalculator24::new(bins);
        let storage = AccountsIndexStorage::new(bins, &config);
        let account_maps = (0..bins)
            .into_iter()
            .map(|bin| RwLock::new(Arc::clone(&storage.in_mem[bin])))
            .collect::<Vec<_>>();
        (account_maps, bin_calculator, storage)
    }

    pub fn set_startup(&self, value: bool) {
        self.storage.set_startup(value);
    }

    /// Get an account
    /// The latest account that appears in `ancestors` or `roots` is returned.
    pub(crate) fn get(
        &self,
        pubkey: &Pubkey,
        ancestors: Option<&Ancestors>,
        max_root: Option<Slot>,
    ) -> AccountIndexGetResult<'_, T> {
        let read_lock = self.account_maps[self.bin_calculator.bin_from_pubkey(pubkey)]
            .read()
            .unwrap();
        let account = read_lock
            .get(pubkey)
            .map(ReadAccountMapEntry::from_account_map_entry);

        match account {
            Some(locked_entry) => {
                drop(read_lock);
                let slot_list = locked_entry.slot_list();
                let found_index = self.latest_slot(ancestors, slot_list, max_root);
                match found_index {
                    Some(found_index) => AccountIndexGetResult::Found(locked_entry, found_index),
                    None => AccountIndexGetResult::NotFoundOnFork,
                }
            }
            None => AccountIndexGetResult::Missing(read_lock),
        }
    }

    // Given a SlotSlice `L`, a list of ancestors and a maximum slot, find the latest element
    // in `L`, where the slot `S` is an ancestor or root, and if `S` is a root, then `S <= max_root`
    fn latest_slot(
        &self,
        ancestors: Option<&Ancestors>,
        slice: SlotSlice<T>,
        max_root: Option<Slot>,
    ) -> Option<usize> {
        let mut current_max = 0;
        let mut rv = None;
        if let Some(ancestors) = ancestors {
            if !ancestors.is_empty() {
                for (i, (slot, _t)) in slice.iter().rev().enumerate() {
                    if (rv.is_none() || *slot > current_max) && ancestors.contains_key(slot) {
                        rv = Some(i);
                        current_max = *slot;
                    }
                }
            }
        }

        let max_root = max_root.unwrap_or(Slot::MAX);
        let mut tracker = None;

        for (i, (slot, _t)) in slice.iter().rev().enumerate() {
            if (rv.is_none() || *slot > current_max) && *slot <= max_root {
                let lock = match tracker {
                    Some(inner) => inner,
                    None => self.roots_tracker.read().unwrap(),
                };
                if lock.roots.contains(slot) {
                    rv = Some(i);
                    current_max = *slot;
                }
                tracker = Some(lock);
            }
        }

        rv.map(|index| slice.len() - 1 - index)
    }
}


#[derive(Debug, Default, Clone)]
pub struct AccountsIndexConfig {
    pub bins: Option<usize>,
    pub flush_threads: Option<usize>,
    pub drives: Option<Vec<PathBuf>>,
    pub index_limit_mb: Option<usize>,
    pub ages_to_stay_in_cache: Option<Age>,
    pub scan_results_limit_bytes: Option<usize>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AccountSecondaryIndexesIncludeExclude {
    pub exclude: bool,
    pub keys: HashSet<Pubkey>,
}

#[derive(Debug, Default, Clone)]
pub struct AccountSecondaryIndexes {
    pub keys: Option<AccountSecondaryIndexesIncludeExclude>,
    pub indexes: HashSet<AccountIndex>,
}

impl AccountSecondaryIndexes {
    pub fn is_empty(&self) -> bool {
        self.indexes.is_empty()
    }
    pub fn contains(&self, index: &AccountIndex) -> bool {
        self.indexes.contains(index)
    }
    pub fn include_key(&self, key: &Pubkey) -> bool {
        match &self.keys {
            Some(options) => options.exclude ^ options.keys.contains(key),
            None => true, // include all keys
        }
    }
}

