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
pub type ScanResult<T, ScanError> = Result<T, ScanError>;
pub type SlotSlice<'s, T> = &'s [(Slot, T)];
pub type SlotList<T> = Vec<(Slot, T)>;

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
pub type SlotList<T> = Vec<(Slot, T)>;

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
}

#[derive(Debug, Default)]
pub struct AccountMapEntryMeta {
    pub dirty: AtomicBool,
    pub age: AtomicU8,
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

