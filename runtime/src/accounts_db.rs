//! Persistent accounts are stored in below path location:
//!  <path>/<pid>/data/
//!
//! The persistent store would allow for this mode of operation:
//!  - Concurrent single thread append with many concurrent readers.
//!
//! The underlying memory is memory mapped to a file. The accounts would be
//! stored across multiple files and the mappings of file and offset of a
//! particular account would be stored in a shared index. This will allow for
//! concurrent commits without blocking reads, which will sequentially write
//! to memory, ssd or disk, and should be as fast as the hardware allow for.
//! The only required in memory data structure with a write lock is the index,
//! which should be fast to update.
//!
//! AppendVec's only store accounts for single slots.  To bootstrap the
//! index from a persistent store of AppendVec's, the entries include
//! a "write_version".  A single global atomic `AccountsDb::write_version`
//! tracks the number of commits to the entire data store. So the latest
//! commit for each slot entry would be indexed.

#[cfg(test)]
use std::{thread::sleep, time::Duration};

use crate::accounts_index::{AccountsIndexConfig, ACCOUNTS_INDEX_CONFIG_FOR_TESTING};
use {
    crate::{
        // accounts_background_service::{DroppedSlotsSender, SendDroppedBankCallback},
        accounts_cache::{
            AccountsCache, 
            CachedAccount, 
            // SlotCache
        },
        // accounts_hash::{AccountsHash, CalculateHashIntermediate, HashStats, PreviousPass},
        accounts_index::{
            AccountIndexGetResult, 
            AccountSecondaryIndexes, AccountsIndex, 
            // AccountsIndexConfig,
            // AccountsIndexRootsStats, IndexKey, 
            IndexValue, 
            IsCached, 
            // RefCount, ScanConfig,
            // ScanResult, SlotList, SlotSlice, 
            ZeroLamport, 
            // ACCOUNTS_INDEX_CONFIG_FOR_BENCHMARKS,
            // ACCOUNTS_INDEX_CONFIG_FOR_TESTING,
        },
        accounts_update_notifier_interface::AccountsUpdateNotifier,
        ancestors::Ancestors,
        append_vec::{AppendVec, 
            StoredAccountMeta, /*StoredMeta, StoredMetaWriteVersion*/
        },
        // cache_hash_data::CacheHashData,
        // contains::Contains,
        pubkey_bins::PubkeyBinCalculator24,
        read_only_accounts_cache::ReadOnlyAccountsCache,
        rent_collector::RentCollector,
        // sorted_storages::SortedStorages,
    },
    blake3::traits::digest::Digest,
    crossbeam_channel::{unbounded, Receiver, Sender},
    dashmap::{
        mapref::entry::Entry::{Occupied, Vacant},
        DashMap, DashSet,
    },
    log::*,
    rand::{prelude::SliceRandom, thread_rng, Rng},
    rayon::{prelude::*, ThreadPool},
    serde::{Deserialize, Serialize},
    measure::measure::Measure,
    rayon_threadlimit::get_thread_count,
    sdk::{
        account::{AccountSharedData, ReadableAccount},
        clock::{BankId, Epoch, Slot, SlotCount},
        epoch_schedule::EpochSchedule,
        genesis_config::{ClusterType, GenesisConfig},
        hash::Hash,
        pubkey::Pubkey,
        timing::AtomicInterval,
    },
    vote_program::vote_state::MAX_LOCKOUT_HISTORY,
    std::{
        borrow::{Borrow, Cow},
        boxed::Box,
        collections::{hash_map::Entry, BTreeSet, HashMap, HashSet},
        convert::TryFrom,
        hash::{Hash as StdHash, Hasher as StdHasher},
        io::{Error as IoError, Result as IoResult},
        ops::{Range, RangeBounds},
        path::{Path, PathBuf},
        str::FromStr,
        sync::{
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
            Arc, Condvar, Mutex, MutexGuard, RwLock,
        },
        thread::Builder,
        time::Instant,
    },
    tempfile::TempDir,
};


// A specially reserved storage id just for entries in the cache, so that
// operations that take a storage entry can maintain a common interface
// when interacting with cached accounts. This id is "virtual" in that it
// doesn't actually refer to an actual storage entry.
const CACHE_VIRTUAL_STORAGE_ID: usize = AppendVecId::MAX;


// type AccountInfoAccountsIndex = AccountsIndex<AccountInfo>;
type ShrinkCandidates = HashMap<Slot, HashMap<AppendVecId, Arc<AccountStorageEntry>>>;

/// An offset into the AccountsDb::storage vector
pub type AppendVecId = usize;

// Each slot has a set of storage entries.
pub(crate) type SlotStores = Arc<RwLock<HashMap<usize, Arc<AccountStorageEntry>>>>;

#[derive(Debug, Eq, PartialEq, Copy, Clone, Deserialize, Serialize, AbiExample, AbiEnumVisitor)]
pub enum AccountStorageStatus {
    Available = 0,
    Full = 1,
    Candidate = 2,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct IndexGenerationInfo {
    pub accounts_data_len: u64,
}

#[derive(Default, Debug, PartialEq, Clone, Copy)]
pub struct AccountInfo {
    /// index identifying the append storage
    store_id: AppendVecId,

    /// offset into the storage
    offset: usize,

    /// needed to track shrink candidacy in bytes. Used to update the number
    /// of alive bytes in an AppendVec as newer slots purge outdated entries
    stored_size: usize,

    /// lamports in the account used when squashing kept for optimization
    /// purposes to remove accounts with zero balance.
    lamports: u64,
}

impl ZeroLamport for AccountInfo {
    fn is_zero_lamport(&self) -> bool {
        self.lamports == 0
    }
}
impl IsCached for AccountInfo {
    fn is_cached(&self) -> bool {
        self.store_id == CACHE_VIRTUAL_STORAGE_ID
    }
}
impl IndexValue for AccountInfo {}

#[derive(Debug, Default, Clone)]
pub struct AccountsDbConfig {
    pub index: Option<AccountsIndexConfig>,
    pub accounts_hash_cache_path: Option<PathBuf>,
    pub filler_account_count: Option<usize>,
    pub hash_calc_num_passes: Option<usize>,
    pub write_cache_limit_bytes: Option<u64>,
}

#[derive(Clone, Default, Debug)]
pub struct AccountStorage(pub DashMap<Slot, SlotStores>);

impl AccountStorage {
    fn get_account_storage_entry(
        &self,
        slot: Slot,
        store_id: AppendVecId,
    ) -> Option<Arc<AccountStorageEntry>> {
        self.get_slot_stores(slot)
            .and_then(|storage_map| storage_map.read().unwrap().get(&store_id).cloned())
    }

    pub fn get_slot_stores(&self, slot: Slot) -> Option<SlotStores> {
        self.0.get(&slot).map(|result| result.value().clone())
    }

    fn get_slot_storage_entries(&self, slot: Slot) -> Option<Vec<Arc<AccountStorageEntry>>> {
        self.get_slot_stores(slot)
            .map(|res| res.read().unwrap().values().cloned().collect())
    }

    fn slot_store_count(&self, slot: Slot, store_id: AppendVecId) -> Option<usize> {
        self.get_account_storage_entry(slot, store_id)
            .map(|store| store.count())
    }

    fn all_slots(&self) -> Vec<Slot> {
        self.0.iter().map(|iter_item| *iter_item.key()).collect()
    }
}

#[derive(Debug, Default)]
struct RecycleStores {
    entries: Vec<(Instant, Arc<AccountStorageEntry>)>,
    total_bytes: u64,
}

pub type SnapshotStorage = Vec<Arc<AccountStorageEntry>>;
pub type SnapshotStorages = Vec<SnapshotStorage>;

pub const ACCOUNTS_DB_CONFIG_FOR_TESTING: AccountsDbConfig = AccountsDbConfig {
    index: Some(ACCOUNTS_INDEX_CONFIG_FOR_TESTING),
    accounts_hash_cache_path: None,
    filler_account_count: None,
    hash_calc_num_passes: None,
    write_cache_limit_bytes: None,
};

#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, AbiExample)]
pub struct BankHashInfo {
    pub hash: Hash,
    pub snapshot_hash: Hash,
    pub stats: BankHashStats,
}

#[derive(Debug, Default)]
struct AccountsStats {
    delta_hash_scan_time_total_us: AtomicU64,
    delta_hash_accumulate_time_total_us: AtomicU64,
    delta_hash_num: AtomicU64,

    last_store_report: AtomicInterval,
    store_hash_accounts: AtomicU64,
    calc_stored_meta: AtomicU64,
    store_accounts: AtomicU64,
    store_update_index: AtomicU64,
    store_handle_reclaims: AtomicU64,
    store_append_accounts: AtomicU64,
    store_find_store: AtomicU64,
    store_num_accounts: AtomicU64,
    store_total_data: AtomicU64,
    recycle_store_count: AtomicU64,
    create_store_count: AtomicU64,
    store_get_slot_store: AtomicU64,
    store_find_existing: AtomicU64,
    dropped_stores: AtomicU64,
    store_uncleaned_update: AtomicU64,
}

#[derive(Debug, Default)]
struct CleanAccountsStats {
    purge_stats: PurgeStats,
    latest_accounts_index_roots_stats: LatestAccountsIndexRootsStats,

    // stats held here and reported by clean_accounts
    clean_old_root_us: AtomicU64,
    clean_old_root_reclaim_us: AtomicU64,
    reset_uncleaned_roots_us: AtomicU64,
    remove_dead_accounts_remove_us: AtomicU64,
    remove_dead_accounts_shrink_us: AtomicU64,
    clean_stored_dead_slots_us: AtomicU64,
}

#[derive(Debug, Default)]
struct PurgeStats {
    last_report: AtomicInterval,
    safety_checks_elapsed: AtomicU64,
    remove_cache_elapsed: AtomicU64,
    remove_storage_entries_elapsed: AtomicU64,
    drop_storage_entries_elapsed: AtomicU64,
    num_cached_slots_removed: AtomicUsize,
    num_stored_slots_removed: AtomicUsize,
    total_removed_storage_entries: AtomicUsize,
    total_removed_cached_bytes: AtomicU64,
    total_removed_stored_bytes: AtomicU64,
    recycle_stores_write_elapsed: AtomicU64,
    scan_storages_elasped: AtomicU64,
    purge_accounts_index_elapsed: AtomicU64,
    handle_reclaims_elapsed: AtomicU64,
}

#[derive(Debug, Default)]
struct ShrinkStats {
    last_report: AtomicInterval,
    num_slots_shrunk: AtomicUsize,
    storage_read_elapsed: AtomicU64,
    index_read_elapsed: AtomicU64,
    find_alive_elapsed: AtomicU64,
    create_and_insert_store_elapsed: AtomicU64,
    store_accounts_elapsed: AtomicU64,
    update_index_elapsed: AtomicU64,
    handle_reclaims_elapsed: AtomicU64,
    write_storage_elapsed: AtomicU64,
    rewrite_elapsed: AtomicU64,
    drop_storage_entries_elapsed: AtomicU64,
    recycle_stores_write_elapsed: AtomicU64,
    accounts_removed: AtomicUsize,
    bytes_removed: AtomicU64,
    bytes_written: AtomicU64,
    skipped_shrink: AtomicU64,
    dead_accounts: AtomicU64,
    alive_accounts: AtomicU64,
    accounts_loaded: AtomicU64,
}

/// Removing unrooted slots in Accounts Background Service needs to be synchronized with flushing
/// slots from the Accounts Cache.  This keeps track of those slots and the Mutex + Condvar for
/// synchronization.
#[derive(Debug, Default)]
struct RemoveUnrootedSlotsSynchronization {
    // slots being flushed from the cache or being purged
    slots_under_contention: Mutex<HashSet<Slot>>,
    signal: Condvar,
}

/// Persistent storage structure holding the accounts
#[derive(Debug)]
pub struct AccountStorageEntry {
    pub(crate) id: AtomicUsize,

    pub(crate) slot: AtomicU64,

    /// storage holding the accounts
    pub(crate) accounts: AppendVec,

    /// Keeps track of the number of accounts stored in a specific AppendVec.
    ///  This is periodically checked to reuse the stores that do not have
    ///  any accounts in it
    /// status corresponding to the storage, lets us know that
    ///  the append_vec, once maxed out, then emptied, can be reclaimed
    count_and_status: RwLock<(usize, AccountStorageStatus)>,

    /// This is the total number of accounts stored ever since initialized to keep
    /// track of lifetime count of all store operations. And this differs from
    /// count_and_status in that this field won't be decremented.
    ///
    /// This is used as a rough estimate for slot shrinking. As such a relaxed
    /// use case, this value ARE NOT strictly synchronized with count_and_status!
    approx_store_count: AtomicUsize,

    alive_bytes: AtomicUsize,
}

impl AccountStorageEntry {

    pub fn flush(&self) -> Result<(), IoError> {
        self.accounts.flush()
    }

    pub fn get_path(&self) -> PathBuf {
        self.accounts.get_path()
    }

    pub fn slot(&self) -> Slot {
        self.slot.load(Ordering::Acquire)
    }

    pub fn append_vec_id(&self) -> AppendVecId {
        self.id.load(Ordering::Acquire)
    }

    pub fn has_accounts(&self) -> bool {
        self.count() > 0
    }

    pub fn count(&self) -> usize {
        self.count_and_status.read().unwrap().0
    }

    fn get_stored_account_meta(&self, offset: usize) -> Option<StoredAccountMeta> {
        Some(self.accounts.get_account(offset)?.0)
    }

}

#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, AbiExample)]
pub struct BankHashStats {
    pub num_updated_accounts: u64,
    pub num_removed_accounts: u64,
    pub num_lamports_stored: u64,
    pub total_data_len: u64,
    pub num_executable_accounts: u64,
}

#[derive(Debug, Default)]
struct LatestAccountsIndexRootsStats {
    roots_len: AtomicUsize,
    uncleaned_roots_len: AtomicUsize,
    previous_uncleaned_roots_len: AtomicUsize,
    roots_range: AtomicU64,
    rooted_cleaned_count: AtomicUsize,
    unrooted_cleaned_count: AtomicUsize,
    clean_unref_from_storage_us: AtomicU64,
    clean_dead_slot_us: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
pub enum AccountShrinkThreshold {
    /// Measure the total space sparseness across all candididates
    /// And select the candidiates by using the top sparse account storage entries to shrink.
    /// The value is the overall shrink threshold measured as ratio of the total live bytes
    /// over the total bytes.
    TotalSpace { shrink_ratio: f64 },
    /// Use the following option to shrink all stores whose alive ratio is below
    /// the specified threshold.
    IndividalStore { shrink_ratio: f64 },
}

// Some hints for applicability of additional sanity checks for the do_load fast-path;
// Slower fallback code path will be taken if the fast path has failed over the retry
// threshold, regardless of these hints. Also, load cannot fail not-deterministically
// even under very rare circumstances, unlike previously did allow.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LoadHint {
    // Caller hints that it's loading transactions for a block which is
    // descended from the current root, and at the tip of its fork.
    // Thereby, further this assumes AccountIndex::max_root should not increase
    // during this load, meaning there should be no squash.
    // Overall, this enables us to assert!() strictly while running the fast-path for
    // account loading, while maintaining the determinism of account loading and resultant
    // transaction execution thereof.
    FixedMaxRoot,
    // Caller can't hint the above safety assumption. Generally RPC and miscellaneous
    // other call-site falls into this category. The likelihood of slower path is slightly
    // increased as well.
    Unspecified,
}


pub enum LoadedAccount<'a> {
    Stored(StoredAccountMeta<'a>),
    Cached(Cow<'a, CachedAccount>),
}

impl<'a> LoadedAccount<'a> {

    pub fn take_account(self) -> AccountSharedData {
        match self {
            LoadedAccount::Stored(stored_account_meta) => stored_account_meta.clone_account(),
            LoadedAccount::Cached(cached_account) => match cached_account {
                Cow::Owned(cached_account) => cached_account.account.clone(),
                Cow::Borrowed(cached_account) => cached_account.account.clone(),
            },
        }
    }

    pub fn is_cached(&self) -> bool {
        match self {
            LoadedAccount::Stored(_) => false,
            LoadedAccount::Cached(_) => true,
        }
    }
}

pub enum LoadedAccountAccessor<'a> {
    // StoredAccountMeta can't be held directly here due to its lifetime dependency to
    // AccountStorageEntry
    Stored(Option<(Arc<AccountStorageEntry>, usize)>),
    // None value in Cached variant means the cache was flushed
    Cached(Option<Cow<'a, CachedAccount>>),
}

impl<'a> LoadedAccountAccessor<'a> {
    fn check_and_get_loaded_account(&mut self) -> LoadedAccount {
        // all of these following .expect() and .unwrap() are like serious logic errors,
        // ideal for representing this as rust type system....

        match self {
            LoadedAccountAccessor::Cached(None) | LoadedAccountAccessor::Stored(None) => {
                panic!("Should have already been taken care of when creating this LoadedAccountAccessor");
            }
            LoadedAccountAccessor::Cached(Some(_cached_account)) => {
                // Cached(Some(x)) variant always produces `Some` for get_loaded_account() since
                // it just returns the inner `x` without additional fetches
                self.get_loaded_account().unwrap()
            }
            LoadedAccountAccessor::Stored(Some(_maybe_storage_entry)) => {
                // If we do find the storage entry, we can guarantee that the storage entry is
                // safe to read from because we grabbed a reference to the storage entry while it
                // was still in the storage map. This means even if the storage entry is removed
                // from the storage map after we grabbed the storage entry, the recycler should not
                // reset the storage entry until we drop the reference to the storage entry.
                self.get_loaded_account()
                    .expect("If a storage entry was found in the storage map, it must not have been reset yet")
            }
        }
    }

    fn get_loaded_account(&mut self) -> Option<LoadedAccount> {
        match self {
            LoadedAccountAccessor::Cached(cached_account) => {
                let cached_account: Cow<'a, CachedAccount> = cached_account.take().expect(
                    "Cache flushed/purged should be handled before trying to fetch account",
                );
                Some(LoadedAccount::Cached(cached_account))
            }
            LoadedAccountAccessor::Stored(maybe_storage_entry) => {
                // storage entry may not be present if slot was cleaned up in
                // between reading the accounts index and calling this function to
                // get account meta from the storage entry here
                maybe_storage_entry
                    .as_ref()
                    .and_then(|(storage_entry, offset)| {
                        storage_entry
                            .get_stored_account_meta(*offset)
                            .map(LoadedAccount::Stored)
                    })
            }
        }
    }
}

type AccountInfoAccountsIndex = AccountsIndex<AccountInfo>;
// This structure handles the load/store of the accounts
#[derive(Debug)]
pub struct AccountsDb {
    /// Keeps tracks of index into AppendVec on a per slot basis
    pub accounts_index: AccountInfoAccountsIndex,

    pub storage: AccountStorage,

    pub accounts_cache: AccountsCache,

    write_cache_limit_bytes: Option<u64>,

    sender_bg_hasher: Option<Sender<CachedAccount>>,
    read_only_accounts_cache: ReadOnlyAccountsCache,

    recycle_stores: RwLock<RecycleStores>,

    /// distribute the accounts across storage lists
    pub next_id: AtomicUsize,

    /// Set of shrinkable stores organized by map of slot to append_vec_id
    pub shrink_candidate_slots: Mutex<ShrinkCandidates>,

    /// Legacy shrink slots to support non-cached code-path.
    pub shrink_candidate_slots_v1: Mutex<Vec<Slot>>,

    pub(crate) write_version: AtomicU64,

    /// Set of storage paths to pick from
    pub(crate) paths: Vec<PathBuf>,

    accounts_hash_cache_path: PathBuf,

    // used by tests
    // holds this until we are dropped
    #[allow(dead_code)]
    temp_accounts_hash_cache_path: Option<TempDir>,

    pub shrink_paths: RwLock<Option<Vec<PathBuf>>>,

    /// Directory of paths this accounts_db needs to hold/remove
    #[allow(dead_code)]
    pub(crate) temp_paths: Option<Vec<TempDir>>,

    /// Starting file size of appendvecs
    file_size: u64,

    /// Thread pool used for par_iter
    pub thread_pool: ThreadPool,

    pub thread_pool_clean: ThreadPool,

    /// Number of append vecs to create to maximize parallelism when scanning
    /// the accounts
    min_num_stores: usize,

    pub bank_hashes: RwLock<HashMap<Slot, BankHashInfo>>,

    stats: AccountsStats,

    clean_accounts_stats: CleanAccountsStats,

    // Stats for purges called outside of clean_accounts()
    external_purge_slots_stats: PurgeStats,

    shrink_stats: ShrinkStats,

    pub cluster_type: Option<ClusterType>,

    pub account_indexes: AccountSecondaryIndexes,

    pub caching_enabled: bool,

    /// Set of unique keys per slot which is used
    /// to drive clean_accounts
    /// Generated by get_accounts_delta_hash
    uncleaned_pubkeys: DashMap<Slot, Vec<Pubkey>>,

    #[cfg(test)]
    load_delay: u64,

    // #[cfg(test)]
    load_limit: AtomicU64,

    is_bank_drop_callback_enabled: AtomicBool,

    /// Set of slots currently being flushed by `flush_slot_cache()` or removed
    /// by `remove_unrooted_slot()`. Used to ensure `remove_unrooted_slots(slots)`
    /// can safely clear the set of unrooted slots `slots`.
    remove_unrooted_slots_synchronization: RemoveUnrootedSlotsSynchronization,

    shrink_ratio: AccountShrinkThreshold,

    /// Set of stores which are recently rooted or had accounts removed
    /// such that potentially a 0-lamport account update could be present which
    /// means we can remove the account from the index entirely.
    dirty_stores: DashMap<(Slot, AppendVecId), Arc<AccountStorageEntry>>,

    /// Zero-lamport accounts that are *not* purged during clean because they need to stay alive
    /// for incremental snapshot support.
    zero_lamport_accounts_to_purge_after_full_snapshot: DashSet<(Slot, Pubkey)>,

    /// GeyserPlugin accounts update notifier
    accounts_update_notifier: Option<AccountsUpdateNotifier>,

    filler_account_count: usize,
    pub filler_account_suffix: Option<Pubkey>,

    // # of passes should be a function of the total # of accounts that are active.
    // higher passes = slower total time, lower dynamic memory usage
    // lower passes = faster total time, higher dynamic memory usage
    // passes=2 cuts dynamic memory usage in approximately half.
    pub num_hash_scan_passes: Option<usize>,
}

impl AccountsDb {

    pub fn load(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
        load_hint: LoadHint,
    ) -> Option<(AccountSharedData, Slot)> {
        self.do_load(ancestors, pubkey, None, load_hint)
    }

    fn do_load(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
        max_root: Option<Slot>,
        load_hint: LoadHint,
    ) -> Option<(AccountSharedData, Slot)> {
        #[cfg(not(test))]
        assert!(max_root.is_none());

        let (slot, store_id, offset, _maybe_account_accesor) =
            self.read_index_for_accessor_or_load_slow(ancestors, pubkey, max_root, false)?;
        // Notice the subtle `?` at previous line, we bail out pretty early if missing.

        if self.caching_enabled && store_id != CACHE_VIRTUAL_STORAGE_ID {
            let result = self.read_only_accounts_cache.load(*pubkey, slot);
            if let Some(account) = result {
                return Some((account, slot));
            }
        }

        let (mut account_accessor, slot) = self.retry_to_get_account_accessor(
            slot, store_id, offset, ancestors, pubkey, max_root, load_hint,
        )?;
        let loaded_account = account_accessor.check_and_get_loaded_account();
        let is_cached = loaded_account.is_cached();
        let account = loaded_account.take_account();

        if self.caching_enabled && !is_cached {
            /*
            We show this store into the read-only cache for account 'A' and future loads of 'A' from the read-only cache are
            safe/reflect 'A''s latest state on this fork.
            This safety holds if during replay of slot 'S', we show we only read 'A' from the write cache,
            not the read-only cache, after it's been updated in replay of slot 'S'.
            Assume for contradiction this is not true, and we read 'A' from the read-only cache *after* it had been updated in 'S'.
            This means an entry '(S, A)' was added to the read-only cache after 'A' had been updated in 'S'.
            Now when '(S, A)' was being added to the read-only cache, it must have been true that  'is_cache == false',
            which means '(S', A)' does not exist in the write cache yet.
            However, by the assumption for contradiction above ,  'A' has already been updated in 'S' which means '(S, A)'
            must exist in the write cache, which is a contradiction.
            */
            self.read_only_accounts_cache
                .store(*pubkey, slot, account.clone());
        }
        Some((account, slot))
    }

    fn read_index_for_accessor_or_load_slow<'a>(
        &'a self,
        ancestors: &Ancestors,
        pubkey: &'a Pubkey,
        max_root: Option<Slot>,
        clone_in_lock: bool,
    ) -> Option<(Slot, AppendVecId, usize, Option<LoadedAccountAccessor<'a>>)> {
        let (lock, index) = match self.accounts_index.get(pubkey, Some(ancestors), max_root) {
            AccountIndexGetResult::Found(lock, index) => (lock, index),
            // we bail out pretty early for missing.
            AccountIndexGetResult::NotFoundOnFork => {
                return None;
            }
            AccountIndexGetResult::Missing(_) => {
                return None;
            }
        };

        let slot_list = lock.slot_list();
        let (
            slot,
            AccountInfo {
                store_id, offset, ..
            },
        ) = slot_list[index];

        let some_from_slow_path = if clone_in_lock {
            // the fast path must have failed.... so take the slower approach
            // of copying potentially large Account::data inside the lock.

            // calling check_and_get_loaded_account is safe as long as we're guaranteed to hold
            // the lock during the time and there should be no purge thanks to alive ancestors
            // held by our caller.
            Some(self.get_account_accessor(slot, pubkey, store_id, offset))
        } else {
            None
        };

        Some((slot, store_id, offset, some_from_slow_path))
        // `lock` is dropped here rather pretty quickly with clone_in_lock = false,
        // so the entry could be raced for mutation by other subsystems,
        // before we actually provision an account data for caller's use from now on.
        // This is traded for less contention and resultant performance, introducing fair amount of
        // delicate handling in retry_to_get_account_accessor() below ;)
        // you're warned!
    }

    pub fn get_accounts_hash(&self, slot: Slot) -> Hash {
        let bank_hashes = self.bank_hashes.read().unwrap();
        let bank_hash_info = bank_hashes.get(&slot).unwrap();
        bank_hash_info.snapshot_hash
    }

    pub fn get_snapshot_storages(
        &self,
        snapshot_slot: Slot,
        snapshot_base_slot: Option<Slot>,
        ancestors: Option<&Ancestors>,
    ) -> (SnapshotStorages, Vec<Slot>) {
        let mut m = Measure::start("get slots");
        let slots = self
            .storage
            .0
            .iter()
            .map(|k| *k.key() as Slot)
            .collect::<Vec<_>>();
        m.stop();
        let mut m2 = Measure::start("filter");

        let chunk_size = 5_000;
        let wide = self.thread_pool_clean.install(|| {
            slots
                .par_chunks(chunk_size)
                .map(|slots| {
                    slots
                        .iter()
                        .filter_map(|slot| {
                            if *slot <= snapshot_slot
                                && snapshot_base_slot
                                    .map_or(true, |snapshot_base_slot| *slot > snapshot_base_slot)
                                && (self.accounts_index.is_root(*slot)
                                    || ancestors
                                        .map(|ancestors| ancestors.contains_key(slot))
                                        .unwrap_or_default())
                            {
                                self.storage.0.get(slot).map_or_else(
                                    || None,
                                    |item| {
                                        let storages = item
                                            .value()
                                            .read()
                                            .unwrap()
                                            .values()
                                            .filter(|x| x.has_accounts())
                                            .cloned()
                                            .collect::<Vec<_>>();
                                        if !storages.is_empty() {
                                            Some((storages, *slot))
                                        } else {
                                            None
                                        }
                                    },
                                )
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<(SnapshotStorage, Slot)>>()
                })
                .collect::<Vec<_>>()
        });
        m2.stop();
        let mut m3 = Measure::start("flatten");
        // some slots we found above may not have been a root or met the slot # constraint.
        // So the resulting 'slots' vector we return will be a subset of the raw keys we got initially.
        let mut slots = Vec::with_capacity(slots.len());
        let result = wide
            .into_iter()
            .flatten()
            .map(|(storage, slot)| {
                slots.push(slot);
                storage
            })
            .collect::<Vec<_>>();
        m3.stop();

        debug!(
            "hash_total: get slots: {}, filter: {}, flatten: {}",
            m.as_us(),
            m2.as_us(),
            m3.as_us()
        );
        (result, slots)
    }

    // fn max_clean_root(&self, proposed_clean_root: Option<Slot>) -> Option<Slot> {
    //     match (
    //         self.accounts_index.min_ongoing_scan_root(),
    //         proposed_clean_root,
    //     ) {
    //         (None, None) => None,
    //         (Some(min_scan_root), None) => Some(min_scan_root),
    //         (None, Some(proposed_clean_root)) => Some(proposed_clean_root),
    //         (Some(min_scan_root), Some(proposed_clean_root)) => {
    //             Some(std::cmp::min(min_scan_root, proposed_clean_root))
    //         }
    //     }
    // }

    // // Purge zero lamport accounts and older rooted account states as garbage
    // // collection
    // // Only remove those accounts where the entire rooted history of the account
    // // can be purged because there are no live append vecs in the ancestors
    // pub fn clean_accounts(
    //     &self,
    //     max_clean_root: Option<Slot>,
    //     is_startup: bool,
    //     last_full_snapshot_slot: Option<Slot>,
    // ) {
    //     let mut measure_all = Measure::start("clean_accounts");
    //     let max_clean_root = self.max_clean_root(max_clean_root);

    //     // hold a lock to prevent slot shrinking from running because it might modify some rooted
    //     // slot storages which can not happen as long as we're cleaning accounts because we're also
    //     // modifying the rooted slot storages!
    //     let mut candidates_v1 = self.shrink_candidate_slots_v1.lock().unwrap();
    //     self.report_store_stats();

    //     let mut key_timings = CleanKeyTimings::default();
    //     let mut pubkeys = self.construct_candidate_clean_keys(
    //         max_clean_root,
    //         last_full_snapshot_slot,
    //         &mut key_timings,
    //     );

    //     let mut sort = Measure::start("sort");
    //     if is_startup {
    //         pubkeys.par_sort_unstable();
    //     } else {
    //         self.thread_pool_clean
    //             .install(|| pubkeys.par_sort_unstable());
    //     }
    //     sort.stop();

    //     let total_keys_count = pubkeys.len();
    //     let mut accounts_scan = Measure::start("accounts_scan");
    //     let uncleaned_roots = self.accounts_index.clone_uncleaned_roots();
    //     let uncleaned_roots_len = self.accounts_index.uncleaned_roots_len();
    //     let found_not_zero_accum = AtomicU64::new(0);
    //     let not_found_on_fork_accum = AtomicU64::new(0);
    //     let missing_accum = AtomicU64::new(0);
    //     let useful_accum = AtomicU64::new(0);

    //     // parallel scan the index.
    //     let (mut purges_zero_lamports, purges_old_accounts) = {
    //         let do_clean_scan = || {
    //             pubkeys
    //                 .par_chunks(4096)
    //                 .map(|pubkeys: &[Pubkey]| {
    //                     let mut purges_zero_lamports = HashMap::new();
    //                     let mut purges_old_accounts = Vec::new();
    //                     let mut found_not_zero = 0;
    //                     let mut not_found_on_fork = 0;
    //                     let mut missing = 0;
    //                     let mut useful = 0;
    //                     self.accounts_index.scan(
    //                         pubkeys,
    //                         max_clean_root,
    //                         // return true if we want this item to remain in the cache
    //                         |exists, slot_list, index_in_slot_list, pubkey, ref_count| {
    //                             let mut useless = true;
    //                             if !exists {
    //                                 missing += 1;
    //                             } else {
    //                                 match index_in_slot_list {
    //                                     Some(index_in_slot_list) => {
    //                                         // found info relative to max_clean_root
    //                                         let (slot, account_info) =
    //                                             &slot_list[index_in_slot_list];
    //                                         if account_info.lamports == 0 {
    //                                             useless = false;
    //                                             purges_zero_lamports.insert(
    //                                                 *pubkey,
    //                                                 (
    //                                                     self.accounts_index.get_rooted_entries(
    //                                                         slot_list,
    //                                                         max_clean_root,
    //                                                     ),
    //                                                     ref_count,
    //                                                 ),
    //                                             );
    //                                         } else {
    //                                             found_not_zero += 1;
    //                                         }
    //                                         let slot = *slot;

    //                                         if uncleaned_roots.contains(&slot) {
    //                                             // Assertion enforced by `accounts_index.get()`, the latest slot
    //                                             // will not be greater than the given `max_clean_root`
    //                                             if let Some(max_clean_root) = max_clean_root {
    //                                                 assert!(slot <= max_clean_root);
    //                                             }
    //                                             purges_old_accounts.push(*pubkey);
    //                                             useless = false;
    //                                         }
    //                                     }
    //                                     None => {
    //                                         // This pubkey is in the index but not in a root slot, so clean
    //                                         // it up by adding it to the to-be-purged list.
    //                                         //
    //                                         // Also, this pubkey must have been touched by some slot since
    //                                         // it was in the dirty list, so we assume that the slot it was
    //                                         // touched in must be unrooted.
    //                                         not_found_on_fork += 1;
    //                                         useless = false;
    //                                         purges_old_accounts.push(*pubkey);
    //                                     }
    //                                 }
    //                             }
    //                             if !useless {
    //                                 useful += 1;
    //                             }
    //                             !useless
    //                         },
    //                     );
    //                     found_not_zero_accum.fetch_add(found_not_zero, Ordering::Relaxed);
    //                     not_found_on_fork_accum.fetch_add(not_found_on_fork, Ordering::Relaxed);
    //                     missing_accum.fetch_add(missing, Ordering::Relaxed);
    //                     useful_accum.fetch_add(useful, Ordering::Relaxed);
    //                     (purges_zero_lamports, purges_old_accounts)
    //                 })
    //                 .reduce(
    //                     || (HashMap::new(), Vec::new()),
    //                     |mut m1, m2| {
    //                         // Collapse down the hashmaps/vecs into one.
    //                         m1.0.extend(m2.0);
    //                         m1.1.extend(m2.1);
    //                         m1
    //                     },
    //                 )
    //         };
    //         if is_startup {
    //             do_clean_scan()
    //         } else {
    //             self.thread_pool_clean.install(do_clean_scan)
    //         }
    //     };
    //     accounts_scan.stop();

    //     let mut clean_old_rooted = Measure::start("clean_old_roots");
    //     let (purged_account_slots, removed_accounts) =
    //         self.clean_accounts_older_than_root(purges_old_accounts, max_clean_root);

    //     if self.caching_enabled {
    //         self.do_reset_uncleaned_roots(max_clean_root);
    //     } else {
    //         self.do_reset_uncleaned_roots_v1(&mut candidates_v1, max_clean_root);
    //     }
    //     clean_old_rooted.stop();

    //     let mut store_counts_time = Measure::start("store_counts");

    //     // Calculate store counts as if everything was purged
    //     // Then purge if we can
    //     let mut store_counts: HashMap<AppendVecId, (usize, HashSet<Pubkey>)> = HashMap::new();
    //     for (key, (account_infos, ref_count)) in purges_zero_lamports.iter_mut() {
    //         if purged_account_slots.contains_key(key) {
    //             *ref_count = self.accounts_index.ref_count_from_storage(key);
    //         }
    //         account_infos.retain(|(slot, account_info)| {
    //             let was_slot_purged = purged_account_slots
    //                 .get(key)
    //                 .map(|slots_removed| slots_removed.contains(slot))
    //                 .unwrap_or(false);
    //             if was_slot_purged {
    //                 // No need to look up the slot storage below if the entire
    //                 // slot was purged
    //                 return false;
    //             }
    //             // Check if this update in `slot` to the account with `key` was reclaimed earlier by
    //             // `clean_accounts_older_than_root()`
    //             let was_reclaimed = removed_accounts
    //                 .get(&account_info.store_id)
    //                 .map(|store_removed| store_removed.contains(&account_info.offset))
    //                 .unwrap_or(false);
    //             if was_reclaimed {
    //                 return false;
    //             }
    //             if let Some(store_count) = store_counts.get_mut(&account_info.store_id) {
    //                 store_count.0 -= 1;
    //                 store_count.1.insert(*key);
    //             } else {
    //                 let mut key_set = HashSet::new();
    //                 key_set.insert(*key);
    //                 assert!(
    //                     !account_info.is_cached(),
    //                     "The Accounts Cache must be flushed first for this account info. pubkey: {}, slot: {}",
    //                     *key,
    //                     *slot
    //                 );
    //                 let count = self
    //                     .storage
    //                     .slot_store_count(*slot, account_info.store_id)
    //                     .unwrap()
    //                     - 1;
    //                 debug!(
    //                     "store_counts, inserting slot: {}, store id: {}, count: {}",
    //                     slot, account_info.store_id, count
    //                 );
    //                 store_counts.insert(account_info.store_id, (count, key_set));
    //             }
    //             true
    //         });
    //     }
    //     store_counts_time.stop();

    //     let mut calc_deps_time = Measure::start("calc_deps");
    //     Self::calc_delete_dependencies(&purges_zero_lamports, &mut store_counts);
    //     calc_deps_time.stop();

    //     let mut purge_filter = Measure::start("purge_filter");
    //     self.filter_zero_lamport_clean_for_incremental_snapshots(
    //         max_clean_root,
    //         last_full_snapshot_slot,
    //         &store_counts,
    //         &mut purges_zero_lamports,
    //     );
    //     purge_filter.stop();

    //     let mut reclaims_time = Measure::start("reclaims");
    //     // Recalculate reclaims with new purge set
    //     let pubkey_to_slot_set: Vec<_> = purges_zero_lamports
    //         .into_iter()
    //         .map(|(key, (slots_list, _ref_count))| {
    //             (
    //                 key,
    //                 slots_list
    //                     .into_iter()
    //                     .map(|(slot, _)| slot)
    //                     .collect::<HashSet<Slot>>(),
    //             )
    //         })
    //         .collect();

    //     let reclaims = self.purge_keys_exact(pubkey_to_slot_set.iter());

    //     // Don't reset from clean, since the pubkeys in those stores may need to be unref'ed
    //     // and those stores may be used for background hashing.
    //     let reset_accounts = false;
    //     let mut reclaim_result = ReclaimResult::default();
    //     let reclaim_result = Some(&mut reclaim_result);
    //     self.handle_reclaims(
    //         &reclaims,
    //         None,
    //         Some(&self.clean_accounts_stats.purge_stats),
    //         reclaim_result,
    //         reset_accounts,
    //     );

    //     reclaims_time.stop();
    //     measure_all.stop();

    //     self.clean_accounts_stats.report();
    //     datapoint_info!(
    //         "clean_accounts",
    //         ("total_us", measure_all.as_us(), i64),
    //         (
    //             "collect_delta_keys_us",
    //             key_timings.collect_delta_keys_us,
    //             i64
    //         ),
    //         (
    //             "dirty_store_processing_us",
    //             key_timings.dirty_store_processing_us,
    //             i64
    //         ),
    //         ("accounts_scan", accounts_scan.as_us() as i64, i64),
    //         ("clean_old_rooted", clean_old_rooted.as_us() as i64, i64),
    //         ("store_counts", store_counts_time.as_us() as i64, i64),
    //         ("purge_filter", purge_filter.as_us() as i64, i64),
    //         ("calc_deps", calc_deps_time.as_us() as i64, i64),
    //         ("reclaims", reclaims_time.as_us() as i64, i64),
    //         ("delta_insert_us", key_timings.delta_insert_us, i64),
    //         ("delta_key_count", key_timings.delta_key_count, i64),
    //         ("dirty_pubkeys_count", key_timings.dirty_pubkeys_count, i64),
    //         ("sort_us", sort.as_us(), i64),
    //         ("useful_keys", useful_accum.load(Ordering::Relaxed), i64),
    //         ("total_keys_count", total_keys_count, i64),
    //         (
    //             "scan_found_not_zero",
    //             found_not_zero_accum.load(Ordering::Relaxed),
    //             i64
    //         ),
    //         (
    //             "scan_not_found_on_fork",
    //             not_found_on_fork_accum.load(Ordering::Relaxed),
    //             i64
    //         ),
    //         ("scan_missing", missing_accum.load(Ordering::Relaxed), i64),
    //         ("uncleaned_roots_len", uncleaned_roots_len, i64),
    //         (
    //             "clean_old_root_us",
    //             self.clean_accounts_stats
    //                 .clean_old_root_us
    //                 .swap(0, Ordering::Relaxed),
    //             i64
    //         ),
    //         (
    //             "clean_old_root_reclaim_us",
    //             self.clean_accounts_stats
    //                 .clean_old_root_reclaim_us
    //                 .swap(0, Ordering::Relaxed),
    //             i64
    //         ),
    //         (
    //             "reset_uncleaned_roots_us",
    //             self.clean_accounts_stats
    //                 .reset_uncleaned_roots_us
    //                 .swap(0, Ordering::Relaxed),
    //             i64
    //         ),
    //         (
    //             "remove_dead_accounts_remove_us",
    //             self.clean_accounts_stats
    //                 .remove_dead_accounts_remove_us
    //                 .swap(0, Ordering::Relaxed),
    //             i64
    //         ),
    //         (
    //             "remove_dead_accounts_shrink_us",
    //             self.clean_accounts_stats
    //                 .remove_dead_accounts_shrink_us
    //                 .swap(0, Ordering::Relaxed),
    //             i64
    //         ),
    //         (
    //             "clean_stored_dead_slots_us",
    //             self.clean_accounts_stats
    //                 .clean_stored_dead_slots_us
    //                 .swap(0, Ordering::Relaxed),
    //             i64
    //         ),
    //     );
    // }

    fn get_account_accessor<'a>(
        &'a self,
        slot: Slot,
        pubkey: &'a Pubkey,
        store_id: usize,
        offset: usize,
    ) -> LoadedAccountAccessor<'a> {
        if store_id == CACHE_VIRTUAL_STORAGE_ID {
            let maybe_cached_account = self.accounts_cache.load(slot, pubkey).map(Cow::Owned);
            LoadedAccountAccessor::Cached(maybe_cached_account)
        } else {
            let maybe_storage_entry = self
                .storage
                .get_account_storage_entry(slot, store_id)
                .map(|account_storage_entry| (account_storage_entry, offset));
            LoadedAccountAccessor::Stored(maybe_storage_entry)
        }
    }

    fn retry_to_get_account_accessor<'a>(
        &'a self,
        mut slot: Slot,
        mut store_id: usize,
        mut offset: usize,
        ancestors: &'a Ancestors,
        pubkey: &'a Pubkey,
        max_root: Option<Slot>,
        load_hint: LoadHint,
    ) -> Option<(LoadedAccountAccessor<'a>, Slot)> {
        #[cfg(test)]
        {
            // Give some time for cache flushing to occur here for unit tests
            sleep(Duration::from_millis(self.load_delay));
        }

        // Failsafe for potential race conditions with other subsystems
        let mut num_acceptable_failed_iterations = 0;
        loop {
            let account_accessor = self.get_account_accessor(slot, pubkey, store_id, offset);
            match account_accessor {
                LoadedAccountAccessor::Cached(Some(_)) | LoadedAccountAccessor::Stored(Some(_)) => {
                    // Great! There was no race, just return :) This is the most usual situation
                    return Some((account_accessor, slot));
                }
                LoadedAccountAccessor::Cached(None) => {
                    num_acceptable_failed_iterations += 1;
                    // Cache was flushed in between checking the index and retrieving from the cache,
                    // so retry. This works because in accounts cache flush, an account is written to
                    // storage *before* it is removed from the cache
                    match load_hint {
                        LoadHint::FixedMaxRoot => {
                            // it's impossible for this to fail for transaction loads from
                            // replaying/banking more than once.
                            // This is because:
                            // 1) For a slot `X` that's being replayed, there is only one
                            // latest ancestor containing the latest update for the account, and this
                            // ancestor can only be flushed once.
                            // 2) The root cannot move while replaying, so the index cannot continually
                            // find more up to date entries than the current `slot`
                            assert!(num_acceptable_failed_iterations <= 1);
                        }
                        LoadHint::Unspecified => {
                            // Because newer root can be added to the index (= not fixed),
                            // multiple flush race conditions can be observed under very rare
                            // condition, at least theoretically
                        }
                    }
                }
                LoadedAccountAccessor::Stored(None) => {
                    match load_hint {
                        LoadHint::FixedMaxRoot => {
                            // When running replay on the validator, or banking stage on the leader,
                            // it should be very rare that the storage entry doesn't exist if the
                            // entry in the accounts index is the latest version of this account.
                            //
                            // There are only a few places where the storage entry may not exist
                            // after reading the index:
                            // 1) Shrink has removed the old storage entry and rewritten to
                            // a newer storage entry
                            // 2) The `pubkey` asked for in this function is a zero-lamport account,
                            // and the storage entry holding this account qualified for zero-lamport clean.
                            //
                            // In both these cases, it should be safe to retry and recheck the accounts
                            // index indefinitely, without incrementing num_acceptable_failed_iterations.
                            // That's because if the root is fixed, there should be a bounded number
                            // of pending cleans/shrinks (depends how far behind the AccountsBackgroundService
                            // is), termination to the desired condition is guaranteed.
                            //
                            // Also note that in both cases, if we do find the storage entry,
                            // we can guarantee that the storage entry is safe to read from because
                            // we grabbed a reference to the storage entry while it was still in the
                            // storage map. This means even if the storage entry is removed from the storage
                            // map after we grabbed the storage entry, the recycler should not reset the
                            // storage entry until we drop the reference to the storage entry.
                            //
                            // eh, no code in this arm? yes!
                        }
                        LoadHint::Unspecified => {
                            // RPC get_account() may have fetched an old root from the index that was
                            // either:
                            // 1) Cleaned up by clean_accounts(), so the accounts index has been updated
                            // and the storage entries have been removed.
                            // 2) Dropped by purge_slots() because the slot was on a minor fork, which
                            // removes the slots' storage entries but doesn't purge from the accounts index
                            // (account index cleanup is left to clean for stored slots). Note that
                            // this generally is impossible to occur in the wild because the RPC
                            // should hold the slot's bank, preventing it from being purged() to
                            // begin with.
                            num_acceptable_failed_iterations += 1;
                        }
                    }
                }
            }
            

            // #[cfg(test)]
            let load_limit = self.load_limit.load(Ordering::Relaxed);

            let fallback_to_slow_path = if num_acceptable_failed_iterations >= load_limit {
                // The latest version of the account existed in the index, but could not be
                // fetched from storage. This means a race occurred between this function and clean
                // accounts/purge_slots
                let message = format!(
                    "do_load() failed to get key: {} from storage, latest attempt was for \
                     slot: {}, storage_entry: {} offset: {}, load_hint: {:?}",
                    pubkey, slot, store_id, offset, load_hint,
                );
                datapoint_warn!("accounts_db-do_load_warn", ("warn", message, String));
                true
            } else {
                false
            };

            // Because reading from the cache/storage failed, retry from the index read
            let (new_slot, new_store_id, new_offset, maybe_account_accessor) = self
                .read_index_for_accessor_or_load_slow(
                    ancestors,
                    pubkey,
                    max_root,
                    fallback_to_slow_path,
                )?;
            // Notice the subtle `?` at previous line, we bail out pretty early if missing.

            if new_slot == slot && new_store_id == store_id {
                // Considering that we're failed to get accessor above and further that
                // the index still returned the same (slot, store_id) tuple, offset must be same
                // too.
                assert!(new_offset == offset);

                // If the entry was missing from the cache, that means it must have been flushed,
                // and the accounts index is always updated before cache flush, so store_id must
                // not indicate being cached at this point.
                assert!(new_store_id != CACHE_VIRTUAL_STORAGE_ID);

                // If this is not a cache entry, then this was a minor fork slot
                // that had its storage entries cleaned up by purge_slots() but hasn't been
                // cleaned yet. That means this must be rpc access and not replay/banking at the
                // very least. Note that purge shouldn't occur even for RPC as caller must hold all
                // of ancestor slots..
                assert!(load_hint == LoadHint::Unspecified);

                // Everything being assert!()-ed, let's panic!() here as it's an error condition
                // after all....
                // That reasoning is based on the fact all of code-path reaching this fn
                // retry_to_get_account_accessor() must outlive the Arc<Bank> (and its all
                // ancestors) over this fn invocation, guaranteeing the prevention of being purged,
                // first of all.
                // For details, see the comment in AccountIndex::do_checked_scan_accounts(),
                // which is referring back here.
                panic!(
                    "Bad index entry detected ({}, {}, {}, {}, {:?})",
                    pubkey, slot, store_id, offset, load_hint
                );
            } else if fallback_to_slow_path {
                // the above bad-index-entry check must had been checked first to retain the same
                // behavior
                return Some((
                    maybe_account_accessor.expect("must be some if clone_in_lock=true"),
                    new_slot,
                ));
            }

            slot = new_slot;
            store_id = new_store_id;
            offset = new_offset;
        }
    }
    
}
pub fn get_temp_accounts_paths(count: u32) -> IoResult<(Vec<TempDir>, Vec<PathBuf>)> {
    let temp_dirs: IoResult<Vec<TempDir>> = (0..count).map(|_| TempDir::new()).collect();
    let temp_dirs = temp_dirs?;
    let paths: Vec<PathBuf> = temp_dirs.iter().map(|t| t.path().to_path_buf()).collect();
    Ok((temp_dirs, paths))
}
