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

use crate::{accounts_index::{AccountsIndexConfig, ACCOUNTS_INDEX_CONFIG_FOR_TESTING}, append_vec::{StoredMetaWriteVersion, StoredMeta}};
use {
    crate::{
        cache_hash_data::CacheHashData,
        accounts_hash::{AccountsHash, CalculateHashIntermediate, HashStats, PreviousPass},
        sorted_storages::SortedStorages,
        // accounts_background_service::{DroppedSlotsSender, SendDroppedBankCallback},
        accounts_cache::{
            AccountsCache, 
            CachedAccount, 
            SlotCache
        },
        contains::Contains,
        // accounts_hash::{AccountsHash, CalculateHashIntermediate, HashStats, PreviousPass},
        accounts_index::{
            AccountIndexGetResult, 
            AccountSecondaryIndexes, AccountsIndex, 
            // AccountsIndexConfig,
            AccountsIndexRootsStats, IndexKey, 
            IndexValue, 
            IsCached, 
            SlotList,
            SlotSlice,
            RefCount, ScanConfig,
            ScanResult, 
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

mod geyser_plugin_utils;

pub type BinnedHashData = Vec<Vec<CalculateHashIntermediate>>;

pub struct AccountsAddRootTiming {
    pub index_us: u64,
    pub cache_us: u64,
    pub store_us: u64,
}

struct FoundStoredAccount<'a> {
    pub account: StoredAccountMeta<'a>,
    pub store_id: AppendVecId,
    pub account_size: usize,
}


// A specially reserved storage id just for entries in the cache, so that
// operations that take a storage entry can maintain a common interface
// when interacting with cached accounts. This id is "virtual" in that it
// doesn't actually refer to an actual storage entry.
const CACHE_VIRTUAL_STORAGE_ID: usize = AppendVecId::MAX;
const PAGE_SIZE: u64 = 4 * 1024;
const MAX_RECYCLE_STORES: usize = 1000;
const STORE_META_OVERHEAD: usize = 256;
// when the accounts write cache exceeds this many bytes, we will flush it
// this can be specified on the command line, too (--accounts-db-cache-limit-mb)
const WRITE_CACHE_LIMIT_BYTES_DEFAULT: u64 = 15_000_000_000;
const FLUSH_CACHE_RANDOM_THRESHOLD: usize = MAX_LOCKOUT_HISTORY;
const SCAN_SLOT_PAR_ITER_THRESHOLD: usize = 4000;

#[cfg(not(test))]
const ABSURD_CONSECUTIVE_FAILED_ITERATIONS: usize = 100;

pub const DEFAULT_FILE_SIZE: u64 = PAGE_SIZE * 1024;
pub const DEFAULT_NUM_THREADS: u32 = 8;
pub const DEFAULT_NUM_DIRS: u32 = 4;

// When calculating hashes, it is helpful to break the pubkeys found into bins based on the pubkey value.
// More bins means smaller vectors to sort, copy, etc.
pub const PUBKEY_BINS_FOR_CALCULATING_HASHES: usize = 65536;
pub const NUM_SCAN_PASSES_DEFAULT: usize = 2;

// Without chunks, we end up with 1 output vec for each outer snapshot storage.
// This results in too many vectors to be efficient.
// Chunks when scanning storages to calculate hashes.
// If this is too big, we don't get enough parallelism of scanning storages.
// If this is too small, then we produce too many output vectors to iterate.
// Metrics indicate a sweet spot in the 2.5k-5k range for mnb.
const MAX_ITEMS_PER_CHUNK: Slot = 2_500;

// A specially reserved write version (identifier for ordering writes in an AppendVec)
// for entries in the cache, so that  operations that take a storage entry can maintain
// a common interface when interacting with cached accounts. This version is "virtual" in
// that it doesn't actually map to an entry in an AppendVec.
const CACHE_VIRTUAL_WRITE_VERSION: StoredMetaWriteVersion = 0;

// A specially reserved offset (represents an offset into an AppendVec)
// for entries in the cache, so that  operations that take a storage entry can maintain
// a common interface when interacting with cached accounts. This version is "virtual" in
// that it doesn't actually map to an entry in an AppendVec.
const CACHE_VIRTUAL_OFFSET: usize = 0;
const CACHE_VIRTUAL_STORED_SIZE: usize = 0;

// pub const ACCOUNTS_DB_CONFIG_FOR_BENCHMARKS: AccountsDbConfig = AccountsDbConfig {
//     index: Some(ACCOUNTS_INDEX_CONFIG_FOR_BENCHMARKS),
//     accounts_hash_cache_path: None,
//     filler_account_count: None,
//     hash_calc_num_passes: None,
//     write_cache_limit_bytes: None,
// };

// type AccountInfoAccountsIndex = AccountsIndex<AccountInfo>;
type ShrinkCandidates = HashMap<Slot, HashMap<AppendVecId, Arc<AccountStorageEntry>>>;
type StorageFinder<'a> = Box<dyn Fn(Slot, usize) -> Arc<AccountStorageEntry> + 'a>;
/// An offset into the AccountsDb::storage vector
pub type AppendVecId = usize;
type AccountSlots = HashMap<Pubkey, HashSet<Slot>>;
type AppendVecOffsets = HashMap<AppendVecId, HashSet<usize>>;
type ReclaimResult = (AccountSlots, AppendVecOffsets);
// Each slot has a set of storage entries.
pub(crate) type SlotStores = Arc<RwLock<HashMap<usize, Arc<AccountStorageEntry>>>>;

#[derive(Debug, Default, Clone, Copy)]
struct SlotIndexGenerationInfo {
    insert_time_us: u64,
    num_accounts: u64,
    num_accounts_rent_exempt: u64,
    accounts_data_len: u64,
}

#[derive(Default, Debug, PartialEq)]
struct StorageSizeAndCount {
    pub stored_size: usize,
    pub count: usize,
}
type StorageSizeAndCountMap = DashMap<AppendVecId, StorageSizeAndCount>;

#[derive(Default, Debug)]
struct GenerateIndexTimings {
    pub index_time: u64,
    pub scan_time: u64,
    pub insertion_time_us: u64,
    pub min_bin_size: usize,
    pub max_bin_size: usize,
    pub total_items: usize,
    pub storage_size_accounts_map_us: u64,
    pub storage_size_storages_us: u64,
    pub storage_size_accounts_map_flatten_us: u64,
    pub index_flush_us: u64,
    pub rent_exempt: u64,
    pub total_duplicates: u64,
    pub accounts_data_len_dedup_time_us: u64,
}

impl GenerateIndexTimings {
    pub fn report(&self) {
        datapoint_info!(
            "generate_index",
            // we cannot accurately measure index insertion time because of many threads and lock contention
            ("total_us", self.index_time, i64),
            ("scan_stores_us", self.scan_time, i64),
            ("insertion_time_us", self.insertion_time_us, i64),
            ("min_bin_size", self.min_bin_size as i64, i64),
            ("max_bin_size", self.max_bin_size as i64, i64),
            (
                "storage_size_accounts_map_us",
                self.storage_size_accounts_map_us as i64,
                i64
            ),
            (
                "storage_size_storages_us",
                self.storage_size_storages_us as i64,
                i64
            ),
            (
                "storage_size_accounts_map_flatten_us",
                self.storage_size_accounts_map_flatten_us as i64,
                i64
            ),
            ("index_flush_us", self.index_flush_us as i64, i64),
            (
                "total_rent_paying_with_duplicates",
                self.total_duplicates.saturating_sub(self.rent_exempt) as i64,
                i64
            ),
            (
                "total_items_with_duplicates",
                self.total_duplicates as i64,
                i64
            ),
            ("total_items", self.total_items as i64, i64),
            (
                "accounts_data_len_dedup_time_us",
                self.accounts_data_len_dedup_time_us as i64,
                i64
            ),
        );
    }
}

struct MultiThreadProgress<'a> {
    last_update: Instant,
    my_last_report_count: u64,
    total_count: &'a AtomicU64,
    report_delay_secs: u64,
    first_caller: bool,
    ultimate_count: u64,
}

impl<'a> MultiThreadProgress<'a> {
    fn new(total_count: &'a AtomicU64, report_delay_secs: u64, ultimate_count: u64) -> Self {
        Self {
            last_update: Instant::now(),
            my_last_report_count: 0,
            total_count,
            report_delay_secs,
            first_caller: false,
            ultimate_count,
        }
    }
    fn report(&mut self, my_current_count: u64) {
        let now = Instant::now();
        if now.duration_since(self.last_update).as_secs() >= self.report_delay_secs {
            let my_total_newly_processed_slots_since_last_report =
                my_current_count - self.my_last_report_count;

            self.my_last_report_count = my_current_count;
            let previous_total_processed_slots_across_all_threads = self.total_count.fetch_add(
                my_total_newly_processed_slots_since_last_report,
                Ordering::Relaxed,
            );
            self.first_caller =
                self.first_caller || 0 == previous_total_processed_slots_across_all_threads;
            if self.first_caller {
                info!(
                    "generating index: {}/{} slots...",
                    previous_total_processed_slots_across_all_threads
                        + my_total_newly_processed_slots_since_last_report,
                    self.ultimate_count
                );
            }
            self.last_update = now;
        }
    }
}

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

impl IsCached for AccountInfo {
    fn is_cached(&self) -> bool {
        self.store_id == CACHE_VIRTUAL_STORAGE_ID
    }
}

impl IndexValue for AccountInfo {}

impl ZeroLamport for AccountInfo {
    fn is_zero_lamport(&self) -> bool {
        self.lamports == 0
    }
}

impl ZeroLamport for AccountSharedData {
    fn is_zero_lamport(&self) -> bool {
        self.wens() == 0
    }
}

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

impl RecycleStores{
    fn add_entry(&mut self, new_entry: Arc<AccountStorageEntry>) {
        self.total_bytes += new_entry.total_bytes();
        self.entries.push((Instant::now(), new_entry))
    }

    fn remove_entry(&mut self, index: usize) -> Arc<AccountStorageEntry> {
        let (_added_time, removed_entry) = self.entries.swap_remove(index);
        self.total_bytes -= removed_entry.total_bytes();
        removed_entry
    }

    fn iter(&self) -> std::slice::Iter<(Instant, Arc<AccountStorageEntry>)> {
        self.entries.iter()
    }

    fn add_entries(&mut self, new_entries: Vec<Arc<AccountStorageEntry>>) {
        self.total_bytes += new_entries.iter().map(|e| e.total_bytes()).sum::<u64>();
        let now = Instant::now();
        for new_entry in new_entries {
            self.entries.push((now, new_entry));
        }
    }

    fn entry_count(&self) -> usize {
        self.entries.len()
    }

    fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
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

impl CleanAccountsStats {
    fn report(&self) {
        self.purge_stats.report("clean_purge_slots_stats", None);
        self.latest_accounts_index_roots_stats.report();
    }
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

impl PurgeStats{
    fn report(&self, metric_name: &'static str, report_interval_ms: Option<u64>) {
        let should_report = report_interval_ms
            .map(|report_interval_ms| self.last_report.should_update(report_interval_ms))
            .unwrap_or(true);

        if should_report {
            datapoint_info!(
                metric_name,
                (
                    "safety_checks_elapsed",
                    self.safety_checks_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "remove_cache_elapsed",
                    self.remove_cache_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "remove_storage_entries_elapsed",
                    self.remove_storage_entries_elapsed
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "drop_storage_entries_elapsed",
                    self.drop_storage_entries_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "num_cached_slots_removed",
                    self.num_cached_slots_removed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "num_stored_slots_removed",
                    self.num_stored_slots_removed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "total_removed_storage_entries",
                    self.total_removed_storage_entries
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "total_removed_cached_bytes",
                    self.total_removed_cached_bytes.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "total_removed_stored_bytes",
                    self.total_removed_stored_bytes.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "recycle_stores_write_elapsed",
                    self.recycle_stores_write_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "scan_storages_elasped",
                    self.scan_storages_elasped.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "purge_accounts_index_elapsed",
                    self.purge_accounts_index_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "handle_reclaims_elapsed",
                    self.handle_reclaims_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
            );
        }
    }
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

impl ShrinkStats{
    fn report(&self) {
        if self.last_report.should_update(1000) {
            datapoint_info!(
                "shrink_stats",
                (
                    "num_slots_shrunk",
                    self.num_slots_shrunk.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "storage_read_elapsed",
                    self.storage_read_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "index_read_elapsed",
                    self.index_read_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "find_alive_elapsed",
                    self.find_alive_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "create_and_insert_store_elapsed",
                    self.create_and_insert_store_elapsed
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "store_accounts_elapsed",
                    self.store_accounts_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "update_index_elapsed",
                    self.update_index_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "handle_reclaims_elapsed",
                    self.handle_reclaims_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "write_storage_elapsed",
                    self.write_storage_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "rewrite_elapsed",
                    self.rewrite_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "drop_storage_entries_elapsed",
                    self.drop_storage_entries_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "recycle_stores_write_time",
                    self.recycle_stores_write_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "accounts_removed",
                    self.accounts_removed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "bytes_removed",
                    self.bytes_removed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "bytes_written",
                    self.bytes_written.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "skipped_shrink",
                    self.skipped_shrink.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "alive_accounts",
                    self.alive_accounts.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "dead_accounts",
                    self.dead_accounts.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "accounts_loaded",
                    self.accounts_loaded.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
            );
        }
    }
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
    fn remove_account(&self, num_bytes: usize, reset_accounts: bool) -> usize {
        let mut count_and_status = self.count_and_status.write().unwrap();
        let (mut count, mut status) = *count_and_status;

        if count == 1 && status == AccountStorageStatus::Full && reset_accounts {
            // this case arises when we remove the last account from the
            //  storage, but we've learned from previous write attempts that
            //  the storage is full
            //
            // the only time it's safe to call reset() on an append_vec is when
            //  every account has been removed
            //          **and**
            //  the append_vec has previously been completely full
            //
            // otherwise, the storage may be in flight with a store()
            //   call
            self.accounts.reset();
            status = AccountStorageStatus::Available;
        }

        // Some code path is removing accounts too many; this may result in an
        // unintended reveal of old state for unrelated accounts.
        assert!(
            count > 0,
            "double remove of account in slot: {}/store: {}!!",
            self.slot(),
            self.append_vec_id(),
        );

        self.alive_bytes.fetch_sub(num_bytes, Ordering::SeqCst);
        count -= 1;
        *count_and_status = (count, status);
        count
    }

    fn try_available(&self) -> bool {
        let mut count_and_status = self.count_and_status.write().unwrap();
        let (count, status) = *count_and_status;

        if status == AccountStorageStatus::Available {
            *count_and_status = (count, AccountStorageStatus::Candidate);
            true
        } else {
            false
        }
    }

    fn add_account(&self, num_bytes: usize) {
        let mut count_and_status = self.count_and_status.write().unwrap();
        *count_and_status = (count_and_status.0 + 1, count_and_status.1);
        self.approx_store_count.fetch_add(1, Ordering::Relaxed);
        self.alive_bytes.fetch_add(num_bytes, Ordering::SeqCst);
    }

    pub fn status(&self) -> AccountStorageStatus {
        self.count_and_status.read().unwrap().1
    }

    pub fn set_status(&self, mut status: AccountStorageStatus) {
        let mut count_and_status = self.count_and_status.write().unwrap();

        let count = count_and_status.0;

        if status == AccountStorageStatus::Full && count == 0 {
            // this case arises when the append_vec is full (store_ptrs fails),
            //  but all accounts have already been removed from the storage
            //
            // the only time it's safe to call reset() on an append_vec is when
            //  every account has been removed
            //          **and**
            //  the append_vec has previously been completely full
            //
            self.accounts.reset();
            status = AccountStorageStatus::Available;
        }

        *count_and_status = (count, status);
    }

    pub fn written_bytes(&self) -> u64 {
        self.accounts.len() as u64
    }

    pub fn recycle(&self, slot: Slot, id: usize) {
        let mut count_and_status = self.count_and_status.write().unwrap();
        self.accounts.reset();
        *count_and_status = (0, AccountStorageStatus::Available);
        self.slot.store(slot, Ordering::Release);
        self.id.store(id, Ordering::Release);
        self.approx_store_count.store(0, Ordering::Relaxed);
        self.alive_bytes.store(0, Ordering::Release);
    }

    pub fn new(path: &Path, slot: Slot, id: usize, file_size: u64) -> Self {
        let tail = AppendVec::file_name(slot, id);
        let path = Path::new(path).join(tail);
        let accounts = AppendVec::new(&path, true, file_size as usize);

        Self {
            id: AtomicUsize::new(id),
            slot: AtomicU64::new(slot),
            accounts,
            count_and_status: RwLock::new((0, AccountStorageStatus::Available)),
            approx_store_count: AtomicUsize::new(0),
            alive_bytes: AtomicUsize::new(0),
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.accounts.capacity()
    }

    pub fn alive_bytes(&self) -> usize {
        self.alive_bytes.load(Ordering::SeqCst)
    }

    pub fn approx_stored_count(&self) -> usize {
        self.approx_store_count.load(Ordering::Relaxed)
    }

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

    pub(crate) fn new_existing(
        slot: Slot,
        id: AppendVecId,
        accounts: AppendVec,
        num_accounts: usize,
    ) -> Self {
        Self {
            id: AtomicUsize::new(id),
            slot: AtomicU64::new(slot),
            accounts,
            count_and_status: RwLock::new((0, AccountStorageStatus::Available)),
            approx_store_count: AtomicUsize::new(num_accounts),
            alive_bytes: AtomicUsize::new(0),
        }
    }

    pub fn all_accounts(&self) -> Vec<StoredAccountMeta> {
        self.accounts.accounts(0)
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

impl BankHashStats{
    pub fn update<T: ReadableAccount + ZeroLamport>(&mut self, account: &T) {
        if account.is_zero_lamport() {
            self.num_removed_accounts += 1;
        } else {
            self.num_updated_accounts += 1;
        }
        self.total_data_len = self
            .total_data_len
            .wrapping_add(account.data().len() as u64);
        if account.executable() {
            self.num_executable_accounts += 1;
        }
        self.num_lamports_stored = self.num_lamports_stored.wrapping_add(account.wens());
    }

    pub fn merge(&mut self, other: &BankHashStats) {
        self.num_updated_accounts += other.num_updated_accounts;
        self.num_removed_accounts += other.num_removed_accounts;
        self.total_data_len = self.total_data_len.wrapping_add(other.total_data_len);
        self.num_lamports_stored = self
            .num_lamports_stored
            .wrapping_add(other.num_lamports_stored);
        self.num_executable_accounts += other.num_executable_accounts;
    }
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

impl LatestAccountsIndexRootsStats{
    fn update(&self, accounts_index_roots_stats: &AccountsIndexRootsStats) {
        self.roots_len
            .store(accounts_index_roots_stats.roots_len, Ordering::Relaxed);
        self.uncleaned_roots_len.store(
            accounts_index_roots_stats.uncleaned_roots_len,
            Ordering::Relaxed,
        );
        self.previous_uncleaned_roots_len.store(
            accounts_index_roots_stats.previous_uncleaned_roots_len,
            Ordering::Relaxed,
        );
        self.roots_range
            .store(accounts_index_roots_stats.roots_range, Ordering::Relaxed);
        self.rooted_cleaned_count.fetch_add(
            accounts_index_roots_stats.rooted_cleaned_count,
            Ordering::Relaxed,
        );
        self.unrooted_cleaned_count.fetch_add(
            accounts_index_roots_stats.unrooted_cleaned_count,
            Ordering::Relaxed,
        );
        self.clean_unref_from_storage_us.fetch_add(
            accounts_index_roots_stats.clean_unref_from_storage_us,
            Ordering::Relaxed,
        );
        self.clean_dead_slot_us.fetch_add(
            accounts_index_roots_stats.clean_dead_slot_us,
            Ordering::Relaxed,
        );
    }

    fn report(&self) {
        datapoint_info!(
            "accounts_index_roots_len",
            (
                "roots_len",
                self.roots_len.load(Ordering::Relaxed) as i64,
                i64
            ),
            (
                "uncleaned_roots_len",
                self.uncleaned_roots_len.load(Ordering::Relaxed) as i64,
                i64
            ),
            (
                "previous_uncleaned_roots_len",
                self.previous_uncleaned_roots_len.load(Ordering::Relaxed) as i64,
                i64
            ),
            (
                "roots_range_width",
                self.roots_range.load(Ordering::Relaxed) as i64,
                i64
            ),
            (
                "unrooted_cleaned_count",
                self.unrooted_cleaned_count.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "rooted_cleaned_count",
                self.rooted_cleaned_count.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "clean_unref_from_storage_us",
                self.clean_unref_from_storage_us.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "clean_dead_slot_us",
                self.clean_dead_slot_us.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
        );

        // Don't need to reset since this tracks the latest updates, not a cumulative total
    }
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
    pub fn write_version(&self) -> StoredMetaWriteVersion {
        match self {
            LoadedAccount::Stored(stored_account_meta) => stored_account_meta.meta.write_version,
            LoadedAccount::Cached(_) => CACHE_VIRTUAL_WRITE_VERSION,
        }
    }

    pub fn lamports(&self) -> u64 {
        match self {
            LoadedAccount::Stored(stored_account_meta) => stored_account_meta.account_meta.lamports,
            LoadedAccount::Cached(cached_account) => cached_account.account.wens(),
        }
    }

    pub fn pubkey(&self) -> &Pubkey {
        match self {
            LoadedAccount::Stored(stored_account_meta) => &stored_account_meta.meta.pubkey,
            LoadedAccount::Cached(cached_account) => cached_account.pubkey(),
        }
    }

    pub fn compute_hash(&self, slot: Slot, pubkey: &Pubkey) -> Hash {
        match self {
            LoadedAccount::Stored(stored_account_meta) => {
                AccountsDb::hash_stored_account(slot, stored_account_meta)
            }
            LoadedAccount::Cached(cached_account) => {
                AccountsDb::hash_account(slot, &cached_account.account, pubkey)
            }
        }
    }

    pub fn loaded_hash(&self) -> Hash {
        match self {
            LoadedAccount::Stored(stored_account_meta) => *stored_account_meta.hash,
            LoadedAccount::Cached(cached_account) => cached_account.hash(),
        }
    }

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

#[derive(Default)]
pub struct StoreAccountsTiming {
    store_accounts_elapsed: u64,
    update_index_elapsed: u64,
    handle_reclaims_elapsed: u64,
}

#[derive(Debug)]
pub enum BankHashVerificationError {
    MismatchedAccountHash,
    MismatchedBankHash,
    MissingBankHash,
    MismatchedTotalLamports(u64, u64),
}

impl<'a> ZeroLamport for StoredAccountMeta<'a> {
    fn is_zero_lamport(&self) -> bool {
        self.wens() == 0
    }
}

impl<'a> ReadableAccount for StoredAccountMeta<'a> {
    fn wens(&self) -> u64 {
        self.account_meta.lamports
    }
    fn data(&self) -> &[u8] {
        self.data
    }
    fn owner(&self) -> &Pubkey {
        &self.account_meta.owner
    }
    fn executable(&self) -> bool {
        self.account_meta.executable
    }
    fn rent_epoch(&self) -> Epoch {
        self.account_meta.rent_epoch
    }
}

#[derive(Default)]
struct CleanKeyTimings {
    collect_delta_keys_us: u64,
    delta_insert_us: u64,
    hashset_to_vec_us: u64,
    dirty_store_processing_us: u64,
    delta_key_count: u64,
    dirty_pubkeys_count: u64,
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

    #[cfg(test)]
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

fn quarter_thread_count() -> usize {
    std::cmp::max(2, num_cpus::get() / 4)
}

pub fn make_min_priority_thread_pool() -> ThreadPool {
    // Use lower thread count to reduce priority.
    let num_threads = quarter_thread_count();
    rayon::ThreadPoolBuilder::new()
        .thread_name(|i| format!("solana-cleanup-accounts-{}", i))
        .num_threads(num_threads)
        .build()
        .unwrap()
}

pub const DEFAULT_ACCOUNTS_SHRINK_OPTIMIZE_TOTAL_SPACE: bool = true;
pub const DEFAULT_ACCOUNTS_SHRINK_RATIO: f64 = 0.80;
// The default extra account space in percentage from the ideal target
const DEFAULT_ACCOUNTS_SHRINK_THRESHOLD_OPTION: AccountShrinkThreshold =
    AccountShrinkThreshold::TotalSpace {
        shrink_ratio: DEFAULT_ACCOUNTS_SHRINK_RATIO,
    };

impl Default for AccountShrinkThreshold {
    fn default() -> AccountShrinkThreshold {
        DEFAULT_ACCOUNTS_SHRINK_THRESHOLD_OPTION
    }
}

trait Versioned {
    fn version(&self) -> u64;
}

impl Versioned for (u64, Hash) {
    fn version(&self) -> u64 {
        self.0
    }
}

impl Versioned for (u64, AccountInfo) {
    fn version(&self) -> u64 {
        self.0
    }
}

pub enum ScanStorageResult<R, B> {
    Cached(Vec<R>),
    Stored(B),
}

struct IndexAccountMapEntry<'a> {
    pub write_version: StoredMetaWriteVersion,
    pub store_id: AppendVecId,
    pub stored_account: StoredAccountMeta<'a>,
}

type GenerateIndexAccountsMap<'a> = HashMap<Pubkey, IndexAccountMapEntry<'a>>;
type DashMapVersionHash = DashMap<Pubkey, (u64, Hash)>;

#[derive(Debug, Default)]
struct FlushStats {
    #[allow(dead_code)]
    slot: Slot,
    #[allow(dead_code)]
    num_flushed: usize,
    #[allow(dead_code)]
    num_purged: usize,
    #[allow(dead_code)]
    total_size: u64,
}

impl AccountsDb {
    /// true if write cache is too big
    fn should_aggressively_flush_cache(&self) -> bool {
        self.write_cache_limit_bytes
            .unwrap_or(WRITE_CACHE_LIMIT_BYTES_DEFAULT)
            < self.accounts_cache.size()
    }

    fn purge_slot_cache_pubkeys(
        &self,
        purged_slot: Slot,
        purged_slot_pubkeys: HashSet<(Slot, Pubkey)>,
        pubkey_to_slot_set: Vec<(Pubkey, Slot)>,
        is_dead: bool,
    ) {
        // Slot purged from cache should not exist in the backing store
        assert!(self.storage.get_slot_stores(purged_slot).is_none());
        let num_purged_keys = pubkey_to_slot_set.len();
        let reclaims = self.purge_keys_exact(pubkey_to_slot_set.iter());
        assert_eq!(reclaims.len(), num_purged_keys);
        if is_dead {
            self.remove_dead_slots_metadata(
                std::iter::once(&purged_slot),
                purged_slot_pubkeys,
                None,
            );
        }
    }

    fn do_flush_slot_cache(
        &self,
        slot: Slot,
        slot_cache: &SlotCache,
        mut should_flush_f: Option<&mut impl FnMut(&Pubkey, &AccountSharedData) -> bool>,
    ) -> FlushStats {
        let mut num_purged = 0;
        let mut total_size = 0;
        let mut num_flushed = 0;
        let iter_items: Vec<_> = slot_cache.iter().collect();
        let mut purged_slot_pubkeys: HashSet<(Slot, Pubkey)> = HashSet::new();
        let mut pubkey_to_slot_set: Vec<(Pubkey, Slot)> = vec![];
        let (accounts, hashes): (Vec<(&Pubkey, &AccountSharedData)>, Vec<Hash>) = iter_items
            .iter()
            .filter_map(|iter_item| {
                let key = iter_item.key();
                let account = &iter_item.value().account;
                let should_flush = should_flush_f
                    .as_mut()
                    .map(|should_flush_f| should_flush_f(key, account))
                    .unwrap_or(true);
                if should_flush {
                    let hash = iter_item.value().hash();
                    total_size += (account.data().len() + STORE_META_OVERHEAD) as u64;
                    num_flushed += 1;
                    Some(((key, account), hash))
                } else {
                    // If we don't flush, we have to remove the entry from the
                    // index, since it's equivalent to purging
                    purged_slot_pubkeys.insert((slot, *key));
                    pubkey_to_slot_set.push((*key, slot));
                    num_purged += 1;
                    None
                }
            })
            .unzip();

        let is_dead_slot = accounts.is_empty();
        // Remove the account index entries from earlier roots that are outdated by later roots.
        // Safe because queries to the index will be reading updates from later roots.
        self.purge_slot_cache_pubkeys(slot, purged_slot_pubkeys, pubkey_to_slot_set, is_dead_slot);

        if !is_dead_slot {
            let aligned_total_size = Self::page_align(total_size);
            // This ensures that all updates are written to an AppendVec, before any
            // updates to the index happen, so anybody that sees a real entry in the index,
            // will be able to find the account in storage
            let flushed_store =
                self.create_and_insert_store(slot, aligned_total_size, "flush_slot_cache");
            self.store_accounts_frozen(
                slot,
                &accounts,
                Some(&hashes),
                Some(Box::new(move |_, _| flushed_store.clone())),
                None,
            );
            // If the above sizing function is correct, just one AppendVec is enough to hold
            // all the data for the slot
            assert_eq!(
                self.storage
                    .get_slot_stores(slot)
                    .unwrap()
                    .read()
                    .unwrap()
                    .len(),
                1
            );
        }

        // Remove this slot from the cache, which will to AccountsDb's new readers should look like an
        // atomic switch from the cache to storage.
        // There is some racy condition for existing readers who just has read exactly while
        // flushing. That case is handled by retry_to_get_account_accessor()
        assert!(self.accounts_cache.remove_slot(slot).is_some());
        FlushStats {
            slot,
            num_flushed,
            num_purged,
            total_size,
        }
    }

    /// `should_flush_f` is an optional closure that determines whether a given
    /// account should be flushed. Passing `None` will by default flush all
    /// accounts
    fn flush_slot_cache(
        &self,
        slot: Slot,
        should_flush_f: Option<&mut impl FnMut(&Pubkey, &AccountSharedData) -> bool>,
    ) -> Option<FlushStats> {
        let is_being_purged = {
            let mut slots_under_contention = self
                .remove_unrooted_slots_synchronization
                .slots_under_contention
                .lock()
                .unwrap();
            // If we're purging this slot, don't flush it here
            if slots_under_contention.contains(&slot) {
                true
            } else {
                slots_under_contention.insert(slot);
                false
            }
        };

        if !is_being_purged {
            let flush_stats = self.accounts_cache.slot_cache(slot).map(|slot_cache| {
                #[cfg(test)]
                {
                    // Give some time for cache flushing to occur here for unit tests
                    sleep(Duration::from_millis(self.load_delay));
                }
                // Since we added the slot to `slots_under_contention` AND this slot
                // still exists in the cache, we know the slot cannot be removed
                // by any other threads past this point. We are now responsible for
                // flushing this slot.
                self.do_flush_slot_cache(slot, &slot_cache, should_flush_f)
            });

            // Nobody else should have been purging this slot, so should not have been removed
            // from `self.remove_unrooted_slots_synchronization`.
            assert!(self
                .remove_unrooted_slots_synchronization
                .slots_under_contention
                .lock()
                .unwrap()
                .remove(&slot));

            // Signal to any threads blocked on `remove_unrooted_slots(slot)` that we have finished
            // flushing
            self.remove_unrooted_slots_synchronization
                .signal
                .notify_all();
            flush_stats
        } else {
            None
        }
    }

    fn flush_rooted_accounts_cache(
        &self,
        requested_flush_root: Option<Slot>,
        should_clean: Option<(&mut usize, &mut usize)>,
    ) -> (usize, usize) {
        let max_clean_root = should_clean.as_ref().and_then(|_| {
            // If there is a long running scan going on, this could prevent any cleaning
            // based on updates from slots > `max_clean_root`.
            self.max_clean_root(requested_flush_root)
        });

        // Use HashMap because HashSet doesn't provide Entry api
        let mut written_accounts = HashMap::new();

        // If `should_clean` is None, then`should_flush_f` is also None, which will cause
        // `flush_slot_cache` to flush all accounts to storage without cleaning any accounts.
        let mut should_flush_f = should_clean.map(|(account_bytes_saved, num_accounts_saved)| {
            move |&pubkey: &Pubkey, account: &AccountSharedData| {
                use std::collections::hash_map::Entry::{Occupied, Vacant};
                let should_flush = match written_accounts.entry(pubkey) {
                    Vacant(vacant_entry) => {
                        vacant_entry.insert(());
                        true
                    }
                    Occupied(_occupied_entry) => {
                        *account_bytes_saved += account.data().len();
                        *num_accounts_saved += 1;
                        // If a later root already wrote this account, no point
                        // in flushing it
                        false
                    }
                };
                should_flush
            }
        });

        // Always flush up to `requested_flush_root`, which is necessary for things like snapshotting.
        let cached_roots: BTreeSet<Slot> = self.accounts_cache.clear_roots(requested_flush_root);

        // Iterate from highest to lowest so that we don't need to flush earlier
        // outdated updates in earlier roots
        let mut num_roots_flushed = 0;
        for &root in cached_roots.iter().rev() {
            let should_flush_f = if let Some(max_clean_root) = max_clean_root {
                if root > max_clean_root {
                    // Only if the root is greater than the `max_clean_root` do we
                    // have to prevent cleaning, otherwise, just default to `should_flush_f`
                    // for any slots <= `max_clean_root`
                    None
                } else {
                    should_flush_f.as_mut()
                }
            } else {
                should_flush_f.as_mut()
            };

            if self.flush_slot_cache(root, should_flush_f).is_some() {
                num_roots_flushed += 1;
            }

            // Regardless of whether this slot was *just* flushed from the cache by the above
            // `flush_slot_cache()`, we should update the `max_flush_root`.
            // This is because some rooted slots may be flushed to storage *before* they are marked as root.
            // This can occur for instance when:
            // 1) The cache is overwhelmed, we we flushed some yet to be rooted frozen slots
            // 2) Random evictions
            // These slots may then *later* be marked as root, so we still need to handle updating the
            // `max_flush_root` in the accounts cache.
            self.accounts_cache.set_max_flush_root(root);
        }

        // Only add to the uncleaned roots set *after* we've flushed the previous roots,
        // so that clean will actually be able to clean the slots.
        let num_new_roots = cached_roots.len();
        self.accounts_index.add_uncleaned_roots(cached_roots);
        (num_new_roots, num_roots_flushed)
    }

    // `force_flush` flushes all the cached roots `<= requested_flush_root`. It also then
    // flushes:
    // 1) excess remaining roots or unrooted slots while 'should_aggressively_flush_cache' is true
    pub fn flush_accounts_cache(&self, force_flush: bool, requested_flush_root: Option<Slot>) {
        #[cfg(not(test))]
        assert!(requested_flush_root.is_some());

        if !force_flush && !self.should_aggressively_flush_cache() {
            return;
        }

        // Flush only the roots <= requested_flush_root, so that snapshotting has all
        // the relevant roots in storage.
        let mut flush_roots_elapsed = Measure::start("flush_roots_elapsed");
        let mut account_bytes_saved = 0;
        let mut num_accounts_saved = 0;

        // Note even if force_flush is false, we will still flush all roots <= the
        // given `requested_flush_root`, even if some of the later roots cannot be used for
        // cleaning due to an ongoing scan
        let (total_new_cleaned_roots, num_cleaned_roots_flushed) = self
            .flush_rooted_accounts_cache(
                requested_flush_root,
                Some((&mut account_bytes_saved, &mut num_accounts_saved)),
            );
        flush_roots_elapsed.stop();

        // Note we don't purge unrooted slots here because there may be ongoing scans/references
        // for those slot, let the Bank::drop() implementation do cleanup instead on dead
        // banks

        // If 'should_aggressively_flush_cache', then flush the excess ones to storage
        let (total_new_excess_roots, num_excess_roots_flushed) =
            if self.should_aggressively_flush_cache() {
                // Start by flushing the roots
                //
                // Cannot do any cleaning on roots past `requested_flush_root` because future
                // snapshots may need updates from those later slots, hence we pass `None`
                // for `should_clean`.
                self.flush_rooted_accounts_cache(None, None)
            } else {
                (0, 0)
            };

        let mut excess_slot_count = 0;
        let mut unflushable_unrooted_slot_count = 0;
        let max_flushed_root = self.accounts_cache.fetch_max_flush_root();
        if self.should_aggressively_flush_cache() {
            let old_slots = self.accounts_cache.cached_frozen_slots();
            excess_slot_count = old_slots.len();
            let mut flush_stats = FlushStats::default();
            old_slots.into_iter().for_each(|old_slot| {
                // Don't flush slots that are known to be unrooted
                if old_slot > max_flushed_root {
                    if self.should_aggressively_flush_cache() {
                        if let Some(stats) =
                            self.flush_slot_cache(old_slot, None::<&mut fn(&_, &_) -> bool>)
                        {
                            flush_stats.num_flushed += stats.num_flushed;
                            flush_stats.num_purged += stats.num_purged;
                            flush_stats.total_size += stats.total_size;
                        }
                    }
                } else {
                    unflushable_unrooted_slot_count += 1;
                }
            });
            datapoint_info!(
                "accounts_db-flush_accounts_cache_aggressively",
                ("num_flushed", flush_stats.num_flushed, i64),
                ("num_purged", flush_stats.num_purged, i64),
                ("total_flush_size", flush_stats.total_size, i64),
                ("total_cache_size", self.accounts_cache.size(), i64),
                ("total_frozen_slots", excess_slot_count, i64),
                ("total_slots", self.accounts_cache.num_slots(), i64),
            );
        }

        datapoint_info!(
            "accounts_db-flush_accounts_cache",
            ("total_new_cleaned_roots", total_new_cleaned_roots, i64),
            ("num_cleaned_roots_flushed", num_cleaned_roots_flushed, i64),
            ("total_new_excess_roots", total_new_excess_roots, i64),
            ("num_excess_roots_flushed", num_excess_roots_flushed, i64),
            ("excess_slot_count", excess_slot_count, i64),
            (
                "unflushable_unrooted_slot_count",
                unflushable_unrooted_slot_count,
                i64
            ),
            (
                "flush_roots_elapsed",
                flush_roots_elapsed.as_us() as i64,
                i64
            ),
            ("account_bytes_saved", account_bytes_saved, i64),
            ("num_accounts_saved", num_accounts_saved, i64),
        );

        // Flush a random slot out after every force flush to catch any inconsistencies
        // between cache and written state (i.e. should cause a hash mismatch between validators
        // that flush and don't flush if such a bug exists).
        let num_slots_remaining = self.accounts_cache.num_slots();
        if force_flush && num_slots_remaining >= FLUSH_CACHE_RANDOM_THRESHOLD {
            // Don't flush slots that are known to be unrooted
            let mut frozen_slots = self.accounts_cache.cached_frozen_slots();
            frozen_slots.retain(|s| *s > max_flushed_root);
            // Remove a random index 0 <= i < `frozen_slots.len()`
            let rand_slot = frozen_slots.choose(&mut thread_rng());
            if let Some(rand_slot) = rand_slot {
                let random_flush_stats =
                    self.flush_slot_cache(*rand_slot, None::<&mut fn(&_, &_) -> bool>);
                info!(
                    "Flushed random slot: num_remaining: {} {:?}",
                    num_slots_remaining, random_flush_stats,
                );
            }
        }
    }

    /// Scan a specific slot through all the account storage in parallel
    pub fn scan_account_storage<R, B>(
        &self,
        slot: Slot,
        cache_map_func: impl Fn(LoadedAccount) -> Option<R> + Sync,
        storage_scan_func: impl Fn(&B, LoadedAccount) + Sync,
    ) -> ScanStorageResult<R, B>
    where
        R: Send,
        B: Send + Default + Sync,
    {
        if let Some(slot_cache) = self.accounts_cache.slot_cache(slot) {
            // If we see the slot in the cache, then all the account information
            // is in this cached slot
            if slot_cache.len() > SCAN_SLOT_PAR_ITER_THRESHOLD {
                ScanStorageResult::Cached(self.thread_pool.install(|| {
                    slot_cache
                        .par_iter()
                        .filter_map(|cached_account| {
                            cache_map_func(LoadedAccount::Cached(Cow::Borrowed(
                                cached_account.value(),
                            )))
                        })
                        .collect()
                }))
            } else {
                ScanStorageResult::Cached(
                    slot_cache
                        .iter()
                        .filter_map(|cached_account| {
                            cache_map_func(LoadedAccount::Cached(Cow::Borrowed(
                                cached_account.value(),
                            )))
                        })
                        .collect(),
                )
            }
        } else {
            let retval = B::default();
            // If the slot is not in the cache, then all the account information must have
            // been flushed. This is guaranteed because we only remove the rooted slot from
            // the cache *after* we've finished flushing in `flush_slot_cache`.
            let storage_maps: Vec<Arc<AccountStorageEntry>> = self
                .storage
                .get_slot_storage_entries(slot)
                .unwrap_or_default();
            self.thread_pool.install(|| {
                storage_maps
                    .par_iter()
                    .flat_map(|storage| storage.all_accounts())
                    .for_each(|account| storage_scan_func(&retval, LoadedAccount::Stored(account)));
            });

            ScanStorageResult::Stored(retval)
        }
    }

    /// helper to return
    /// 1. pubkey, hash pairs for the slot
    /// 2. us spent scanning
    /// 3. Measure started when we began accumulating
    fn get_pubkey_hash_for_slot(&self, slot: Slot) -> (Vec<(Pubkey, Hash)>, u64, Measure) {
        let mut scan = Measure::start("scan");

        let scan_result: ScanStorageResult<(Pubkey, Hash), DashMapVersionHash> = self
            .scan_account_storage(
                slot,
                |loaded_account: LoadedAccount| {
                    // Cache only has one version per key, don't need to worry about versioning
                    Some((*loaded_account.pubkey(), loaded_account.loaded_hash()))
                },
                |accum: &DashMap<Pubkey, (u64, Hash)>, loaded_account: LoadedAccount| {
                    let loaded_write_version = loaded_account.write_version();
                    let loaded_hash = loaded_account.loaded_hash();
                    // keep the latest write version for each pubkey
                    match accum.entry(*loaded_account.pubkey()) {
                        Occupied(mut occupied_entry) => {
                            if loaded_write_version > occupied_entry.get().version() {
                                occupied_entry.insert((loaded_write_version, loaded_hash));
                            }
                        }

                        Vacant(vacant_entry) => {
                            vacant_entry.insert((loaded_write_version, loaded_hash));
                        }
                    }
                },
            );
        scan.stop();

        let accumulate = Measure::start("accumulate");
        let hashes: Vec<_> = match scan_result {
            ScanStorageResult::Cached(cached_result) => cached_result,
            ScanStorageResult::Stored(stored_result) => stored_result
                .into_iter()
                .map(|(pubkey, (_latest_write_version, hash))| (pubkey, hash))
                .collect(),
        };
        (hashes, scan.as_us(), accumulate)
    }

    /// true if it is possible that there are filler accounts present
    pub fn filler_accounts_enabled(&self) -> bool {
        self.filler_account_suffix.is_some()
    }

    pub fn get_accounts_delta_hash(&self, slot: Slot) -> Hash {
        let (mut hashes, scan_us, mut accumulate) = self.get_pubkey_hash_for_slot(slot);
        let dirty_keys = hashes.iter().map(|(pubkey, _hash)| *pubkey).collect();

        if self.filler_accounts_enabled() {
            // filler accounts must be added to 'dirty_keys' above but cannot be used to calculate hash
            hashes.retain(|(pubkey, _hash)| !self.is_filler_account(pubkey));
        }

        let ret = AccountsHash::accumulate_account_hashes(hashes);
        accumulate.stop();
        let mut uncleaned_time = Measure::start("uncleaned_index");
        self.uncleaned_pubkeys.insert(slot, dirty_keys);
        uncleaned_time.stop();
        self.stats
            .store_uncleaned_update
            .fetch_add(uncleaned_time.as_us(), Ordering::Relaxed);

        self.stats
            .delta_hash_scan_time_total_us
            .fetch_add(scan_us, Ordering::Relaxed);
        self.stats
            .delta_hash_accumulate_time_total_us
            .fetch_add(accumulate.as_us(), Ordering::Relaxed);
        self.stats.delta_hash_num.fetch_add(1, Ordering::Relaxed);
        ret
    }

    /// Only called from startup or test code.
    pub fn verify_bank_hash_and_lamports(
        &self,
        slot: Slot,
        ancestors: &Ancestors,
        total_lamports: u64,
        test_hash_calculation: bool,
    ) -> Result<(), BankHashVerificationError> {
        use BankHashVerificationError::*;

        let use_index = false;
        let check_hash = false; // this will not be supported anymore
        let is_startup = true;
        let can_cached_slot_be_unflushed = false;
        let (calculated_hash, calculated_lamports) = self
            .calculate_accounts_hash_helper_with_verify(
                use_index,
                test_hash_calculation,
                slot,
                ancestors,
                None,
                can_cached_slot_be_unflushed,
                check_hash,
                None,
                is_startup,
            )?;

        if calculated_lamports != total_lamports {
            warn!(
                "Mismatched total lamports: {} calculated: {}",
                total_lamports, calculated_lamports
            );
            return Err(MismatchedTotalLamports(calculated_lamports, total_lamports));
        }

        let bank_hashes = self.bank_hashes.read().unwrap();
        if let Some(found_hash_info) = bank_hashes.get(&slot) {
            if calculated_hash == found_hash_info.snapshot_hash {
                Ok(())
            } else {
                warn!(
                    "mismatched bank hash for slot {}: {} (calculated) != {} (expected)",
                    slot, calculated_hash, found_hash_info.snapshot_hash
                );
                Err(MismatchedBankHash)
            }
        } else {
            Err(MissingBankHash)
        }
    }

    // Reads all accounts in given slot's AppendVecs and filter only to alive,
    // then create a minimum AppendVec filled with the alive.
    // v1 path shrinks all stores in the slot
    //
    // Requires all stores in the slot to be re-written otherwise the accounts_index
    // store ref count could become incorrect.
    fn do_shrink_slot_v1(&self, slot: Slot, forced: bool) -> usize {
        trace!("shrink_stale_slot: slot: {}", slot);

        if let Some(stores_lock) = self.storage.get_slot_stores(slot) {
            let stores: Vec<_> = stores_lock.read().unwrap().values().cloned().collect();
            let mut alive_count = 0;
            let mut stored_count = 0;
            let mut written_bytes = 0;
            let mut total_bytes = 0;
            for store in &stores {
                alive_count += store.count();
                stored_count += store.approx_stored_count();
                written_bytes += store.written_bytes();
                total_bytes += store.total_bytes();
            }
            if alive_count == stored_count && stores.len() == 1 {
                trace!(
                    "shrink_stale_slot ({}): not able to shrink at all: alive/stored: {} / {} {}",
                    slot,
                    alive_count,
                    stored_count,
                    if forced { " (forced)" } else { "" },
                );
                return 0;
            } else if !forced {
                let sparse_by_count = (alive_count as f32 / stored_count as f32) <= 0.8;
                let sparse_by_bytes = (written_bytes as f32 / total_bytes as f32) <= 0.8;
                let not_sparse = !sparse_by_count && !sparse_by_bytes;
                let too_small_to_shrink = total_bytes <= PAGE_SIZE;
                if not_sparse || too_small_to_shrink {
                    return 0;
                }
                info!(
                    "shrink_stale_slot ({}): not_sparse: {} count: {}/{} byte: {}/{}",
                    slot, not_sparse, alive_count, stored_count, written_bytes, total_bytes,
                );
            }

            self.do_shrink_slot_stores(slot, stores.iter())
        } else {
            0
        }
    }

    pub fn shrink_all_slots(&self, is_startup: bool, last_full_snapshot_slot: Option<Slot>) {
        const DIRTY_STORES_CLEANING_THRESHOLD: usize = 10_000;
        const OUTER_CHUNK_SIZE: usize = 2000;
        if is_startup && self.caching_enabled {
            let slots = self.all_slots_in_storage();
            let threads = num_cpus::get();
            let inner_chunk_size = std::cmp::max(OUTER_CHUNK_SIZE / threads, 1);
            slots.chunks(OUTER_CHUNK_SIZE).for_each(|chunk| {
                chunk.par_chunks(inner_chunk_size).for_each(|slots| {
                    for slot in slots {
                        self.shrink_slot_forced(*slot);
                    }
                });
                if self.dirty_stores.len() > DIRTY_STORES_CLEANING_THRESHOLD {
                    self.clean_accounts(None, is_startup, last_full_snapshot_slot);
                }
            });
        } else {
            for slot in self.all_slots_in_storage() {
                if self.caching_enabled {
                    self.shrink_slot_forced(slot);
                } else {
                    self.do_shrink_slot_forced_v1(slot);
                }
                if self.dirty_stores.len() > DIRTY_STORES_CLEANING_THRESHOLD {
                    self.clean_accounts(None, is_startup, last_full_snapshot_slot);
                }
            }
        }
    }

    fn do_shrink_slot_forced_v1(&self, slot: Slot) {
        self.do_shrink_slot_v1(slot, true);
    }

    fn do_reset_uncleaned_roots_v1(
        &self,
        candidates: &mut MutexGuard<Vec<Slot>>,
        max_clean_root: Option<Slot>,
    ) {
        let previous_roots = self.accounts_index.reset_uncleaned_roots(max_clean_root);
        candidates.extend(previous_roots);
    }

    fn do_reset_uncleaned_roots(&self, max_clean_root: Option<Slot>) {
        let mut measure = Measure::start("reset");
        self.accounts_index.reset_uncleaned_roots(max_clean_root);
        measure.stop();
        self.clean_accounts_stats
            .reset_uncleaned_roots_us
            .fetch_add(measure.as_us(), Ordering::Relaxed);
    }

    /// Reclaim older states of accounts older than max_clean_root for AccountsDb bloat mitigation
    fn clean_accounts_older_than_root(
        &self,
        purges: Vec<Pubkey>,
        max_clean_root: Option<Slot>,
    ) -> ReclaimResult {
        if purges.is_empty() {
            return ReclaimResult::default();
        }
        // This number isn't carefully chosen; just guessed randomly such that
        // the hot loop will be the order of ~Xms.
        const INDEX_CLEAN_BULK_COUNT: usize = 4096;

        let mut clean_rooted = Measure::start("clean_old_root-ms");
        let reclaim_vecs = purges
            .par_chunks(INDEX_CLEAN_BULK_COUNT)
            .map(|pubkeys: &[Pubkey]| {
                let mut reclaims = Vec::new();
                for pubkey in pubkeys {
                    self.accounts_index
                        .clean_rooted_entries(pubkey, &mut reclaims, max_clean_root);
                }
                reclaims
            });
        let reclaims: Vec<_> = reclaim_vecs.flatten().collect();
        clean_rooted.stop();
        inc_new_counter_info!("clean-old-root-par-clean-ms", clean_rooted.as_ms() as usize);
        self.clean_accounts_stats
            .clean_old_root_us
            .fetch_add(clean_rooted.as_us(), Ordering::Relaxed);

        let mut measure = Measure::start("clean_old_root_reclaims");

        // Don't reset from clean, since the pubkeys in those stores may need to be unref'ed
        // and those stores may be used for background hashing.
        let reset_accounts = false;

        let mut reclaim_result = ReclaimResult::default();
        self.handle_reclaims(
            &reclaims,
            None,
            Some(&self.clean_accounts_stats.purge_stats),
            Some(&mut reclaim_result),
            reset_accounts,
        );
        measure.stop();
        debug!("{} {}", clean_rooted, measure);
        inc_new_counter_info!("clean-old-root-reclaim-ms", measure.as_ms() as usize);
        self.clean_accounts_stats
            .clean_old_root_reclaim_us
            .fetch_add(measure.as_us(), Ordering::Relaxed);
        reclaim_result
    }

    /// Remove uncleaned slots, up to a maximum slot, and return the collected pubkeys
    ///
    fn remove_uncleaned_slots_and_collect_pubkeys_up_to_slot(
        &self,
        max_slot: Slot,
    ) -> Vec<Vec<Pubkey>> {
        let uncleaned_slots = self.collect_uncleaned_slots_up_to_slot(max_slot);
        self.remove_uncleaned_slots_and_collect_pubkeys(uncleaned_slots)
    }

    /// Remove `slots` from `uncleaned_pubkeys` and collect all pubkeys
    ///
    /// For each slot in the list of uncleaned slots, remove it from the `uncleaned_pubkeys` Map
    /// and collect all the pubkeys to return.
    fn remove_uncleaned_slots_and_collect_pubkeys(
        &self,
        uncleaned_slots: Vec<Slot>,
    ) -> Vec<Vec<Pubkey>> {
        uncleaned_slots
            .into_iter()
            .filter_map(|uncleaned_slot| {
                self.uncleaned_pubkeys
                    .remove(&uncleaned_slot)
                    .map(|(_removed_slot, removed_pubkeys)| removed_pubkeys)
            })
            .collect()
    }

    /// Collect all the uncleaned slots, up to a max slot
    ///
    /// Search through the uncleaned Pubkeys and return all the slots, up to a maximum slot.
    fn collect_uncleaned_slots_up_to_slot(&self, max_slot: Slot) -> Vec<Slot> {
        self.uncleaned_pubkeys
            .iter()
            .filter_map(|entry| {
                let slot = *entry.key();
                (slot <= max_slot).then_some(slot)
            })
            .collect()
    }

    // Construct a vec of pubkeys for cleaning from:
    //   uncleaned_pubkeys - the delta set of updated pubkeys in rooted slots from the last clean
    //   dirty_stores - set of stores which had accounts removed or recently rooted
    fn construct_candidate_clean_keys(
        &self,
        max_clean_root: Option<Slot>,
        last_full_snapshot_slot: Option<Slot>,
        timings: &mut CleanKeyTimings,
    ) -> Vec<Pubkey> {
        let mut dirty_store_processing_time = Measure::start("dirty_store_processing");
        let max_slot = max_clean_root.unwrap_or_else(|| self.accounts_index.max_root());
        let mut dirty_stores = Vec::with_capacity(self.dirty_stores.len());
        self.dirty_stores.retain(|(slot, _store_id), store| {
            if *slot > max_slot {
                true
            } else {
                dirty_stores.push((*slot, store.clone()));
                false
            }
        });
        let dirty_stores_len = dirty_stores.len();
        let pubkeys = DashSet::new();
        for (_slot, store) in dirty_stores {
            for account in store.accounts.accounts(0) {
                pubkeys.insert(account.meta.pubkey);
            }
        }
        trace!(
            "dirty_stores.len: {} pubkeys.len: {}",
            dirty_stores_len,
            pubkeys.len()
        );
        timings.dirty_pubkeys_count = pubkeys.len() as u64;
        dirty_store_processing_time.stop();
        timings.dirty_store_processing_us += dirty_store_processing_time.as_us();

        let mut collect_delta_keys = Measure::start("key_create");
        let delta_keys = self.remove_uncleaned_slots_and_collect_pubkeys_up_to_slot(max_slot);
        collect_delta_keys.stop();
        timings.collect_delta_keys_us += collect_delta_keys.as_us();

        let mut delta_insert = Measure::start("delta_insert");
        self.thread_pool_clean.install(|| {
            delta_keys.par_iter().for_each(|keys| {
                for key in keys {
                    pubkeys.insert(*key);
                }
            });
        });
        delta_insert.stop();
        timings.delta_insert_us += delta_insert.as_us();

        timings.delta_key_count = pubkeys.len() as u64;

        let mut hashset_to_vec = Measure::start("flat_map");
        let mut pubkeys: Vec<Pubkey> = pubkeys.into_iter().collect();
        hashset_to_vec.stop();
        timings.hashset_to_vec_us += hashset_to_vec.as_us();

        // Check if we should purge any of the zero_lamport_accounts_to_purge_later, based on the
        // last_full_snapshot_slot.
        assert!(
            last_full_snapshot_slot.is_some() || self.zero_lamport_accounts_to_purge_after_full_snapshot.is_empty(),
            "if snapshots are disabled, then zero_lamport_accounts_to_purge_later should always be empty"
        );
        if let Some(last_full_snapshot_slot) = last_full_snapshot_slot {
            self.zero_lamport_accounts_to_purge_after_full_snapshot
                .retain(|(slot, pubkey)| {
                    let is_candidate_for_clean =
                        max_slot >= *slot && last_full_snapshot_slot >= *slot;
                    if is_candidate_for_clean {
                        pubkeys.push(*pubkey);
                    }
                    !is_candidate_for_clean
                });
        }

        pubkeys
    }

    fn report_store_stats(&self) {
        let mut total_count = 0;
        let mut min = std::usize::MAX;
        let mut min_slot = 0;
        let mut max = 0;
        let mut max_slot = 0;
        let mut newest_slot = 0;
        let mut oldest_slot = std::u64::MAX;
        let mut total_bytes = 0;
        let mut total_alive_bytes = 0;
        for iter_item in self.storage.0.iter() {
            let slot = iter_item.key();
            let slot_stores = iter_item.value().read().unwrap();
            total_count += slot_stores.len();
            if slot_stores.len() < min {
                min = slot_stores.len();
                min_slot = *slot;
            }

            if slot_stores.len() > max {
                max = slot_stores.len();
                max_slot = *slot;
            }
            if *slot > newest_slot {
                newest_slot = *slot;
            }

            if *slot < oldest_slot {
                oldest_slot = *slot;
            }

            for store in slot_stores.values() {
                total_alive_bytes += Self::page_align(store.alive_bytes() as u64);
                total_bytes += store.total_bytes();
            }
        }
        info!("total_stores: {}, newest_slot: {}, oldest_slot: {}, max_slot: {} (num={}), min_slot: {} (num={})",
              total_count, newest_slot, oldest_slot, max_slot, max, min_slot, min);

        let total_alive_ratio = if total_bytes > 0 {
            total_alive_bytes as f64 / total_bytes as f64
        } else {
            0.
        };

        datapoint_info!(
            "accounts_db-stores",
            ("total_count", total_count, i64),
            (
                "recycle_count",
                self.recycle_stores.read().unwrap().entry_count() as u64,
                i64
            ),
            ("total_bytes", total_bytes, i64),
            ("total_alive_bytes", total_alive_bytes, i64),
            ("total_alive_ratio", total_alive_ratio, f64),
        );
        datapoint_info!(
            "accounts_db-perf-stats",
            (
                "delta_hash_num",
                self.stats.delta_hash_num.swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "delta_hash_scan_us",
                self.stats
                    .delta_hash_scan_time_total_us
                    .swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "delta_hash_accumulate_us",
                self.stats
                    .delta_hash_accumulate_time_total_us
                    .swap(0, Ordering::Relaxed),
                i64
            ),
        );
    }

    fn max_clean_root(&self, proposed_clean_root: Option<Slot>) -> Option<Slot> {
        match (
            self.accounts_index.min_ongoing_scan_root(),
            proposed_clean_root,
        ) {
            (None, None) => None,
            (Some(min_scan_root), None) => Some(min_scan_root),
            (None, Some(proposed_clean_root)) => Some(proposed_clean_root),
            (Some(min_scan_root), Some(proposed_clean_root)) => {
                Some(std::cmp::min(min_scan_root, proposed_clean_root))
            }
        }
    }

    // Purge zero lamport accounts and older rooted account states as garbage
    // collection
    // Only remove those accounts where the entire rooted history of the account
    // can be purged because there are no live append vecs in the ancestors
    pub fn clean_accounts(
        &self,
        max_clean_root: Option<Slot>,
        is_startup: bool,
        last_full_snapshot_slot: Option<Slot>,
    ) {
        let mut measure_all = Measure::start("clean_accounts");
        let max_clean_root = self.max_clean_root(max_clean_root);

        // hold a lock to prevent slot shrinking from running because it might modify some rooted
        // slot storages which can not happen as long as we're cleaning accounts because we're also
        // modifying the rooted slot storages!
        let mut candidates_v1 = self.shrink_candidate_slots_v1.lock().unwrap();
        self.report_store_stats();

        let mut key_timings = CleanKeyTimings::default();
        let mut pubkeys = self.construct_candidate_clean_keys(
            max_clean_root,
            last_full_snapshot_slot,
            &mut key_timings,
        );

        let mut sort = Measure::start("sort");
        if is_startup {
            pubkeys.par_sort_unstable();
        } else {
            self.thread_pool_clean
                .install(|| pubkeys.par_sort_unstable());
        }
        sort.stop();

        let total_keys_count = pubkeys.len();
        let mut accounts_scan = Measure::start("accounts_scan");
        let uncleaned_roots = self.accounts_index.clone_uncleaned_roots();
        let uncleaned_roots_len = self.accounts_index.uncleaned_roots_len();
        let found_not_zero_accum = AtomicU64::new(0);
        let not_found_on_fork_accum = AtomicU64::new(0);
        let missing_accum = AtomicU64::new(0);
        let useful_accum = AtomicU64::new(0);

        // parallel scan the index.
        let (mut purges_zero_lamports, purges_old_accounts) = {
            let do_clean_scan = || {
                pubkeys
                    .par_chunks(4096)
                    .map(|pubkeys: &[Pubkey]| {
                        let mut purges_zero_lamports = HashMap::new();
                        let mut purges_old_accounts = Vec::new();
                        let mut found_not_zero = 0;
                        let mut not_found_on_fork = 0;
                        let mut missing = 0;
                        let mut useful = 0;
                        self.accounts_index.scan(
                            pubkeys,
                            max_clean_root,
                            // return true if we want this item to remain in the cache
                            |exists, slot_list, index_in_slot_list, pubkey, ref_count| {
                                let mut useless = true;
                                if !exists {
                                    missing += 1;
                                } else {
                                    match index_in_slot_list {
                                        Some(index_in_slot_list) => {
                                            // found info relative to max_clean_root
                                            let (slot, account_info) =
                                                &slot_list[index_in_slot_list];
                                            if account_info.lamports == 0 {
                                                useless = false;
                                                purges_zero_lamports.insert(
                                                    *pubkey,
                                                    (
                                                        self.accounts_index.get_rooted_entries(
                                                            slot_list,
                                                            max_clean_root,
                                                        ),
                                                        ref_count,
                                                    ),
                                                );
                                            } else {
                                                found_not_zero += 1;
                                            }
                                            let slot = *slot;

                                            if uncleaned_roots.contains(&slot) {
                                                // Assertion enforced by `accounts_index.get()`, the latest slot
                                                // will not be greater than the given `max_clean_root`
                                                if let Some(max_clean_root) = max_clean_root {
                                                    assert!(slot <= max_clean_root);
                                                }
                                                purges_old_accounts.push(*pubkey);
                                                useless = false;
                                            }
                                        }
                                        None => {
                                            // This pubkey is in the index but not in a root slot, so clean
                                            // it up by adding it to the to-be-purged list.
                                            //
                                            // Also, this pubkey must have been touched by some slot since
                                            // it was in the dirty list, so we assume that the slot it was
                                            // touched in must be unrooted.
                                            not_found_on_fork += 1;
                                            useless = false;
                                            purges_old_accounts.push(*pubkey);
                                        }
                                    }
                                }
                                if !useless {
                                    useful += 1;
                                }
                                !useless
                            },
                        );
                        found_not_zero_accum.fetch_add(found_not_zero, Ordering::Relaxed);
                        not_found_on_fork_accum.fetch_add(not_found_on_fork, Ordering::Relaxed);
                        missing_accum.fetch_add(missing, Ordering::Relaxed);
                        useful_accum.fetch_add(useful, Ordering::Relaxed);
                        (purges_zero_lamports, purges_old_accounts)
                    })
                    .reduce(
                        || (HashMap::new(), Vec::new()),
                        |mut m1, m2| {
                            // Collapse down the hashmaps/vecs into one.
                            m1.0.extend(m2.0);
                            m1.1.extend(m2.1);
                            m1
                        },
                    )
            };
            if is_startup {
                do_clean_scan()
            } else {
                self.thread_pool_clean.install(do_clean_scan)
            }
        };
        accounts_scan.stop();

        let mut clean_old_rooted = Measure::start("clean_old_roots");
        let (purged_account_slots, removed_accounts) =
            self.clean_accounts_older_than_root(purges_old_accounts, max_clean_root);

        if self.caching_enabled {
            self.do_reset_uncleaned_roots(max_clean_root);
        } else {
            self.do_reset_uncleaned_roots_v1(&mut candidates_v1, max_clean_root);
        }
        clean_old_rooted.stop();

        let mut store_counts_time = Measure::start("store_counts");

        // Calculate store counts as if everything was purged
        // Then purge if we can
        let mut store_counts: HashMap<AppendVecId, (usize, HashSet<Pubkey>)> = HashMap::new();
        for (key, (account_infos, ref_count)) in purges_zero_lamports.iter_mut() {
            if purged_account_slots.contains_key(key) {
                *ref_count = self.accounts_index.ref_count_from_storage(key);
            }
            account_infos.retain(|(slot, account_info)| {
                let was_slot_purged = purged_account_slots
                    .get(key)
                    .map(|slots_removed| slots_removed.contains(slot))
                    .unwrap_or(false);
                if was_slot_purged {
                    // No need to look up the slot storage below if the entire
                    // slot was purged
                    return false;
                }
                // Check if this update in `slot` to the account with `key` was reclaimed earlier by
                // `clean_accounts_older_than_root()`
                let was_reclaimed = removed_accounts
                    .get(&account_info.store_id)
                    .map(|store_removed| store_removed.contains(&account_info.offset))
                    .unwrap_or(false);
                if was_reclaimed {
                    return false;
                }
                if let Some(store_count) = store_counts.get_mut(&account_info.store_id) {
                    store_count.0 -= 1;
                    store_count.1.insert(*key);
                } else {
                    let mut key_set = HashSet::new();
                    key_set.insert(*key);
                    assert!(
                        !account_info.is_cached(),
                        "The Accounts Cache must be flushed first for this account info. pubkey: {}, slot: {}",
                        *key,
                        *slot
                    );
                    let count = self
                        .storage
                        .slot_store_count(*slot, account_info.store_id)
                        .unwrap()
                        - 1;
                    debug!(
                        "store_counts, inserting slot: {}, store id: {}, count: {}",
                        slot, account_info.store_id, count
                    );
                    store_counts.insert(account_info.store_id, (count, key_set));
                }
                true
            });
        }
        store_counts_time.stop();

        let mut calc_deps_time = Measure::start("calc_deps");
        Self::calc_delete_dependencies(&purges_zero_lamports, &mut store_counts);
        calc_deps_time.stop();

        let mut purge_filter = Measure::start("purge_filter");
        self.filter_zero_lamport_clean_for_incremental_snapshots(
            max_clean_root,
            last_full_snapshot_slot,
            &store_counts,
            &mut purges_zero_lamports,
        );
        purge_filter.stop();

        let mut reclaims_time = Measure::start("reclaims");
        // Recalculate reclaims with new purge set
        let pubkey_to_slot_set: Vec<_> = purges_zero_lamports
            .into_iter()
            .map(|(key, (slots_list, _ref_count))| {
                (
                    key,
                    slots_list
                        .into_iter()
                        .map(|(slot, _)| slot)
                        .collect::<HashSet<Slot>>(),
                )
            })
            .collect();

        let reclaims = self.purge_keys_exact(pubkey_to_slot_set.iter());

        // Don't reset from clean, since the pubkeys in those stores may need to be unref'ed
        // and those stores may be used for background hashing.
        let reset_accounts = false;
        let mut reclaim_result = ReclaimResult::default();
        let reclaim_result = Some(&mut reclaim_result);
        self.handle_reclaims(
            &reclaims,
            None,
            Some(&self.clean_accounts_stats.purge_stats),
            reclaim_result,
            reset_accounts,
        );

        reclaims_time.stop();
        measure_all.stop();

        self.clean_accounts_stats.report();
        datapoint_info!(
            "clean_accounts",
            ("total_us", measure_all.as_us(), i64),
            (
                "collect_delta_keys_us",
                key_timings.collect_delta_keys_us,
                i64
            ),
            (
                "dirty_store_processing_us",
                key_timings.dirty_store_processing_us,
                i64
            ),
            ("accounts_scan", accounts_scan.as_us() as i64, i64),
            ("clean_old_rooted", clean_old_rooted.as_us() as i64, i64),
            ("store_counts", store_counts_time.as_us() as i64, i64),
            ("purge_filter", purge_filter.as_us() as i64, i64),
            ("calc_deps", calc_deps_time.as_us() as i64, i64),
            ("reclaims", reclaims_time.as_us() as i64, i64),
            ("delta_insert_us", key_timings.delta_insert_us, i64),
            ("delta_key_count", key_timings.delta_key_count, i64),
            ("dirty_pubkeys_count", key_timings.dirty_pubkeys_count, i64),
            ("sort_us", sort.as_us(), i64),
            ("useful_keys", useful_accum.load(Ordering::Relaxed), i64),
            ("total_keys_count", total_keys_count, i64),
            (
                "scan_found_not_zero",
                found_not_zero_accum.load(Ordering::Relaxed),
                i64
            ),
            (
                "scan_not_found_on_fork",
                not_found_on_fork_accum.load(Ordering::Relaxed),
                i64
            ),
            ("scan_missing", missing_accum.load(Ordering::Relaxed), i64),
            ("uncleaned_roots_len", uncleaned_roots_len, i64),
            (
                "clean_old_root_us",
                self.clean_accounts_stats
                    .clean_old_root_us
                    .swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "clean_old_root_reclaim_us",
                self.clean_accounts_stats
                    .clean_old_root_reclaim_us
                    .swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "reset_uncleaned_roots_us",
                self.clean_accounts_stats
                    .reset_uncleaned_roots_us
                    .swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "remove_dead_accounts_remove_us",
                self.clean_accounts_stats
                    .remove_dead_accounts_remove_us
                    .swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "remove_dead_accounts_shrink_us",
                self.clean_accounts_stats
                    .remove_dead_accounts_shrink_us
                    .swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "clean_stored_dead_slots_us",
                self.clean_accounts_stats
                    .clean_stored_dead_slots_us
                    .swap(0, Ordering::Relaxed),
                i64
            ),
        );
    }

    fn calc_delete_dependencies(
        purges: &HashMap<Pubkey, (SlotList<AccountInfo>, u64)>,
        store_counts: &mut HashMap<AppendVecId, (usize, HashSet<Pubkey>)>,
    ) {
        // Another pass to check if there are some filtered accounts which
        // do not match the criteria of deleting all appendvecs which contain them
        // then increment their storage count.
        let mut already_counted = HashSet::new();
        for (pubkey, (account_infos, ref_count_from_storage)) in purges.iter() {
            let no_delete = if account_infos.len() as u64 != *ref_count_from_storage {
                debug!(
                    "calc_delete_dependencies(),
                    pubkey: {},
                    account_infos: {:?},
                    account_infos_len: {},
                    ref_count_from_storage: {}",
                    pubkey,
                    account_infos,
                    account_infos.len(),
                    ref_count_from_storage,
                );
                true
            } else {
                let mut no_delete = false;
                for (_slot, account_info) in account_infos {
                    debug!(
                        "calc_delete_dependencies()
                        storage id: {},
                        count len: {}",
                        account_info.store_id,
                        store_counts.get(&account_info.store_id).unwrap().0,
                    );
                    if store_counts.get(&account_info.store_id).unwrap().0 != 0 {
                        no_delete = true;
                        break;
                    }
                }
                no_delete
            };
            if no_delete {
                let mut pending_store_ids: HashSet<usize> = HashSet::new();
                for (_bank_id, account_info) in account_infos {
                    if !already_counted.contains(&account_info.store_id) {
                        pending_store_ids.insert(account_info.store_id);
                    }
                }
                while !pending_store_ids.is_empty() {
                    let id = pending_store_ids.iter().next().cloned().unwrap();
                    pending_store_ids.remove(&id);
                    if already_counted.contains(&id) {
                        continue;
                    }
                    store_counts.get_mut(&id).unwrap().0 += 1;
                    already_counted.insert(id);

                    let affected_pubkeys = &store_counts.get(&id).unwrap().1;
                    for key in affected_pubkeys {
                        for (_slot, account_info) in &purges.get(key).unwrap().0 {
                            if !already_counted.contains(&account_info.store_id) {
                                pending_store_ids.insert(account_info.store_id);
                            }
                        }
                    }
                }
            }
        }
    }

    /// During clean, some zero-lamport accounts that are marked for purge should *not* actually
    /// get purged.  Filter out those accounts here.
    ///
    /// When using incremental snapshots, do not purge zero-lamport accounts if the slot is higher
    /// than the last full snapshot slot.  This is to protect against the following scenario:
    ///
    ///   ```text
    ///   A full snapshot is taken, and it contains an account with a non-zero balance.  Later,
    ///   that account's  goes to zero.  Evntually cleaning runs, and before, this account would be
    ///   cleaned up.  Finally, an incremental snapshot is taken.
    ///
    ///   Later, the incremental (and full) snapshot is used to rebuild the bank and accounts
    ///   database (e.x. if the node restarts).  The full snapshot _does_ contain the account (from
    ///   above) and its balance is non-zero, however, since the account was cleaned up in a later
    ///   slot, the incremental snapshot does not contain any info about this account, thus, the
    ///   accounts database will contain the old info from this account, which has its old non-zero
    ///   balance.  Very bad!
    ///   ```
    ///
    /// This filtering step can be skipped if there is no `last_full_snapshot_slot`, or if the
    /// `max_clean_root` is less-than-or-equal-to the `last_full_snapshot_slot`.
    fn filter_zero_lamport_clean_for_incremental_snapshots(
        &self,
        max_clean_root: Option<Slot>,
        last_full_snapshot_slot: Option<Slot>,
        store_counts: &HashMap<AppendVecId, (usize, HashSet<Pubkey>)>,
        purges_zero_lamports: &mut HashMap<Pubkey, (SlotList<AccountInfo>, RefCount)>,
    ) {
        let should_filter_for_incremental_snapshots =
            max_clean_root.unwrap_or(Slot::MAX) > last_full_snapshot_slot.unwrap_or(Slot::MAX);
        assert!(
            last_full_snapshot_slot.is_some() || !should_filter_for_incremental_snapshots,
            "if filtering for incremental snapshots, then snapshots should be enabled",
        );

        purges_zero_lamports.retain(|pubkey, (slot_account_infos, _ref_count)| {
            // Only keep purges_zero_lamports where the entire history of the account in the root set
            // can be purged. All AppendVecs for those updates are dead.
            for (_slot, account_info) in slot_account_infos.iter() {
                if store_counts.get(&account_info.store_id).unwrap().0 != 0 {
                    return false;
                }
            }

            // Exit early if not filtering more for incremental snapshots
            if !should_filter_for_incremental_snapshots {
                return true;
            }

            let slot_account_info_at_highest_slot = slot_account_infos
                .iter()
                .max_by_key(|(slot, _account_info)| slot);

            slot_account_info_at_highest_slot.map_or(true, |(slot, account_info)| {
                // Do *not* purge zero-lamport accounts if the slot is greater than the last full
                // snapshot slot.  Since we're `retain`ing the accounts-to-purge, I felt creating
                // the `cannot_purge` variable made this easier to understand.  Accounts that do
                // not get purged here are added to a list so they be considered for purging later
                // (i.e. after the next full snapshot).
                assert!(account_info.is_zero_lamport());
                let cannot_purge = *slot > last_full_snapshot_slot.unwrap();
                if cannot_purge {
                    self.zero_lamport_accounts_to_purge_after_full_snapshot
                        .insert((*slot, *pubkey));
                }
                !cannot_purge
            })
        });
    }

    fn purge_keys_exact<'a, C: 'a>(
        &'a self,
        pubkey_to_slot_set: impl Iterator<Item = &'a (Pubkey, C)>,
    ) -> Vec<(u64, AccountInfo)>
    where
        C: Contains<'a, Slot>,
    {
        let mut reclaims = Vec::new();
        let mut dead_keys = Vec::new();

        for (pubkey, slots_set) in pubkey_to_slot_set {
            let is_empty = self
                .accounts_index
                .purge_exact(pubkey, slots_set, &mut reclaims);
            if is_empty {
                dead_keys.push(pubkey);
            }
        }

        self.accounts_index
            .handle_dead_keys(&dead_keys, &self.account_indexes);
        reclaims
    }

    // Reads all accounts in given slot's AppendVecs and filter only to alive,
    // then create a minimum AppendVec filled with the alive.
    fn shrink_slot_forced(&self, slot: Slot) -> usize {
        debug!("shrink_slot_forced: slot: {}", slot);

        if let Some(stores_lock) = self.storage.get_slot_stores(slot) {
            let stores: Vec<Arc<AccountStorageEntry>> =
                stores_lock.read().unwrap().values().cloned().collect();
            if !Self::is_shrinking_productive(slot, &stores) {
                return 0;
            }
            self.do_shrink_slot_stores(slot, stores.iter())
        } else {
            0
        }
    }

    fn do_shrink_slot_stores<'a, I>(&'a self, slot: Slot, stores: I) -> usize
    where
        I: Iterator<Item = &'a Arc<AccountStorageEntry>>,
    {
        debug!("do_shrink_slot_stores: slot: {}", slot);
        let mut stored_accounts: HashMap<Pubkey, FoundStoredAccount> = HashMap::new();
        let mut original_bytes = 0;
        let mut num_stores = 0;
        for store in stores {
            let mut start = 0;
            original_bytes += store.total_bytes();
            let store_id = store.append_vec_id();
            while let Some((account, next)) = store.accounts.get_account(start) {
                let new_entry = FoundStoredAccount {
                    account,
                    store_id,
                    account_size: next - start,
                };
                match stored_accounts.entry(new_entry.account.meta.pubkey) {
                    Entry::Occupied(mut occupied_entry) => {
                        if new_entry.account.meta.write_version
                            > occupied_entry.get().account.meta.write_version
                        {
                            occupied_entry.insert(new_entry);
                        }
                    }
                    Entry::Vacant(vacant_entry) => {
                        vacant_entry.insert(new_entry);
                    }
                }
                start = next;
            }
            num_stores += 1;
        }

        // sort by pubkey to keep account index lookups close
        let mut stored_accounts = stored_accounts.into_iter().collect::<Vec<_>>();
        stored_accounts.sort_unstable_by(|a, b| a.0.cmp(&b.0));

        let mut index_read_elapsed = Measure::start("index_read_elapsed");
        let alive_total_collect = AtomicUsize::new(0);

        let len = stored_accounts.len();
        let alive_accounts_collect = Mutex::new(Vec::with_capacity(len));
        let unrefed_pubkeys_collect = Mutex::new(Vec::with_capacity(len));
        self.shrink_stats
            .accounts_loaded
            .fetch_add(len as u64, Ordering::Relaxed);

        self.thread_pool.install(|| {
            let chunk_size = 50; // # accounts/thread
            let chunks = len / chunk_size + 1;
            (0..chunks).into_par_iter().for_each(|chunk| {
                let skip = chunk * chunk_size;

                let mut alive_accounts = Vec::with_capacity(chunk_size);
                let mut unrefed_pubkeys = Vec::with_capacity(chunk_size);
                let alive_total = self.load_accounts_index_for_shrink(
                    stored_accounts.iter().skip(skip).take(chunk_size),
                    &mut alive_accounts,
                    &mut unrefed_pubkeys,
                );

                // collect
                alive_accounts_collect
                    .lock()
                    .unwrap()
                    .append(&mut alive_accounts);
                unrefed_pubkeys_collect
                    .lock()
                    .unwrap()
                    .append(&mut unrefed_pubkeys);
                alive_total_collect.fetch_add(alive_total, Ordering::Relaxed);
            });
        });

        let alive_accounts = alive_accounts_collect.into_inner().unwrap();
        let unrefed_pubkeys = unrefed_pubkeys_collect.into_inner().unwrap();
        let alive_total = alive_total_collect.load(Ordering::Relaxed);

        index_read_elapsed.stop();
        let aligned_total: u64 = Self::page_align(alive_total as u64);

        // This shouldn't happen if alive_bytes/approx_stored_count are accurate
        if Self::should_not_shrink(aligned_total, original_bytes, num_stores) {
            self.shrink_stats
                .skipped_shrink
                .fetch_add(1, Ordering::Relaxed);
            for pubkey in unrefed_pubkeys {
                if let Some(locked_entry) = self.accounts_index.get_account_read_entry(pubkey) {
                    locked_entry.addref();
                }
            }
            return 0;
        }

        let total_starting_accounts = stored_accounts.len();
        let total_accounts_after_shrink = alive_accounts.len();
        debug!(
            "shrinking: slot: {}, accounts: ({} => {}) bytes: ({} ; aligned to: {}) original: {}",
            slot,
            total_starting_accounts,
            total_accounts_after_shrink,
            alive_total,
            aligned_total,
            original_bytes,
        );

        let mut rewrite_elapsed = Measure::start("rewrite_elapsed");
        let mut dead_storages = vec![];
        let mut find_alive_elapsed = 0;
        let mut create_and_insert_store_elapsed = 0;
        let mut write_storage_elapsed = 0;
        let mut store_accounts_timing = StoreAccountsTiming::default();
        if aligned_total > 0 {
            let mut start = Measure::start("find_alive_elapsed");
            let mut accounts = Vec::with_capacity(alive_accounts.len());
            let mut hashes = Vec::with_capacity(alive_accounts.len());
            let mut write_versions = Vec::with_capacity(alive_accounts.len());

            for (pubkey, alive_account) in alive_accounts {
                accounts.push((pubkey, &alive_account.account));
                hashes.push(alive_account.account.hash);
                write_versions.push(alive_account.account.meta.write_version);
            }
            start.stop();
            find_alive_elapsed = start.as_us();

            let mut start = Measure::start("create_and_insert_store_elapsed");
            let shrunken_store = if let Some(new_store) =
                self.try_recycle_and_insert_store(slot, aligned_total, aligned_total + 1024)
            {
                new_store
            } else {
                let maybe_shrink_paths = self.shrink_paths.read().unwrap();
                if let Some(ref shrink_paths) = *maybe_shrink_paths {
                    self.create_and_insert_store_with_paths(
                        slot,
                        aligned_total,
                        "shrink-w-path",
                        shrink_paths,
                    )
                } else {
                    self.create_and_insert_store(slot, aligned_total, "shrink")
                }
            };
            start.stop();
            create_and_insert_store_elapsed = start.as_us();

            // here, we're writing back alive_accounts. That should be an atomic operation
            // without use of rather wide locks in this whole function, because we're
            // mutating rooted slots; There should be no writers to them.
            store_accounts_timing = self.store_accounts_frozen(
                slot,
                &accounts,
                Some(&hashes),
                Some(Box::new(move |_, _| shrunken_store.clone())),
                Some(Box::new(write_versions.into_iter())),
            );

            // `store_accounts_frozen()` above may have purged accounts from some
            // other storage entries (the ones that were just overwritten by this
            // new storage entry). This means some of those stores might have caused
            // this slot to be read to `self.shrink_candidate_slots`, so delete
            // those here
            self.shrink_candidate_slots.lock().unwrap().remove(&slot);

            // Purge old, overwritten storage entries
            let mut start = Measure::start("write_storage_elapsed");
            if let Some(slot_stores) = self.storage.get_slot_stores(slot) {
                slot_stores.write().unwrap().retain(|_key, store| {
                    if store.count() == 0 {
                        self.dirty_stores
                            .insert((slot, store.append_vec_id()), store.clone());
                        dead_storages.push(store.clone());
                        false
                    } else {
                        true
                    }
                });
            }
            start.stop();
            write_storage_elapsed = start.as_us();
        }
        rewrite_elapsed.stop();

        let mut recycle_stores_write_elapsed = Measure::start("recycle_stores_write_time");
        let mut recycle_stores = self.recycle_stores.write().unwrap();
        recycle_stores_write_elapsed.stop();

        let mut drop_storage_entries_elapsed = Measure::start("drop_storage_entries_elapsed");
        if recycle_stores.entry_count() < MAX_RECYCLE_STORES {
            recycle_stores.add_entries(dead_storages);
            drop(recycle_stores);
        } else {
            self.stats
                .dropped_stores
                .fetch_add(dead_storages.len() as u64, Ordering::Relaxed);
            drop(recycle_stores);
            drop(dead_storages);
        }
        drop_storage_entries_elapsed.stop();

        self.shrink_stats
            .num_slots_shrunk
            .fetch_add(1, Ordering::Relaxed);
        self.shrink_stats
            .index_read_elapsed
            .fetch_add(index_read_elapsed.as_us(), Ordering::Relaxed);
        self.shrink_stats
            .find_alive_elapsed
            .fetch_add(find_alive_elapsed, Ordering::Relaxed);
        self.shrink_stats
            .create_and_insert_store_elapsed
            .fetch_add(create_and_insert_store_elapsed, Ordering::Relaxed);
        self.shrink_stats.store_accounts_elapsed.fetch_add(
            store_accounts_timing.store_accounts_elapsed,
            Ordering::Relaxed,
        );
        self.shrink_stats.update_index_elapsed.fetch_add(
            store_accounts_timing.update_index_elapsed,
            Ordering::Relaxed,
        );
        self.shrink_stats.handle_reclaims_elapsed.fetch_add(
            store_accounts_timing.handle_reclaims_elapsed,
            Ordering::Relaxed,
        );
        self.shrink_stats
            .write_storage_elapsed
            .fetch_add(write_storage_elapsed, Ordering::Relaxed);
        self.shrink_stats
            .rewrite_elapsed
            .fetch_add(rewrite_elapsed.as_us(), Ordering::Relaxed);
        self.shrink_stats
            .drop_storage_entries_elapsed
            .fetch_add(drop_storage_entries_elapsed.as_us(), Ordering::Relaxed);
        self.shrink_stats
            .recycle_stores_write_elapsed
            .fetch_add(recycle_stores_write_elapsed.as_us(), Ordering::Relaxed);
        self.shrink_stats.accounts_removed.fetch_add(
            total_starting_accounts - total_accounts_after_shrink,
            Ordering::Relaxed,
        );
        self.shrink_stats.bytes_removed.fetch_add(
            original_bytes.saturating_sub(aligned_total),
            Ordering::Relaxed,
        );
        self.shrink_stats
            .bytes_written
            .fetch_add(aligned_total, Ordering::Relaxed);

        self.shrink_stats.report();

        total_accounts_after_shrink
    }

    fn load_accounts_index_for_shrink<'a, I>(
        &'a self,
        iter: I,
        alive_accounts: &mut Vec<(&'a Pubkey, &'a FoundStoredAccount<'a>)>,
        unrefed_pubkeys: &mut Vec<&'a Pubkey>,
    ) -> usize
    where
        I: Iterator<Item = &'a (Pubkey, FoundStoredAccount<'a>)>,
    {
        let mut alive_total = 0;

        let mut alive = 0;
        let mut dead = 0;
        iter.for_each(|(pubkey, stored_account)| {
            let lookup = self.accounts_index.get_account_read_entry(pubkey);
            if let Some(locked_entry) = lookup {
                let is_alive = locked_entry.slot_list().iter().any(|(_slot, i)| {
                    i.store_id == stored_account.store_id
                        && i.offset == stored_account.account.offset
                });
                if !is_alive {
                    // This pubkey was found in the storage, but no longer exists in the index.
                    // It would have had a ref to the storage from the initial store, but it will
                    // not exist in the re-written slot. Unref it to keep the index consistent with
                    // rewriting the storage entries.
                    unrefed_pubkeys.push(pubkey);
                    locked_entry.unref();
                    dead += 1;
                } else {
                    alive_accounts.push((pubkey, stored_account));
                    alive_total += stored_account.account_size;
                    alive += 1;
                }
            }
        });
        self.shrink_stats
            .alive_accounts
            .fetch_add(alive, Ordering::Relaxed);
        self.shrink_stats
            .dead_accounts
            .fetch_add(dead, Ordering::Relaxed);

        alive_total
    }

    fn try_recycle_store(
        &self,
        slot: Slot,
        min_size: u64,
        max_size: u64,
    ) -> Option<Arc<AccountStorageEntry>> {
        let mut max = 0;
        let mut min = std::u64::MAX;
        let mut avail = 0;
        let mut recycle_stores = self.recycle_stores.write().unwrap();
        for (i, (_recycled_time, store)) in recycle_stores.iter().enumerate() {
            if Arc::strong_count(store) == 1 {
                max = std::cmp::max(store.accounts.capacity(), max);
                min = std::cmp::min(store.accounts.capacity(), min);
                avail += 1;

                if store.accounts.capacity() >= min_size && store.accounts.capacity() < max_size {
                    let ret = recycle_stores.remove_entry(i);
                    drop(recycle_stores);
                    let old_id = ret.append_vec_id();
                    ret.recycle(slot, self.next_id.fetch_add(1, Ordering::AcqRel));
                    debug!(
                        "recycling store: {} {:?} old_id: {}",
                        ret.append_vec_id(),
                        ret.get_path(),
                        old_id
                    );
                    return Some(ret);
                }
            }
        }
        debug!(
            "no recycle stores max: {} min: {} len: {} looking: {}, {} avail: {}",
            max,
            min,
            recycle_stores.entry_count(),
            min_size,
            max_size,
            avail,
        );
        None
    }

    fn try_recycle_and_insert_store(
        &self,
        slot: Slot,
        min_size: u64,
        max_size: u64,
    ) -> Option<Arc<AccountStorageEntry>> {
        let store = self.try_recycle_store(slot, min_size, max_size)?;
        self.insert_store(slot, store.clone());
        Some(store)
    }

    fn create_and_insert_store(
        &self,
        slot: Slot,
        size: u64,
        from: &str,
    ) -> Arc<AccountStorageEntry> {
        self.create_and_insert_store_with_paths(slot, size, from, &self.paths)
    }

    fn new_storage_entry(&self, slot: Slot, path: &Path, size: u64) -> AccountStorageEntry {
        AccountStorageEntry::new(
            path,
            slot,
            self.next_id.fetch_add(1, Ordering::AcqRel),
            size,
        )
    }

    fn create_store(
        &self,
        slot: Slot,
        size: u64,
        from: &str,
        paths: &[PathBuf],
    ) -> Arc<AccountStorageEntry> {
        let path_index = thread_rng().gen_range(0, paths.len());
        let store = Arc::new(self.new_storage_entry(
            slot,
            Path::new(&paths[path_index]),
            Self::page_align(size),
        ));

        assert!(
            store.append_vec_id() != CACHE_VIRTUAL_STORAGE_ID,
            "We've run out of storage ids!"
        );
        debug!(
            "creating store: {} slot: {} len: {} size: {} from: {} path: {:?}",
            store.append_vec_id(),
            slot,
            store.accounts.len(),
            store.accounts.capacity(),
            from,
            store.accounts.get_path()
        );

        store
    }

    fn create_and_insert_store_with_paths(
        &self,
        slot: Slot,
        size: u64,
        from: &str,
        paths: &[PathBuf],
    ) -> Arc<AccountStorageEntry> {
        let store = self.create_store(slot, size, from, paths);
        let store_for_index = store.clone();

        self.insert_store(slot, store_for_index);
        store
    }

    fn insert_store(&self, slot: Slot, store: Arc<AccountStorageEntry>) {
        let slot_storages: SlotStores = self.storage.get_slot_stores(slot).unwrap_or_else(||
            // DashMap entry.or_insert() returns a RefMut, essentially a write lock,
            // which is dropped after this block ends, minimizing time held by the lock.
            // However, we still want to persist the reference to the `SlotStores` behind
            // the lock, hence we clone it out, (`SlotStores` is an Arc so is cheap to clone).
            self.storage
                .0
                .entry(slot)
                .or_insert(Arc::new(RwLock::new(HashMap::new())))
                .clone());

        assert!(slot_storages
            .write()
            .unwrap()
            .insert(store.append_vec_id(), store)
            .is_none());
    }

    fn is_shrinking_productive(slot: Slot, stores: &[Arc<AccountStorageEntry>]) -> bool {
        let mut alive_count = 0;
        let mut stored_count = 0;
        let mut alive_bytes = 0;
        let mut total_bytes = 0;

        for store in stores {
            alive_count += store.count();
            stored_count += store.approx_stored_count();
            alive_bytes += store.alive_bytes();
            total_bytes += store.total_bytes();
        }

        let aligned_bytes = Self::page_align(alive_bytes as u64);
        if Self::should_not_shrink(aligned_bytes, total_bytes, stores.len()) {
            trace!(
                "shrink_slot_forced ({}, {}): not able to shrink at all: alive/stored: ({} / {}) ({}b / {}b) save: {}",
                slot,
                stores.len(),
                alive_count,
                stored_count,
                aligned_bytes,
                total_bytes,
                total_bytes.saturating_sub(aligned_bytes),
            );
            return false;
        }

        true
    }

    fn page_align(size: u64) -> u64 {
        (size + (PAGE_SIZE - 1)) & !(PAGE_SIZE - 1)
    }

    fn should_not_shrink(aligned_bytes: u64, total_bytes: u64, num_stores: usize) -> bool {
        aligned_bytes + PAGE_SIZE > total_bytes && num_stores == 1
    }

    fn all_slots_in_storage(&self) -> Vec<Slot> {
        self.storage.all_slots()
    }

    #[allow(clippy::needless_collect)]
    pub fn generate_index(
        &self,
        limit_load_slot_count_from_snapshot: Option<usize>,
        verify: bool,
        genesis_config: &GenesisConfig,
    ) -> IndexGenerationInfo {
        let mut slots = self.storage.all_slots();
        #[allow(clippy::stable_sort_primitive)]
        slots.sort();
        if let Some(limit) = limit_load_slot_count_from_snapshot {
            slots.truncate(limit); // get rid of the newer slots and keep just the older
        }
        let max_slot = slots.last().cloned().unwrap_or_default();
        let schedule = genesis_config.epoch_schedule;
        let rent_collector = RentCollector::new(
            schedule.get_epoch(max_slot),
            &schedule,
            genesis_config.slots_per_year(),
            &genesis_config.rent,
        );
        let accounts_data_len = AtomicU64::new(0);

        // pass == 0 always runs and generates the index
        // pass == 1 only runs if verify == true.
        // verify checks that all the expected items are in the accounts index and measures how long it takes to look them all up
        let passes = if verify { 2 } else { 1 };
        for pass in 0..passes {
            if pass == 0 {
                self.accounts_index.set_startup(true);
            }
            let storage_info = StorageSizeAndCountMap::default();
            let total_processed_slots_across_all_threads = AtomicU64::new(0);
            let outer_slots_len = slots.len();
            let chunk_size = (outer_slots_len / 7) + 1; // approximately 400k slots in a snapshot
            let mut index_time = Measure::start("index");
            let insertion_time_us = AtomicU64::new(0);
            let rent_exempt = AtomicU64::new(0);
            let total_duplicates = AtomicU64::new(0);
            let storage_info_timings = Mutex::new(GenerateIndexTimings::default());
            let scan_time: u64 = slots
                .par_chunks(chunk_size)
                .map(|slots| {
                    let mut log_status = MultiThreadProgress::new(
                        &total_processed_slots_across_all_threads,
                        2,
                        outer_slots_len as u64,
                    );
                    let mut scan_time_sum = 0;
                    for (index, slot) in slots.iter().enumerate() {
                        let mut scan_time = Measure::start("scan");
                        log_status.report(index as u64);
                        let storage_maps: Vec<Arc<AccountStorageEntry>> = self
                            .storage
                            .get_slot_storage_entries(*slot)
                            .unwrap_or_default();
                        let accounts_map = self.process_storage_slot(&storage_maps);
                        scan_time.stop();
                        scan_time_sum += scan_time.as_us();
                        Self::update_storage_info(
                            &storage_info,
                            &accounts_map,
                            &storage_info_timings,
                        );

                        let insert_us = if pass == 0 {
                            // generate index
                            let SlotIndexGenerationInfo {
                                insert_time_us: insert_us,
                                num_accounts: total_this_slot,
                                num_accounts_rent_exempt: rent_exempt_this_slot,
                                accounts_data_len: accounts_data_len_this_slot,
                            } = self.generate_index_for_slot(accounts_map, slot, &rent_collector);
                            rent_exempt.fetch_add(rent_exempt_this_slot, Ordering::Relaxed);
                            total_duplicates.fetch_add(total_this_slot, Ordering::Relaxed);
                            accounts_data_len
                                .fetch_add(accounts_data_len_this_slot, Ordering::Relaxed);
                            insert_us
                        } else {
                            // verify index matches expected and measure the time to get all items
                            assert!(verify);
                            let mut lookup_time = Measure::start("lookup_time");
                            for account in accounts_map.into_iter() {
                                let (key, account_info) = account;
                                let lock = self.accounts_index.get_account_maps_read_lock(&key);
                                let x = lock.get(&key).unwrap();
                                let sl = x.slot_list.read().unwrap();
                                let mut count = 0;
                                for (slot2, account_info2) in sl.iter() {
                                    if slot2 == slot {
                                        count += 1;
                                        let ai = AccountInfo {
                                            store_id: account_info.store_id,
                                            offset: account_info.stored_account.offset,
                                            stored_size: account_info.stored_account.stored_size,
                                            lamports: account_info
                                                .stored_account
                                                .account_meta
                                                .lamports,
                                        };
                                        assert_eq!(&ai, account_info2);
                                    }
                                }
                                assert_eq!(1, count);
                            }
                            lookup_time.stop();
                            lookup_time.as_us()
                        };
                        insertion_time_us.fetch_add(insert_us, Ordering::Relaxed);
                    }
                    scan_time_sum
                })
                .sum();
            index_time.stop();

            info!("rent_collector: {:?}", rent_collector);
            let mut min_bin_size = usize::MAX;
            let mut max_bin_size = usize::MIN;
            let total_items = self
                .accounts_index
                .account_maps
                .iter()
                .map(|map_bin| {
                    let len = map_bin.read().unwrap().len_for_stats();
                    min_bin_size = std::cmp::min(min_bin_size, len);
                    max_bin_size = std::cmp::max(max_bin_size, len);
                    len
                })
                .sum();

            // subtract data.len() from accounts_data_len for all old accounts that are in the index twice
            let mut accounts_data_len_dedup_timer =
                Measure::start("handle accounts data len duplicates");
            if pass == 0 {
                let mut unique_pubkeys = HashSet::<Pubkey>::default();
                self.uncleaned_pubkeys.iter().for_each(|entry| {
                    entry.value().iter().for_each(|pubkey| {
                        unique_pubkeys.insert(*pubkey);
                    })
                });
                let accounts_data_len_from_duplicates = unique_pubkeys
                    .into_iter()
                    .collect::<Vec<_>>()
                    .par_chunks(4096)
                    .map(|pubkeys| self.pubkeys_to_duplicate_accounts_data_len(pubkeys))
                    .sum();
                accounts_data_len.fetch_sub(accounts_data_len_from_duplicates, Ordering::Relaxed);
                info!(
                    "accounts data len: {}",
                    accounts_data_len.load(Ordering::Relaxed)
                );
            }
            accounts_data_len_dedup_timer.stop();

            let storage_info_timings = storage_info_timings.into_inner().unwrap();

            let mut index_flush_us = 0;
            if pass == 0 {
                // tell accounts index we are done adding the initial accounts at startup
                let mut m = Measure::start("accounts_index_idle_us");
                self.accounts_index.set_startup(false);
                m.stop();
                index_flush_us = m.as_us();
            }

            let mut timings = GenerateIndexTimings {
                index_flush_us,
                scan_time,
                index_time: index_time.as_us(),
                insertion_time_us: insertion_time_us.load(Ordering::Relaxed),
                min_bin_size,
                max_bin_size,
                total_items,
                rent_exempt: rent_exempt.load(Ordering::Relaxed),
                total_duplicates: total_duplicates.load(Ordering::Relaxed),
                storage_size_accounts_map_us: storage_info_timings.storage_size_accounts_map_us,
                storage_size_accounts_map_flatten_us: storage_info_timings
                    .storage_size_accounts_map_flatten_us,
                accounts_data_len_dedup_time_us: accounts_data_len_dedup_timer.as_us(),
                ..GenerateIndexTimings::default()
            };

            if pass == 0 {
                // Need to add these last, otherwise older updates will be cleaned
                for slot in &slots {
                    self.accounts_index.add_root(*slot, false);
                }

                self.set_storage_count_and_alive_bytes(storage_info, &mut timings);
            }
            timings.report();
        }

        IndexGenerationInfo {
            accounts_data_len: accounts_data_len.load(Ordering::Relaxed),
        }
    }

    fn set_storage_count_and_alive_bytes(
        &self,
        stored_sizes_and_counts: StorageSizeAndCountMap,
        timings: &mut GenerateIndexTimings,
    ) {
        // store count and size for each storage
        let mut storage_size_storages_time = Measure::start("storage_size_storages");
        for slot_stores in self.storage.0.iter() {
            for (id, store) in slot_stores.value().read().unwrap().iter() {
                // Should be default at this point
                assert_eq!(store.alive_bytes(), 0);
                if let Some(entry) = stored_sizes_and_counts.get(id) {
                    trace!(
                        "id: {} setting count: {} cur: {}",
                        id,
                        entry.count,
                        store.count(),
                    );
                    store.count_and_status.write().unwrap().0 = entry.count;
                    store.alive_bytes.store(entry.stored_size, Ordering::SeqCst);
                } else {
                    trace!("id: {} clearing count", id);
                    store.count_and_status.write().unwrap().0 = 0;
                }
            }
        }
        storage_size_storages_time.stop();
        timings.storage_size_storages_us = storage_size_storages_time.as_us();
    }

    /// Used during generate_index() to get the _duplicate_ accounts data len from the given pubkeys
    fn pubkeys_to_duplicate_accounts_data_len(&self, pubkeys: &[Pubkey]) -> u64 {
        let mut accounts_data_len_from_duplicates = 0;
        pubkeys.iter().for_each(|pubkey| {
            if let Some(entry) = self.accounts_index.get_account_read_entry(pubkey) {
                let slot_list = entry.slot_list();
                if slot_list.len() < 2 {
                    return;
                }
                // Only the account data len in the highest slot should be used, and the rest are
                // duplicates.  So sort the slot list in descending slot order, skip the first
                // item, then sum up the remaining data len, which are the duplicates.
                let mut slot_list = slot_list.clone();
                slot_list
                    .select_nth_unstable_by(0, |a, b| b.0.cmp(&a.0))
                    .2
                    .iter()
                    .for_each(|(slot, account_info)| {
                        let maybe_storage_entry = self
                            .storage
                            .get_account_storage_entry(*slot, account_info.store_id);
                        let mut accessor = LoadedAccountAccessor::Stored(
                            maybe_storage_entry.map(|entry| (entry, account_info.offset)),
                        );
                        let loaded_account = accessor.check_and_get_loaded_account();
                        let account = loaded_account.take_account();
                        accounts_data_len_from_duplicates += account.data().len();
                    });
            }
        });
        accounts_data_len_from_duplicates as u64
    }

    fn generate_index_for_slot<'a>(
        &self,
        accounts_map: GenerateIndexAccountsMap<'a>,
        slot: &Slot,
        rent_collector: &RentCollector,
    ) -> SlotIndexGenerationInfo {
        if accounts_map.is_empty() {
            return SlotIndexGenerationInfo::default();
        }

        let secondary = !self.account_indexes.is_empty();

        let mut accounts_data_len = 0;
        let mut num_accounts_rent_exempt = 0;
        let num_accounts = accounts_map.len();
        let items = accounts_map.into_iter().map(
            |(
                pubkey,
                IndexAccountMapEntry {
                    write_version: _write_version,
                    store_id,
                    stored_account,
                },
            )| {
                if secondary {
                    self.accounts_index.update_secondary_indexes(
                        &pubkey,
                        &stored_account.account_meta.owner,
                        stored_account.data,
                        &self.account_indexes,
                    );
                }
                if !stored_account.is_zero_lamport() {
                    accounts_data_len += stored_account.data().len() as u64;
                }

                if !rent_collector.should_collect_rent(&pubkey, &stored_account, false)
                    || rent_collector.get_rent_due(&stored_account).is_exempt()
                {
                    num_accounts_rent_exempt += 1;
                }

                (
                    pubkey,
                    AccountInfo {
                        store_id,
                        offset: stored_account.offset,
                        stored_size: stored_account.stored_size,
                        lamports: stored_account.account_meta.lamports,
                    },
                )
            },
        );

        let (dirty_pubkeys, insert_time_us) = self
            .accounts_index
            .insert_new_if_missing_into_primary_index(*slot, num_accounts, items);

        // dirty_pubkeys will contain a pubkey if an item has multiple rooted entries for
        // a given pubkey. If there is just a single item, there is no cleaning to
        // be done on that pubkey. Use only those pubkeys with multiple updates.
        if !dirty_pubkeys.is_empty() {
            self.uncleaned_pubkeys.insert(*slot, dirty_pubkeys);
        }
        SlotIndexGenerationInfo {
            insert_time_us,
            num_accounts: num_accounts as u64,
            num_accounts_rent_exempt,
            accounts_data_len,
        }
    }

    fn update_storage_info(
        storage_info: &StorageSizeAndCountMap,
        accounts_map: &GenerateIndexAccountsMap<'_>,
        timings: &Mutex<GenerateIndexTimings>,
    ) {
        let mut storage_size_accounts_map_time = Measure::start("storage_size_accounts_map");

        let mut storage_info_local = HashMap::<AppendVecId, StorageSizeAndCount>::default();
        // first collect into a local HashMap with no lock contention
        for (_, v) in accounts_map.iter() {
            let mut info = storage_info_local
                .entry(v.store_id)
                .or_insert_with(StorageSizeAndCount::default);
            info.stored_size += v.stored_account.stored_size;
            info.count += 1;
        }
        storage_size_accounts_map_time.stop();
        // second, collect into the shared DashMap once we've figured out all the info per store_id
        let mut storage_size_accounts_map_flatten_time =
            Measure::start("storage_size_accounts_map_flatten_time");
        for (store_id, v) in storage_info_local.into_iter() {
            let mut info = storage_info
                .entry(store_id)
                .or_insert_with(StorageSizeAndCount::default);
            info.stored_size += v.stored_size;
            info.count += v.count;
        }
        storage_size_accounts_map_flatten_time.stop();

        let mut timings = timings.lock().unwrap();
        timings.storage_size_accounts_map_us += storage_size_accounts_map_time.as_us();
        timings.storage_size_accounts_map_flatten_us +=
            storage_size_accounts_map_flatten_time.as_us();
    }

    fn process_storage_slot<'a>(
        &self,
        storage_maps: &'a [Arc<AccountStorageEntry>],
    ) -> GenerateIndexAccountsMap<'a> {
        let num_accounts = storage_maps
            .iter()
            .map(|storage| storage.approx_stored_count())
            .sum();
        let mut accounts_map = GenerateIndexAccountsMap::with_capacity(num_accounts);
        storage_maps.iter().for_each(|storage| {
            let accounts = storage.all_accounts();
            accounts.into_iter().for_each(|stored_account| {
                let this_version = stored_account.meta.write_version;
                let pubkey = stored_account.meta.pubkey;
                assert!(!self.is_filler_account(&pubkey));
                match accounts_map.entry(pubkey) {
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(IndexAccountMapEntry {
                            write_version: this_version,
                            store_id: storage.append_vec_id(),
                            stored_account,
                        });
                    }
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        let occupied_version = entry.get().write_version;
                        if occupied_version < this_version {
                            entry.insert(IndexAccountMapEntry {
                                write_version: this_version,
                                store_id: storage.append_vec_id(),
                                stored_account,
                            });
                        } else {
                            assert_ne!(occupied_version, this_version);
                        }
                    }
                }
            })
        });
        accounts_map
    }

    pub fn hash_stored_account(slot: Slot, account: &StoredAccountMeta) -> Hash {
        Self::hash_account_data(
            slot,
            account.account_meta.lamports,
            &account.account_meta.owner,
            account.account_meta.executable,
            account.account_meta.rent_epoch,
            account.data,
            &account.meta.pubkey,
        )
    }

    pub fn update_accounts_hash_with_index_option(
        &self,
        use_index: bool,
        debug_verify: bool,
        slot: Slot,
        ancestors: &Ancestors,
        expected_capitalization: Option<u64>,
        can_cached_slot_be_unflushed: bool,
        slots_per_epoch: Option<Slot>,
        is_startup: bool,
    ) -> (Hash, u64) {
        let check_hash = false;
        let (hash, total_lamports) = self
            .calculate_accounts_hash_helper_with_verify(
                use_index,
                debug_verify,
                slot,
                ancestors,
                expected_capitalization,
                can_cached_slot_be_unflushed,
                check_hash,
                slots_per_epoch,
                is_startup,
            )
            .unwrap(); // unwrap here will never fail since check_hash = false
        let mut bank_hashes = self.bank_hashes.write().unwrap();
        let mut bank_hash_info = bank_hashes.get_mut(&slot).unwrap();
        bank_hash_info.snapshot_hash = hash;
        (hash, total_lamports)
    }

    #[allow(clippy::too_many_arguments)]
    fn calculate_accounts_hash_helper_with_verify(
        &self,
        use_index: bool,
        debug_verify: bool,
        slot: Slot,
        ancestors: &Ancestors,
        expected_capitalization: Option<u64>,
        can_cached_slot_be_unflushed: bool,
        check_hash: bool,
        slots_per_epoch: Option<Slot>,
        is_startup: bool,
    ) -> Result<(Hash, u64), BankHashVerificationError> {
        let (hash, total_lamports) = self.calculate_accounts_hash_helper(
            use_index,
            slot,
            ancestors,
            check_hash,
            can_cached_slot_be_unflushed,
            slots_per_epoch,
            is_startup,
        )?;
        if debug_verify {
            // calculate the other way (store or non-store) and verify results match.
            let (hash_other, total_lamports_other) = self.calculate_accounts_hash_helper(
                !use_index,
                slot,
                ancestors,
                check_hash,
                can_cached_slot_be_unflushed,
                None,
                is_startup,
            )?;

            let success = hash == hash_other
                && total_lamports == total_lamports_other
                && total_lamports == expected_capitalization.unwrap_or(total_lamports);
            assert!(success, "update_accounts_hash_with_index_option mismatch. hashes: {}, {}; lamports: {}, {}; expected lamports: {:?}, using index: {}, slot: {}", hash, hash_other, total_lamports, total_lamports_other, expected_capitalization, use_index, slot);
        }
        Ok((hash, total_lamports))
    }

    fn calculate_accounts_hash_helper(
        &self,
        use_index: bool,
        slot: Slot,
        ancestors: &Ancestors,
        check_hash: bool, // this will not be supported anymore
        can_cached_slot_be_unflushed: bool,
        slots_per_epoch: Option<Slot>,
        is_startup: bool,
    ) -> Result<(Hash, u64), BankHashVerificationError> {
        if !use_index {
            let accounts_cache_and_ancestors = if can_cached_slot_be_unflushed {
                Some((&self.accounts_cache, ancestors, &self.accounts_index))
            } else {
                None
            };

            let mut collect_time = Measure::start("collect");
            let (combined_maps, slots) = self.get_snapshot_storages(slot, None, Some(ancestors));
            collect_time.stop();

            let mut sort_time = Measure::start("sort_storages");
            let min_root = self.accounts_index.min_root();
            let storages = SortedStorages::new_with_slots(
                combined_maps.iter().zip(slots.iter()),
                min_root,
                Some(slot),
            );

            self.mark_old_slots_as_dirty(&storages, slots_per_epoch);
            sort_time.stop();

            let timings = HashStats {
                collect_snapshots_us: collect_time.as_us(),
                storage_sort_us: sort_time.as_us(),
                ..HashStats::default()
            };

            let thread_pool = if is_startup {
                None
            } else {
                Some(&self.thread_pool_clean)
            };
            Self::calculate_accounts_hash_without_index(
                &self.accounts_hash_cache_path,
                &storages,
                thread_pool,
                timings,
                check_hash,
                accounts_cache_and_ancestors,
                if self.filler_account_count > 0 {
                    self.filler_account_suffix.as_ref()
                } else {
                    None
                },
                self.num_hash_scan_passes,
            )
        } else {
            self.calculate_accounts_hash(slot, ancestors, check_hash)
        }
    }

    /// true if 'pubkey' is a filler account
    pub fn is_filler_account(&self, pubkey: &Pubkey) -> bool {
        Self::is_filler_account_helper(pubkey, self.filler_account_suffix.as_ref())
    }

    fn calculate_accounts_hash(
        &self,
        slot: Slot,
        ancestors: &Ancestors,
        check_hash: bool, // this will not be supported anymore
    ) -> Result<(Hash, u64), BankHashVerificationError> {
        use BankHashVerificationError::*;
        let mut collect = Measure::start("collect");
        let keys: Vec<_> = self
            .accounts_index
            .account_maps
            .iter()
            .flat_map(|map| {
                let mut keys = map.read().unwrap().keys();
                keys.sort_unstable(); // hashmap is not ordered, but bins are relative to each other
                keys
            })
            .collect();
        collect.stop();

        let mut scan = Measure::start("scan");
        let mismatch_found = AtomicU64::new(0);
        // Pick a chunk size big enough to allow us to produce output vectors that are smaller than the overall size.
        // We'll also accumulate the lamports within each chunk and fewer chunks results in less contention to accumulate the sum.
        let chunks = crate::accounts_hash::MERKLE_FANOUT.pow(4);
        let total_lamports = Mutex::<u64>::new(0);
        let get_hashes = || {
            keys.par_chunks(chunks)
                .map(|pubkeys| {
                    let mut sum = 0u128;
                    let result: Vec<Hash> = pubkeys
                        .iter()
                        .filter_map(|pubkey| {
                            if self.is_filler_account(pubkey) {
                                return None;
                            }
                            if let AccountIndexGetResult::Found(lock, index) =
                                self.accounts_index.get(pubkey, Some(ancestors), Some(slot))
                            {
                                let (slot, account_info) = &lock.slot_list()[index];
                                if account_info.lamports != 0 {
                                    // Because we're keeping the `lock' here, there is no need
                                    // to use retry_to_get_account_accessor()
                                    // In other words, flusher/shrinker/cleaner is blocked to
                                    // cause any Accessor(None) situtation.
                                    // Anyway this race condition concern is currently a moot
                                    // point because calculate_accounts_hash() should not
                                    // currently race with clean/shrink because the full hash
                                    // is synchronous with clean/shrink in
                                    // AccountsBackgroundService
                                    self.get_account_accessor(
                                        *slot,
                                        pubkey,
                                        account_info.store_id,
                                        account_info.offset,
                                    )
                                    .get_loaded_account()
                                    .and_then(
                                        |loaded_account| {
                                            let loaded_hash = loaded_account.loaded_hash();
                                            let balance = account_info.lamports;
                                            if check_hash && !self.is_filler_account(pubkey) {  // this will not be supported anymore
                                                let computed_hash =
                                                    loaded_account.compute_hash(*slot, pubkey);
                                                if computed_hash != loaded_hash {
                                                    info!("hash mismatch found: computed: {}, loaded: {}, pubkey: {}", computed_hash, loaded_hash, pubkey);
                                                    mismatch_found
                                                        .fetch_add(1, Ordering::Relaxed);
                                                    return None;
                                                }
                                            }

                                            sum += balance as u128;
                                            Some(loaded_hash)
                                        },
                                    )
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        })
                        .collect();
                    let mut total = total_lamports.lock().unwrap();
                    *total =
                        AccountsHash::checked_cast_for_capitalization(*total as u128 + sum);
                    result
                }).collect()
        };

        let hashes: Vec<Vec<Hash>> = if check_hash {
            get_hashes()
        } else {
            self.thread_pool_clean.install(get_hashes)
        };
        if mismatch_found.load(Ordering::Relaxed) > 0 {
            warn!(
                "{} mismatched account hash(es) found",
                mismatch_found.load(Ordering::Relaxed)
            );
            return Err(MismatchedAccountHash);
        }

        scan.stop();
        let total_lamports = *total_lamports.lock().unwrap();

        let mut hash_time = Measure::start("hash");
        let (accumulated_hash, hash_total) = AccountsHash::calculate_hash(hashes);
        hash_time.stop();
        datapoint_info!(
            "update_accounts_hash",
            ("accounts_scan", scan.as_us(), i64),
            ("hash", hash_time.as_us(), i64),
            ("hash_total", hash_total, i64),
            ("collect", collect.as_us(), i64),
        );
        Ok((accumulated_hash, total_lamports))
    }

    // modeled after get_accounts_delta_hash
    // intended to be faster than calculate_accounts_hash
    pub fn calculate_accounts_hash_without_index(
        accounts_hash_cache_path: &Path,
        storages: &SortedStorages,
        thread_pool: Option<&ThreadPool>,
        mut stats: HashStats,
        check_hash: bool,
        accounts_cache_and_ancestors: Option<(
            &AccountsCache,
            &Ancestors,
            &AccountInfoAccountsIndex,
        )>,
        filler_account_suffix: Option<&Pubkey>,
        num_hash_scan_passes: Option<usize>,
    ) -> Result<(Hash, u64), BankHashVerificationError> {
        let (num_hash_scan_passes, bins_per_pass) = Self::bins_per_pass(num_hash_scan_passes);
        let mut scan_and_hash = move || {
            let mut previous_pass = PreviousPass::default();
            let mut final_result = (Hash::default(), 0);

            let cache_hash_data = CacheHashData::new(&accounts_hash_cache_path);

            for pass in 0..num_hash_scan_passes {
                let bounds = Range {
                    start: pass * bins_per_pass,
                    end: (pass + 1) * bins_per_pass,
                };

                let result = Self::scan_snapshot_stores_with_cache(
                    &cache_hash_data,
                    storages,
                    &mut stats,
                    PUBKEY_BINS_FOR_CALCULATING_HASHES,
                    &bounds,
                    check_hash,
                    accounts_cache_and_ancestors,
                    filler_account_suffix,
                )?;

                let hash = AccountsHash {
                    filler_account_suffix: filler_account_suffix.cloned(),
                };
                let (hash, lamports, for_next_pass) = hash.rest_of_hash_calculation(
                    result,
                    &mut stats,
                    pass == num_hash_scan_passes - 1,
                    previous_pass,
                    bins_per_pass,
                );
                previous_pass = for_next_pass;
                final_result = (hash, lamports);
            }

            info!(
                "calculate_accounts_hash_without_index: slot (exclusive): {} {:?}",
                storages.range().end,
                final_result
            );
            Ok(final_result)
        };
        if let Some(thread_pool) = thread_pool {
            thread_pool.install(scan_and_hash)
        } else {
            scan_and_hash()
        }
    }

    /// Scan through all the account storage in parallel
    fn scan_account_storage_no_bank<F, F2>(
        cache_hash_data: &CacheHashData,
        accounts_cache_and_ancestors: Option<(
            &AccountsCache,
            &Ancestors,
            &AccountInfoAccountsIndex,
        )>,
        snapshot_storages: &SortedStorages,
        scan_func: F,
        after_func: F2,
        bin_range: &Range<usize>,
        bin_calculator: &PubkeyBinCalculator24,
    ) -> Vec<BinnedHashData>
    where
        F: Fn(LoadedAccount, &mut BinnedHashData, Slot) + Send + Sync,
        F2: Fn(BinnedHashData) -> BinnedHashData + Send + Sync,
    {
        let start_bin_index = bin_range.start;

        let width = snapshot_storages.range_width();
        // 2 is for 2 special chunks - unaligned slots at the beginning and end
        let chunks = 2 + (width as Slot / MAX_ITEMS_PER_CHUNK);
        let range = snapshot_storages.range();
        let slot0 = range.start;
        let first_boundary =
            ((slot0 + MAX_ITEMS_PER_CHUNK) / MAX_ITEMS_PER_CHUNK) * MAX_ITEMS_PER_CHUNK;
        (0..chunks)
            .into_par_iter()
            .map(|chunk| {
                let mut retval = vec![];
                // calculate start, end
                let (start, mut end) = if chunk == 0 {
                    if slot0 == first_boundary {
                        return after_func(retval); // if we evenly divide, nothing for special chunk 0 to do
                    }
                    // otherwise first chunk is not 'full'
                    (slot0, first_boundary)
                } else {
                    // normal chunk in the middle or at the end
                    let start = first_boundary + MAX_ITEMS_PER_CHUNK * (chunk - 1);
                    let end = start + MAX_ITEMS_PER_CHUNK;
                    (start, end)
                };
                end = std::cmp::min(end, range.end);
                if start == end {
                    return after_func(retval);
                }

                let mut file_name = String::default();
                if accounts_cache_and_ancestors.is_none()
                    && end.saturating_sub(start) == MAX_ITEMS_PER_CHUNK
                {
                    let mut load_from_cache = true;
                    let mut hasher = std::collections::hash_map::DefaultHasher::new(); // wrong one?

                    for slot in start..end {
                        let sub_storages = snapshot_storages.get(slot);
                        bin_range.start.hash(&mut hasher);
                        bin_range.end.hash(&mut hasher);
                        if let Some(sub_storages) = sub_storages {
                            if sub_storages.len() > 1 {
                                load_from_cache = false;
                                break;
                            }
                            let storage_file = sub_storages.first().unwrap().accounts.get_path();
                            slot.hash(&mut hasher);
                            storage_file.hash(&mut hasher);
                            // check alive_bytes, etc. here?
                            let amod = std::fs::metadata(storage_file);
                            if amod.is_err() {
                                load_from_cache = false;
                                break;
                            }
                            let amod = amod.unwrap().modified();
                            if amod.is_err() {
                                load_from_cache = false;
                                break;
                            }
                            let amod = amod
                                .unwrap()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            amod.hash(&mut hasher);
                        }
                    }
                    if load_from_cache {
                        // we have a hash value for all the storages in this slot
                        // so, build a file name:
                        let hash = hasher.finish();
                        file_name = format!(
                            "{}.{}.{}.{}.{}",
                            start, end, bin_range.start, bin_range.end, hash
                        );
                        if retval.is_empty() {
                            let range = bin_range.end - bin_range.start;
                            retval.append(&mut vec![Vec::new(); range]);
                        }
                        if cache_hash_data
                            .load(
                                &Path::new(&file_name),
                                &mut retval,
                                start_bin_index,
                                bin_calculator,
                            )
                            .is_ok()
                        {
                            return retval;
                        }

                        // fall through and load normally - we failed to load
                    }
                }

                for slot in start..end {
                    let sub_storages = snapshot_storages.get(slot);
                    let valid_slot = sub_storages.is_some();
                    if let Some((cache, ancestors, accounts_index)) = accounts_cache_and_ancestors {
                        if let Some(slot_cache) = cache.slot_cache(slot) {
                            if valid_slot
                                || ancestors.contains_key(&slot)
                                || accounts_index.is_root(slot)
                            {
                                let keys = slot_cache.get_all_pubkeys();
                                for key in keys {
                                    if let Some(cached_account) = slot_cache.get_cloned(&key) {
                                        let mut accessor = LoadedAccountAccessor::Cached(Some(
                                            Cow::Owned(cached_account),
                                        ));
                                        let account = accessor.get_loaded_account().unwrap();
                                        scan_func(account, &mut retval, slot);
                                    };
                                }
                            }
                        }
                    }

                    if let Some(sub_storages) = sub_storages {
                        Self::scan_multiple_account_storages_one_slot(
                            sub_storages,
                            &scan_func,
                            slot,
                            &mut retval,
                        );
                    }
                }
                let r = after_func(retval);
                if !file_name.is_empty() {
                    let result = cache_hash_data.save(Path::new(&file_name), &r);

                    if result.is_err() {
                        info!(
                            "FAILED_TO_SAVE: {}-{}, {}, first_boundary: {}, {:?}",
                            range.start, range.end, width, first_boundary, file_name,
                        );
                    }
                }
                r
            })
            .filter(|x| !x.is_empty())
            .collect()
    }

    fn scan_multiple_account_storages_one_slot<F, B>(
        storages: &[Arc<AccountStorageEntry>],
        scan_func: &F,
        slot: Slot,
        retval: &mut B,
    ) where
        F: Fn(LoadedAccount, &mut B, Slot) + Send + Sync,
        B: Send + Default,
    {
        // we have to call the scan_func in order of write_version within a slot if there are multiple storages per slot
        let mut len = storages.len();
        let mut progress = Vec::with_capacity(len);
        let mut current = Vec::with_capacity(len);
        for storage in storages {
            let accounts = storage.accounts.accounts(0);
            let mut iterator: std::vec::IntoIter<StoredAccountMeta<'_>> = accounts.into_iter();
            if let Some(item) = iterator
                .next()
                .map(|stored_account| (stored_account.meta.write_version, Some(stored_account)))
            {
                current.push(item);
                progress.push(iterator);
            }
        }
        while !progress.is_empty() {
            let mut min = current[0].0;
            let mut min_index = 0;
            for (i, (item, _)) in current.iter().enumerate().take(len).skip(1) {
                if item < &min {
                    min_index = i;
                    min = *item;
                }
            }
            let mut account = (0, None);
            std::mem::swap(&mut account, &mut current[min_index]);
            scan_func(LoadedAccount::Stored(account.1.unwrap()), retval, slot);
            let next = progress[min_index]
                .next()
                .map(|stored_account| (stored_account.meta.write_version, Some(stored_account)));
            match next {
                Some(item) => {
                    current[min_index] = item;
                }
                None => {
                    current.remove(min_index);
                    progress.remove(min_index);
                    len -= 1;
                }
            }
        }
    }

    fn scan_snapshot_stores_with_cache(
        cache_hash_data: &CacheHashData,
        storage: &SortedStorages,
        mut stats: &mut crate::accounts_hash::HashStats,
        bins: usize,
        bin_range: &Range<usize>,
        check_hash: bool,
        accounts_cache_and_ancestors: Option<(
            &AccountsCache,
            &Ancestors,
            &AccountInfoAccountsIndex,
        )>,
        filler_account_suffix: Option<&Pubkey>,
    ) -> Result<Vec<BinnedHashData>, BankHashVerificationError> {
        let bin_calculator = PubkeyBinCalculator24::new(bins);
        assert!(bin_range.start < bins && bin_range.end <= bins && bin_range.start < bin_range.end);
        let mut time = Measure::start("scan all accounts");
        stats.num_snapshot_storage = storage.storage_count();
        stats.num_slots = storage.slot_count();
        let mismatch_found = AtomicU64::new(0);
        let range = bin_range.end - bin_range.start;
        let sort_time = AtomicU64::new(0);

        let result: Vec<BinnedHashData> = Self::scan_account_storage_no_bank(
            cache_hash_data,
            accounts_cache_and_ancestors,
            storage,
            |loaded_account: LoadedAccount, accum: &mut BinnedHashData, slot: Slot| {
                let pubkey = loaded_account.pubkey();
                let mut pubkey_to_bin_index = bin_calculator.bin_from_pubkey(pubkey);
                if !bin_range.contains(&pubkey_to_bin_index) {
                    return;
                }

                // when we are scanning with bin ranges, we don't need to use exact bin numbers. Subtract to make first bin we care about at index 0.
                pubkey_to_bin_index -= bin_range.start;

                let raw_lamports = loaded_account.lamports();
                let zero_raw_lamports = raw_lamports == 0;
                let balance = if zero_raw_lamports {
                    crate::accounts_hash::ZERO_RAW_LAMPORTS_SENTINEL
                } else {
                    raw_lamports
                };

                let source_item =
                    CalculateHashIntermediate::new(loaded_account.loaded_hash(), balance, *pubkey);

                if check_hash && !Self::is_filler_account_helper(pubkey, filler_account_suffix) {
                    // this will not be supported anymore
                    let computed_hash = loaded_account.compute_hash(slot, pubkey);
                    if computed_hash != source_item.hash {
                        info!(
                            "hash mismatch found: computed: {}, loaded: {}, pubkey: {}",
                            computed_hash, source_item.hash, pubkey
                        );
                        mismatch_found.fetch_add(1, Ordering::Relaxed);
                    }
                }
                if accum.is_empty() {
                    accum.append(&mut vec![Vec::new(); range]);
                }
                accum[pubkey_to_bin_index].push(source_item);
            },
            |x| {
                let (result, timing) = Self::sort_slot_storage_scan(x);
                sort_time.fetch_add(timing, Ordering::Relaxed);
                result
            },
            bin_range,
            &bin_calculator,
        );

        stats.sort_time_total_us += sort_time.load(Ordering::Relaxed);

        if check_hash && mismatch_found.load(Ordering::Relaxed) > 0 {
            warn!(
                "{} mismatched account hash(es) found",
                mismatch_found.load(Ordering::Relaxed)
            );
            return Err(BankHashVerificationError::MismatchedAccountHash);
        }

        time.stop();
        stats.scan_time_total_us += time.as_us();

        Ok(result)
    }

    fn sort_slot_storage_scan(accum: BinnedHashData) -> (BinnedHashData, u64) {
        let time = AtomicU64::new(0);
        (
            accum
                .into_iter()
                .map(|mut items| {
                    let mut sort_time = Measure::start("sort");
                    {
                        // sort_by vs unstable because slot and write_version are already in order
                        items.sort_by(AccountsHash::compare_two_hash_entries);
                    }
                    sort_time.stop();
                    time.fetch_add(sort_time.as_us(), Ordering::Relaxed);
                    items
                })
                .collect(),
            time.load(Ordering::Relaxed),
        )
    }

    // storages are sorted by slot and have range info.
    // if we know slots_per_epoch, then add all stores older than slots_per_epoch to dirty_stores so clean visits these slots
    fn mark_old_slots_as_dirty(&self, storages: &SortedStorages, slots_per_epoch: Option<Slot>) {
        if let Some(slots_per_epoch) = slots_per_epoch {
            let max = storages.range().end;
            let acceptable_straggler_slot_count = 100; // do nothing special for these old stores which will likely get cleaned up shortly
            let sub = slots_per_epoch + acceptable_straggler_slot_count;
            let in_epoch_range_start = max.saturating_sub(sub);
            for slot in storages.range().start..in_epoch_range_start {
                if let Some(storages) = storages.get(slot) {
                    storages.iter().for_each(|store| {
                        self.dirty_stores
                            .insert((slot, store.append_vec_id()), store.clone());
                    });
                }
            }
        }
    }

    pub fn add_root(&self, slot: Slot) -> AccountsAddRootTiming {
        let mut index_time = Measure::start("index_add_root");
        self.accounts_index.add_root(slot, self.caching_enabled);
        index_time.stop();
        let mut cache_time = Measure::start("cache_add_root");
        if self.caching_enabled {
            self.accounts_cache.add_root(slot);
        }
        cache_time.stop();
        let mut store_time = Measure::start("store_add_root");
        if let Some(slot_stores) = self.storage.get_slot_stores(slot) {
            for (store_id, store) in slot_stores.read().unwrap().iter() {
                self.dirty_stores.insert((slot, *store_id), store.clone());
            }
        }
        store_time.stop();

        AccountsAddRootTiming {
            index_us: index_time.as_us(),
            cache_us: cache_time.as_us(),
            store_us: store_time.as_us(),
        }
    }

    pub fn store_cached(&self, slot: Slot, accounts: &[(&Pubkey, &AccountSharedData)]) {
        self.store(slot, accounts, self.caching_enabled);
    }

    pub fn is_filler_account_helper(
        pubkey: &Pubkey,
        filler_account_suffix: Option<&Pubkey>,
    ) -> bool {
        let offset = Self::filler_prefix_bytes();
        filler_account_suffix
            .as_ref()
            .map(|filler_account_suffix| {
                pubkey.as_ref()[offset..] == filler_account_suffix.as_ref()[offset..]
            })
            .unwrap_or_default()
    }

    fn filler_prefix_bytes() -> usize {
        Self::filler_unique_id_bytes() + Self::filler_rent_partition_prefix_bytes()
    }

    pub fn range_scan_accounts<F, A, R>(
        &self,
        metric_name: &'static str,
        ancestors: &Ancestors,
        range: R,
        config: &ScanConfig,
        scan_func: F,
    ) -> A
    where
        F: Fn(&mut A, Option<(&Pubkey, AccountSharedData, Slot)>),
        A: Default,
        R: RangeBounds<Pubkey> + std::fmt::Debug,
    {
        let mut collector = A::default();
        self.accounts_index.range_scan_accounts(
            metric_name,
            ancestors,
            range,
            config,
            |pubkey, (account_info, slot)| {
                // unlike other scan fns, this is called from Bank::collect_rent_eagerly(),
                // which is on-consensus processing in the banking/replaying stage.
                // This requires infallible and consistent account loading.
                // So, we unwrap Option<LoadedAccount> from get_loaded_account() here.
                // This is safe because this closure is invoked with the account_info,
                // while we lock the index entry at AccountsIndex::do_scan_accounts() ultimately,
                // meaning no other subsystems can invalidate the account_info before making their
                // changes to the index entry.
                // For details, see the comment in retry_to_get_account_accessor()
                let account_slot = self
                    .get_account_accessor(slot, pubkey, account_info.store_id, account_info.offset)
                    .get_loaded_account()
                    .map(|loaded_account| (pubkey, loaded_account.take_account(), slot))
                    .unwrap();
                scan_func(&mut collector, Some(account_slot))
            },
        );
        collector
    }

    /// Store the account update.
    /// only called by tests
    pub fn store_uncached(&self, slot: Slot, accounts: &[(&Pubkey, &AccountSharedData)]) {
        self.store(slot, accounts, false);
    }

    fn store(&self, slot: Slot, accounts: &[(&Pubkey, &AccountSharedData)], is_cached_store: bool) {
        // If all transactions in a batch are errored,
        // it's possible to get a store with no accounts.
        if accounts.is_empty() {
            return;
        }

        let mut stats = BankHashStats::default();
        let mut total_data = 0;
        accounts.iter().for_each(|(_pubkey, account)| {
            total_data += account.data().len();
            stats.update(*account);
        });

        self.stats
            .store_total_data
            .fetch_add(total_data as u64, Ordering::Relaxed);

        {
            // we need to drop bank_hashes to prevent deadlocks
            let mut bank_hashes = self.bank_hashes.write().unwrap();
            let slot_info = bank_hashes
                .entry(slot)
                .or_insert_with(BankHashInfo::default);
            slot_info.stats.merge(&stats);
        }

        // we use default hashes for now since the same account may be stored to the cache multiple times
        self.store_accounts_unfrozen(slot, accounts, None, is_cached_store);
        self.report_store_timings();
    }

    fn store_accounts_unfrozen(
        &self,
        slot: Slot,
        accounts: &[(&Pubkey, &AccountSharedData)],
        hashes: Option<&[&Hash]>,
        is_cached_store: bool,
    ) {
        // This path comes from a store to a non-frozen slot.
        // If a store is dead here, then a newer update for
        // each pubkey in the store must exist in another
        // store in the slot. Thus it is safe to reset the store and
        // re-use it for a future store op. The pubkey ref counts should still
        // hold just 1 ref from this slot.
        let reset_accounts = true;

        self.store_accounts_custom(
            slot,
            accounts,
            hashes,
            None::<StorageFinder>,
            None::<Box<dyn Iterator<Item = u64>>>,
            is_cached_store,
            reset_accounts,
        );
    }

    fn report_store_timings(&self) {
        if self.stats.last_store_report.should_update(1000) {
            let (read_only_cache_hits, read_only_cache_misses) =
                self.read_only_accounts_cache.get_and_reset_stats();
            datapoint_info!(
                "accounts_db_store_timings",
                (
                    "hash_accounts",
                    self.stats.store_hash_accounts.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "store_accounts",
                    self.stats.store_accounts.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "update_index",
                    self.stats.store_update_index.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "handle_reclaims",
                    self.stats.store_handle_reclaims.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "append_accounts",
                    self.stats.store_append_accounts.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "find_storage",
                    self.stats.store_find_store.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "num_accounts",
                    self.stats.store_num_accounts.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "total_data",
                    self.stats.store_total_data.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "read_only_accounts_cache_entries",
                    self.read_only_accounts_cache.cache_len(),
                    i64
                ),
                (
                    "read_only_accounts_cache_data_size",
                    self.read_only_accounts_cache.data_size(),
                    i64
                ),
                ("read_only_accounts_cache_hits", read_only_cache_hits, i64),
                (
                    "read_only_accounts_cache_misses",
                    read_only_cache_misses,
                    i64
                ),
                (
                    "calc_stored_meta_us",
                    self.stats.calc_stored_meta.swap(0, Ordering::Relaxed),
                    i64
                ),
            );

            let recycle_stores = self.recycle_stores.read().unwrap();
            datapoint_info!(
                "accounts_db_store_timings2",
                (
                    "recycle_store_count",
                    self.stats.recycle_store_count.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "current_recycle_store_count",
                    recycle_stores.entry_count(),
                    i64
                ),
                (
                    "current_recycle_store_bytes",
                    recycle_stores.total_bytes(),
                    i64
                ),
                (
                    "create_store_count",
                    self.stats.create_store_count.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "store_get_slot_store",
                    self.stats.store_get_slot_store.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "store_find_existing",
                    self.stats.store_find_existing.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "dropped_stores",
                    self.stats.dropped_stores.swap(0, Ordering::Relaxed),
                    i64
                ),
            );
        }
    }

    pub fn index_scan_accounts<F, A>(
        &self,
        ancestors: &Ancestors,
        bank_id: BankId,
        index_key: IndexKey,
        scan_func: F,
        config: &ScanConfig,
    ) -> ScanResult<(A, bool)>
    where
        F: Fn(&mut A, Option<(&Pubkey, AccountSharedData, Slot)>),
        A: Default,
    {
        let key = match &index_key {
            IndexKey::ProgramId(key) => key,
            IndexKey::SplTokenMint(key) => key,
            IndexKey::SplTokenOwner(key) => key,
            IndexKey::VelasAccountStorage(key) => key,
            IndexKey::VelasAccountOwner(key) => key,
            IndexKey::VelasAccountOperational(key) => key,
            IndexKey::VelasRelyingOwner(key) => key,
        };

        if !self.account_indexes.include_key(key) {
            // the requested key was not indexed in the secondary index, so do a normal scan
            let used_index = false;
            let scan_result = self.scan_accounts(ancestors, bank_id, scan_func, config)?;
            return Ok((scan_result, used_index));
        }

        let mut collector = A::default();
        self.accounts_index.index_scan_accounts(
            ancestors,
            bank_id,
            index_key,
            |pubkey, (account_info, slot)| {
                let account_slot = self
                    .get_account_accessor(slot, pubkey, account_info.store_id, account_info.offset)
                    .get_loaded_account()
                    .map(|loaded_account| (pubkey, loaded_account.take_account(), slot));
                scan_func(&mut collector, account_slot)
            },
            config,
        )?;
        let used_index = true;
        Ok((collector, used_index))
    }

    pub fn scan_accounts<F, A>(
        &self,
        ancestors: &Ancestors,
        bank_id: BankId,
        scan_func: F,
        config: &ScanConfig,
    ) -> ScanResult<A>
    where
        F: Fn(&mut A, Option<(&Pubkey, AccountSharedData, Slot)>),
        A: Default,
    {
        let mut collector = A::default();

        // This can error out if the slots being scanned over are aborted
        self.accounts_index.scan_accounts(
            ancestors,
            bank_id,
            |pubkey, (account_info, slot)| {
                let account_slot = self
                    .get_account_accessor(slot, pubkey, account_info.store_id, account_info.offset)
                    .get_loaded_account()
                    .map(|loaded_account| (pubkey, loaded_account.take_account(), slot));
                scan_func(&mut collector, account_slot)
            },
            config,
        )?;

        Ok(collector)
    }

    pub fn load(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
        load_hint: LoadHint,
    ) -> Option<(AccountSharedData, Slot)> {
        self.do_load(ancestors, pubkey, None, load_hint)
    }

    /// return (num_hash_scan_passes, bins_per_pass)
    fn bins_per_pass(num_hash_scan_passes: Option<usize>) -> (usize, usize) {
        let num_hash_scan_passes = num_hash_scan_passes.unwrap_or(NUM_SCAN_PASSES_DEFAULT);
        let bins_per_pass = PUBKEY_BINS_FOR_CALCULATING_HASHES / num_hash_scan_passes;
        assert!(
            num_hash_scan_passes <= PUBKEY_BINS_FOR_CALCULATING_HASHES,
            "num_hash_scan_passes must be <= {}",
            PUBKEY_BINS_FOR_CALCULATING_HASHES
        );
        assert_eq!(
            bins_per_pass * num_hash_scan_passes,
            PUBKEY_BINS_FOR_CALCULATING_HASHES
        ); // evenly divisible

        (num_hash_scan_passes, bins_per_pass)
    }

    

    fn default_with_accounts_index(
        accounts_index: AccountInfoAccountsIndex,
        accounts_hash_cache_path: Option<PathBuf>,
        num_hash_scan_passes: Option<usize>,
    ) -> Self {
        let num_threads = get_thread_count();
        const MAX_READ_ONLY_CACHE_DATA_SIZE: usize = 200_000_000;

        let mut temp_accounts_hash_cache_path = None;
        let accounts_hash_cache_path = accounts_hash_cache_path.unwrap_or_else(|| {
            temp_accounts_hash_cache_path = Some(TempDir::new().unwrap());
            temp_accounts_hash_cache_path
                .as_ref()
                .unwrap()
                .path()
                .to_path_buf()
        });

        let mut bank_hashes = HashMap::new();
        bank_hashes.insert(0, BankHashInfo::default());

        // validate inside here
        Self::bins_per_pass(num_hash_scan_passes);

        AccountsDb {
            accounts_index,
            storage: AccountStorage::default(),
            accounts_cache: AccountsCache::default(),
            sender_bg_hasher: None,
            read_only_accounts_cache: ReadOnlyAccountsCache::new(MAX_READ_ONLY_CACHE_DATA_SIZE),
            recycle_stores: RwLock::new(RecycleStores::default()),
            uncleaned_pubkeys: DashMap::new(),
            next_id: AtomicUsize::new(0),
            shrink_candidate_slots_v1: Mutex::new(Vec::new()),
            shrink_candidate_slots: Mutex::new(HashMap::new()),
            write_cache_limit_bytes: None,
            write_version: AtomicU64::new(0),
            paths: vec![],
            accounts_hash_cache_path,
            temp_accounts_hash_cache_path,
            shrink_paths: RwLock::new(None),
            temp_paths: None,
            file_size: DEFAULT_FILE_SIZE,
            thread_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(num_threads)
                .thread_name(|i| format!("solana-db-accounts-{}", i))
                .build()
                .unwrap(),
            thread_pool_clean: make_min_priority_thread_pool(),
            min_num_stores: num_threads,
            bank_hashes: RwLock::new(bank_hashes),
            external_purge_slots_stats: PurgeStats::default(),
            clean_accounts_stats: CleanAccountsStats::default(),
            shrink_stats: ShrinkStats::default(),
            stats: AccountsStats::default(),
            cluster_type: None,
            account_indexes: AccountSecondaryIndexes::default(),
            caching_enabled: false,
            #[cfg(test)]
            load_delay: u64::default(),
            #[cfg(test)]
            load_limit: AtomicU64::default(),
            is_bank_drop_callback_enabled: AtomicBool::default(),
            remove_unrooted_slots_synchronization: RemoveUnrootedSlotsSynchronization::default(),
            shrink_ratio: AccountShrinkThreshold::default(),
            dirty_stores: DashMap::default(),
            zero_lamport_accounts_to_purge_after_full_snapshot: DashSet::default(),
            accounts_update_notifier: None,
            filler_account_count: 0,
            filler_account_suffix: None,
            num_hash_scan_passes,
        }
    }

    pub fn new_with_config(
        paths: Vec<PathBuf>,
        cluster_type: &ClusterType,
        account_indexes: AccountSecondaryIndexes,
        caching_enabled: bool,
        shrink_ratio: AccountShrinkThreshold,
        accounts_db_config: Option<AccountsDbConfig>,
        accounts_update_notifier: Option<AccountsUpdateNotifier>,
    ) -> Self {
        let accounts_index =
            AccountsIndex::new(accounts_db_config.as_ref().and_then(|x| x.index.clone()));
        let accounts_hash_cache_path = accounts_db_config
            .as_ref()
            .and_then(|x| x.accounts_hash_cache_path.clone());
        let filler_account_count = accounts_db_config
            .as_ref()
            .and_then(|cfg| cfg.filler_account_count)
            .unwrap_or_default();
        let filler_account_suffix = if filler_account_count > 0 {
            Some(sdk::pubkey::new_rand())
        } else {
            None
        }; 
        let paths_is_empty = paths.is_empty();
        let mut new = Self {
            paths,
            cluster_type: Some(*cluster_type),
            account_indexes,
            caching_enabled,
            shrink_ratio,
            accounts_update_notifier,
            filler_account_count,
            filler_account_suffix,
            write_cache_limit_bytes: accounts_db_config
                .as_ref()
                .and_then(|x| x.write_cache_limit_bytes),
            ..Self::default_with_accounts_index(
                accounts_index,
                accounts_hash_cache_path,
                accounts_db_config
                    .as_ref()
                    .and_then(|cfg| cfg.hash_calc_num_passes),
            )
        };
        if paths_is_empty {
            // Create a temporary set of accounts directories, used primarily
            // for testing
            let (temp_dirs, paths) = get_temp_accounts_paths(DEFAULT_NUM_DIRS).unwrap();
            new.accounts_update_notifier = None;
            new.paths = paths;
            new.temp_paths = Some(temp_dirs);
        };

        new.start_background_hasher();
        {
            for path in new.paths.iter() {
                std::fs::create_dir_all(path).expect("Create directory failed.");
            }
        }
        new
    }

    fn start_background_hasher(&mut self) {
        let (sender, receiver) = unbounded();
        Builder::new()
            .name("solana-db-store-hasher-accounts".to_string())
            .spawn(move || {
                Self::background_hasher(receiver);
            })
            .unwrap();
        self.sender_bg_hasher = Some(sender);
    }

    fn background_hasher(receiver: Receiver<CachedAccount>) {
        loop {
            let result = receiver.recv();
            match result {
                Ok(account) => {
                    // if we hold the only ref, then this account doesn't need to be hashed, we ignore this account and it will disappear
                    if Arc::strong_count(&account) > 1 {
                        // this will cause the hash to be calculated and store inside account if it needs to be calculated
                        let _ = (*account).hash();
                    };
                }
                Err(_) => {
                    break;
                }
            }
        }
    }

    pub fn hash_account<T: ReadableAccount>(slot: Slot, account: &T, pubkey: &Pubkey) -> Hash {
        Self::hash_account_data(
            slot,
            account.wens(),
            account.owner(),
            account.executable(),
            account.rent_epoch(),
            account.data(),
            pubkey,
        )
    }

    fn hash_account_data(
        slot: Slot,
        lamports: u64,
        owner: &Pubkey,
        executable: bool,
        rent_epoch: Epoch,
        data: &[u8],
        pubkey: &Pubkey,
    ) -> Hash {
        if lamports == 0 {
            return Hash::default();
        }

        let mut hasher = blake3::Hasher::new();

        hasher.update(&lamports.to_le_bytes());

        hasher.update(&slot.to_le_bytes());

        hasher.update(&rent_epoch.to_le_bytes());

        hasher.update(data);

        if executable {
            hasher.update(&[1u8; 1]);
        } else {
            hasher.update(&[0u8; 1]);
        }

        hasher.update(owner.as_ref());
        hasher.update(pubkey.as_ref());

        Hash::new_from_array(
            <[u8; sdk::hash::HASH_BYTES]>::try_from(hasher.finalize().as_slice()).unwrap(),
        )
    }

    /// filler accounts are space-holding accounts which are ignored by hash calculations and rent.
    /// They are designed to allow a validator to run against a network successfully while simulating having many more accounts present.
    /// All filler accounts share a common pubkey suffix. The suffix is randomly generated per validator on startup.
    /// The filler accounts are added to each slot in the snapshot after index generation.
    /// The accounts added in a slot are setup to have pubkeys such that rent will be collected from them before (or when?) their slot becomes an epoch old.
    /// Thus, the filler accounts are rewritten by rent and the old slot can be thrown away successfully.
    pub fn maybe_add_filler_accounts(&self, epoch_schedule: &EpochSchedule) {
        if self.filler_account_count == 0 {
            return;
        }

        info!("adding {} filler accounts", self.filler_account_count);
        // break this up to force the accounts out of memory after each pass
        let passes = 100;
        let mut roots = self.storage.all_slots();
        Self::retain_roots_within_one_epoch_range(&mut roots, epoch_schedule.slots_per_epoch);
        let root_count = roots.len();
        let per_pass = std::cmp::max(1, root_count / passes);
        let overall_index = AtomicUsize::new(0);
        let string = "FiLLERACCoUNTooooooooooooooooooooooooooooooo";
        let hash = Hash::from_str(string).unwrap();
        let owner = Pubkey::from_str(string).unwrap();
        let lamports = 100_000_000;
        let space = 0;
        let account = AccountSharedData::new(lamports, space, &owner);
        let added = AtomicUsize::default();
        for pass in 0..=passes {
            self.accounts_index.set_startup(true);
            let roots_in_this_pass = roots
                .iter()
                .skip(pass * per_pass)
                .take(per_pass)
                .collect::<Vec<_>>();
            self.thread_pool.install(|| {
                roots_in_this_pass.into_par_iter().for_each(|slot| {
                    let storage_maps: Vec<Arc<AccountStorageEntry>> = self
                        .storage
                        .get_slot_storage_entries(*slot)
                        .unwrap_or_default();
                    if storage_maps.is_empty() {
                        return;
                    }

                    let partition = crate::bank::Bank::variable_cycle_partition_from_previous_slot(
                        epoch_schedule,
                        *slot,
                    );
                    let subrange = crate::bank::Bank::pubkey_range_from_partition(partition);

                    let idx = overall_index.fetch_add(1, Ordering::Relaxed);
                    let filler_entries = (idx + 1) * self.filler_account_count / root_count
                        - idx * self.filler_account_count / root_count;
                    let accounts = (0..filler_entries)
                        .map(|_| {
                            let my_id = added.fetch_add(1, Ordering::Relaxed);
                            let my_id_bytes = u32::to_be_bytes(my_id as u32);

                            // pubkey begins life as entire filler 'suffix' pubkey
                            let mut key = self.filler_account_suffix.unwrap();
                            let rent_prefix_bytes = Self::filler_rent_partition_prefix_bytes();
                            // first bytes are replaced with rent partition range: filler_rent_partition_prefix_bytes
                            key.as_mut()[0..rent_prefix_bytes]
                                .copy_from_slice(&subrange.start().as_ref()[0..rent_prefix_bytes]);
                            // next bytes are replaced with my_id: filler_unique_id_bytes
                            key.as_mut()[rent_prefix_bytes
                                ..(rent_prefix_bytes + Self::filler_unique_id_bytes())]
                                .copy_from_slice(&my_id_bytes);
                            assert!(subrange.contains(&key));
                            key
                        })
                        .collect::<Vec<_>>();
                    let add = accounts
                        .iter()
                        .map(|key| (key, &account))
                        .collect::<Vec<_>>();
                    let hashes = (0..filler_entries).map(|_| hash).collect::<Vec<_>>();
                    self.store_accounts_frozen(*slot, &add[..], Some(&hashes[..]), None, None);
                })
            });
            self.accounts_index.set_startup(false);
        }
        info!("added {} filler accounts", added.load(Ordering::Relaxed));
    }

    /// retain slots in 'roots' that are > (max(roots) - slots_per_epoch)
    fn retain_roots_within_one_epoch_range(roots: &mut Vec<Slot>, slots_per_epoch: SlotCount) {
        if let Some(max) = roots.iter().max() {
            let min = max - slots_per_epoch;
            roots.retain(|slot| slot > &min);
        }
    }

    fn filler_rent_partition_prefix_bytes() -> usize {
        std::mem::size_of::<u64>()
    }

    fn filler_unique_id_bytes() -> usize {
        std::mem::size_of::<u32>()
    }

    fn store_accounts_frozen<'a, T: ReadableAccount + Sync + ZeroLamport>(
        &'a self,
        slot: Slot,
        accounts: &[(&Pubkey, &T)],
        hashes: Option<&[impl Borrow<Hash>]>,
        storage_finder: Option<StorageFinder<'a>>,
        write_version_producer: Option<Box<dyn Iterator<Item = StoredMetaWriteVersion>>>,
    ) -> StoreAccountsTiming {
        // stores on a frozen slot should not reset
        // the append vec so that hashing could happen on the store
        // and accounts in the append_vec can be unrefed correctly
        let reset_accounts = false;
        let is_cached_store = false;
        self.store_accounts_custom(
            slot,
            accounts,
            hashes,
            storage_finder,
            write_version_producer,
            is_cached_store,
            reset_accounts,
        )
    }

    fn store_accounts_custom<'a, T: ReadableAccount + Sync + ZeroLamport>(
        &'a self,
        slot: Slot,
        accounts: &[(&Pubkey, &T)],
        hashes: Option<&[impl Borrow<Hash>]>,
        storage_finder: Option<StorageFinder<'a>>,
        write_version_producer: Option<Box<dyn Iterator<Item = u64>>>,
        is_cached_store: bool,
        reset_accounts: bool,
    ) -> StoreAccountsTiming {
        let storage_finder: StorageFinder<'a> = storage_finder
            .unwrap_or_else(|| Box::new(move |slot, size| self.find_storage_candidate(slot, size)));

        let write_version_producer: Box<dyn Iterator<Item = u64>> = write_version_producer
            .unwrap_or_else(|| {
                let mut current_version = self.bulk_assign_write_version(accounts.len());
                Box::new(std::iter::from_fn(move || {
                    let ret = current_version;
                    current_version += 1;
                    Some(ret)
                }))
            });

        self.stats
            .store_num_accounts
            .fetch_add(accounts.len() as u64, Ordering::Relaxed);
        let mut store_accounts_time = Measure::start("store_accounts");
        let infos = self.store_accounts_to(
            slot,
            accounts,
            hashes,
            storage_finder,
            write_version_producer,
            is_cached_store,
        );
        store_accounts_time.stop();
        self.stats
            .store_accounts
            .fetch_add(store_accounts_time.as_us(), Ordering::Relaxed);
        let mut update_index_time = Measure::start("update_index");

        let previous_slot_entry_was_cached = self.caching_enabled && is_cached_store;

        // If the cache was flushed, then because `update_index` occurs
        // after the account are stored by the above `store_accounts_to`
        // call and all the accounts are stored, all reads after this point
        // will know to not check the cache anymore
        let mut reclaims = self.update_index(slot, infos, accounts, previous_slot_entry_was_cached);

        // For each updated account, `reclaims` should only have at most one
        // item (if the account was previously updated in this slot).
        // filter out the cached reclaims as those don't actually map
        // to anything that needs to be cleaned in the backing storage
        // entries
        if self.caching_enabled {
            reclaims.retain(|(_, r)| !r.is_cached());

            if is_cached_store {
                assert!(reclaims.is_empty());
            }
        }

        update_index_time.stop();
        self.stats
            .store_update_index
            .fetch_add(update_index_time.as_us(), Ordering::Relaxed);

        // A store for a single slot should:
        // 1) Only make "reclaims" for the same slot
        // 2) Should not cause any slots to be removed from the storage
        // database because
        //    a) this slot  has at least one account (the one being stored),
        //    b)From 1) we know no other slots are included in the "reclaims"
        //
        // From 1) and 2) we guarantee passing `no_purge_stats` == None, which is
        // equivalent to asserting there will be no dead slots, is safe.
        let no_purge_stats = None;
        let mut handle_reclaims_time = Measure::start("handle_reclaims");
        self.handle_reclaims(&reclaims, Some(slot), no_purge_stats, None, reset_accounts);
        handle_reclaims_time.stop();
        self.stats
            .store_handle_reclaims
            .fetch_add(handle_reclaims_time.as_us(), Ordering::Relaxed);

        StoreAccountsTiming {
            store_accounts_elapsed: store_accounts_time.as_us(),
            update_index_elapsed: update_index_time.as_us(),
            handle_reclaims_elapsed: handle_reclaims_time.as_us(),
        }
    }

    fn write_accounts_to_cache(
        &self,
        slot: Slot,
        hashes: Option<&[impl Borrow<Hash>]>,
        accounts_and_meta_to_store: &[(StoredMeta, Option<&impl ReadableAccount>)],
    ) -> Vec<AccountInfo> {
        let len = accounts_and_meta_to_store.len();
        let hashes = hashes.map(|hashes| {
            assert_eq!(hashes.len(), len);
            hashes
        });

        accounts_and_meta_to_store
            .iter()
            .enumerate()
            .map(|(i, (meta, account))| {
                let hash = hashes.map(|hashes| hashes[i].borrow());

                let account = account
                    .map(|account| account.to_account_shared_data())
                    .unwrap_or_default();
                let account_info = AccountInfo {
                    store_id: CACHE_VIRTUAL_STORAGE_ID,
                    offset: CACHE_VIRTUAL_OFFSET,
                    stored_size: CACHE_VIRTUAL_STORED_SIZE,
                    lamports: account.wens(),
                };

                self.notify_account_at_accounts_update(slot, meta, &account);

                let cached_account = self.accounts_cache.store(slot, &meta.pubkey, account, hash);
                // hash this account in the bg
                match &self.sender_bg_hasher {
                    Some(ref sender) => {
                        let _ = sender.send(cached_account);
                    }
                    None => (),
                };
                account_info
            })
            .collect()
    }

    fn write_accounts_to_storage<F: FnMut(Slot, usize) -> Arc<AccountStorageEntry>>(
        &self,
        slot: Slot,
        hashes: &[impl Borrow<Hash>],
        mut storage_finder: F,
        accounts_and_meta_to_store: &[(StoredMeta, Option<&impl ReadableAccount>)],
    ) -> Vec<AccountInfo> {
        assert_eq!(hashes.len(), accounts_and_meta_to_store.len());
        let mut infos: Vec<AccountInfo> = Vec::with_capacity(accounts_and_meta_to_store.len());
        let mut total_append_accounts_us = 0;
        let mut total_storage_find_us = 0;
        while infos.len() < accounts_and_meta_to_store.len() {
            let mut storage_find = Measure::start("storage_finder");
            let data_len = accounts_and_meta_to_store[infos.len()]
                .1
                .map(|account| account.data().len())
                .unwrap_or_default();
            let storage = storage_finder(slot, data_len + STORE_META_OVERHEAD);
            storage_find.stop();
            total_storage_find_us += storage_find.as_us();
            let mut append_accounts = Measure::start("append_accounts");
            let rvs = storage.accounts.append_accounts(
                &accounts_and_meta_to_store[infos.len()..],
                &hashes[infos.len()..],
            );
            assert!(!rvs.is_empty());
            append_accounts.stop();
            total_append_accounts_us += append_accounts.as_us();
            if rvs.len() == 1 {
                storage.set_status(AccountStorageStatus::Full);

                // See if an account overflows the append vecs in the slot.
                let data_len = (data_len + STORE_META_OVERHEAD) as u64;
                if !self.has_space_available(slot, data_len) {
                    let special_store_size = std::cmp::max(data_len * 2, self.file_size);
                    if self
                        .try_recycle_and_insert_store(slot, special_store_size, std::u64::MAX)
                        .is_none()
                    {
                        self.stats
                            .create_store_count
                            .fetch_add(1, Ordering::Relaxed);
                        self.create_and_insert_store(slot, special_store_size, "large create");
                    } else {
                        self.stats
                            .recycle_store_count
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                continue;
            }

            for (offsets, (_, account)) in rvs
                .windows(2)
                .zip(&accounts_and_meta_to_store[infos.len()..])
            {
                let stored_size = offsets[1] - offsets[0];
                storage.add_account(stored_size);

                infos.push(AccountInfo {
                    store_id: storage.append_vec_id(),
                    offset: offsets[0],
                    stored_size,
                    lamports: account
                        .map(|account| account.wens())
                        .unwrap_or_default(),
                });
            }
            // restore the state to available
            storage.set_status(AccountStorageStatus::Available);
        }

        self.stats
            .store_append_accounts
            .fetch_add(total_append_accounts_us, Ordering::Relaxed);
        self.stats
            .store_find_store
            .fetch_add(total_storage_find_us, Ordering::Relaxed);

        infos
    }
    
    fn has_space_available(&self, slot: Slot, size: u64) -> bool {
        let slot_storage = self.storage.get_slot_stores(slot).unwrap();
        let slot_storage_r = slot_storage.read().unwrap();
        for (_id, store) in slot_storage_r.iter() {
            if store.status() == AccountStorageStatus::Available
                && (store.accounts.capacity() - store.accounts.len() as u64) > size
            {
                return true;
            }
        }
        false
    }

    fn store_accounts_to<
        F: FnMut(Slot, usize) -> Arc<AccountStorageEntry>,
        P: Iterator<Item = u64>,
    >(
        &self,
        slot: Slot,
        accounts: &[(&Pubkey, &(impl ReadableAccount + ZeroLamport))],
        hashes: Option<&[impl Borrow<Hash>]>,
        storage_finder: F,
        mut write_version_producer: P,
        is_cached_store: bool,
    ) -> Vec<AccountInfo> {
        let mut calc_stored_meta_time = Measure::start("calc_stored_meta");
        let accounts_and_meta_to_store: Vec<_> = accounts
            .iter()
            .map(|(pubkey, account)| {
                self.read_only_accounts_cache.remove(**pubkey, slot);
                // this is the source of Some(Account) or None.
                // Some(Account) = store 'Account'
                // None = store a default/empty account with 0 lamports
                let (account, data_len) = if account.is_zero_lamport() {
                    (None, 0)
                } else {
                    (Some(*account), account.data().len() as u64)
                };
                let meta = StoredMeta {
                    write_version: write_version_producer.next().unwrap(),
                    pubkey: **pubkey,
                    data_len,
                };
                (meta, account)
            })
            .collect();
        calc_stored_meta_time.stop();
        self.stats
            .calc_stored_meta
            .fetch_add(calc_stored_meta_time.as_us(), Ordering::Relaxed);

        if self.caching_enabled && is_cached_store {
            self.write_accounts_to_cache(slot, hashes, &accounts_and_meta_to_store)
        } else {
            match hashes {
                Some(hashes) => self.write_accounts_to_storage(
                    slot,
                    hashes,
                    storage_finder,
                    &accounts_and_meta_to_store,
                ),
                None => {
                    // hash any accounts where we were lazy in calculating the hash
                    let mut hash_time = Measure::start("hash_accounts");
                    let mut stats = BankHashStats::default();
                    let len = accounts_and_meta_to_store.len();
                    let mut hashes = Vec::with_capacity(len);
                    for account in accounts {
                        stats.update(account.1);
                        let hash = Self::hash_account(slot, account.1, account.0);
                        hashes.push(hash);
                    }
                    hash_time.stop();
                    self.stats
                        .store_hash_accounts
                        .fetch_add(hash_time.as_us(), Ordering::Relaxed);

                    self.write_accounts_to_storage(
                        slot,
                        &hashes,
                        storage_finder,
                        &accounts_and_meta_to_store,
                    )
                }
            }
        }
    }

    fn find_storage_candidate(&self, slot: Slot, size: usize) -> Arc<AccountStorageEntry> {
        let mut create_extra = false;
        let mut get_slot_stores = Measure::start("get_slot_stores");
        let slot_stores_lock = self.storage.get_slot_stores(slot);
        get_slot_stores.stop();
        self.stats
            .store_get_slot_store
            .fetch_add(get_slot_stores.as_us(), Ordering::Relaxed);
        let mut find_existing = Measure::start("find_existing");
        if let Some(slot_stores_lock) = slot_stores_lock {
            let slot_stores = slot_stores_lock.read().unwrap();
            if !slot_stores.is_empty() {
                if slot_stores.len() <= self.min_num_stores {
                    let mut total_accounts = 0;
                    for store in slot_stores.values() {
                        total_accounts += store.count();
                    }

                    // Create more stores so that when scanning the storage all CPUs have work
                    if (total_accounts / 16) >= slot_stores.len() {
                        create_extra = true;
                    }
                }

                // pick an available store at random by iterating from a random point
                let to_skip = thread_rng().gen_range(0, slot_stores.len());

                for (i, store) in slot_stores.values().cycle().skip(to_skip).enumerate() {
                    if store.try_available() {
                        let ret = store.clone();
                        drop(slot_stores);
                        if create_extra {
                            if self
                                .try_recycle_and_insert_store(slot, size as u64, std::u64::MAX)
                                .is_none()
                            {
                                self.stats
                                    .create_store_count
                                    .fetch_add(1, Ordering::Relaxed);
                                self.create_and_insert_store(slot, self.file_size, "store extra");
                            } else {
                                self.stats
                                    .recycle_store_count
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        find_existing.stop();
                        self.stats
                            .store_find_existing
                            .fetch_add(find_existing.as_us(), Ordering::Relaxed);
                        return ret;
                    }
                    // looked at every store, bail...
                    if i == slot_stores.len() {
                        break;
                    }
                }
            }
        }
        find_existing.stop();
        self.stats
            .store_find_existing
            .fetch_add(find_existing.as_us(), Ordering::Relaxed);

        let store = if let Some(store) = self.try_recycle_store(slot, size as u64, std::u64::MAX) {
            self.stats
                .recycle_store_count
                .fetch_add(1, Ordering::Relaxed);
            store
        } else {
            self.stats
                .create_store_count
                .fetch_add(1, Ordering::Relaxed);
            self.create_store(slot, self.file_size, "store", &self.paths)
        };

        // try_available is like taking a lock on the store,
        // preventing other threads from using it.
        // It must succeed here and happen before insert,
        // otherwise another thread could also grab it from the index.
        assert!(store.try_available());
        self.insert_store(slot, store.clone());
        store
    }

    fn bulk_assign_write_version(&self, count: usize) -> StoredMetaWriteVersion {
        self.write_version
            .fetch_add(count as StoredMetaWriteVersion, Ordering::AcqRel)
    }

    fn update_index<T: ReadableAccount + Sync>(
        &self,
        slot: Slot,
        infos: Vec<AccountInfo>,
        accounts: &[(&Pubkey, &T)],
        previous_slot_entry_was_cached: bool,
    ) -> SlotList<AccountInfo> {
        // using a thread pool here results in deadlock panics from bank_hashes.write()
        // so, instead we limit how many threads will be created to the same size as the bg thread pool
        let chunk_size = std::cmp::max(1, accounts.len() / quarter_thread_count()); // # pubkeys/thread
        infos
            .par_chunks(chunk_size)
            .zip(accounts.par_chunks(chunk_size))
            .map(|(infos_chunk, accounts_chunk)| {
                let mut reclaims = Vec::with_capacity(infos_chunk.len() / 2);
                for (info, pubkey_account) in infos_chunk.iter().zip(accounts_chunk.iter()) {
                    let pubkey = pubkey_account.0;
                    self.accounts_index.upsert(
                        slot,
                        pubkey,
                        pubkey_account.1.owner(),
                        pubkey_account.1.data(),
                        &self.account_indexes,
                        *info,
                        &mut reclaims,
                        previous_slot_entry_was_cached,
                    );
                }
                reclaims
            })
            .flatten()
            .collect::<Vec<_>>()
    }

    fn is_candidate_for_shrink(&self, store: &Arc<AccountStorageEntry>) -> bool {
        match self.shrink_ratio {
            AccountShrinkThreshold::TotalSpace { shrink_ratio: _ } => {
                Self::page_align(store.alive_bytes() as u64) < store.total_bytes()
            }
            AccountShrinkThreshold::IndividalStore { shrink_ratio } => {
                (Self::page_align(store.alive_bytes() as u64) as f64 / store.total_bytes() as f64)
                    < shrink_ratio
            }
        }
    }

    fn remove_dead_accounts(
        &self,
        reclaims: SlotSlice<AccountInfo>,
        expected_slot: Option<Slot>,
        mut reclaimed_offsets: Option<&mut AppendVecOffsets>,
        reset_accounts: bool,
    ) -> HashSet<Slot> {
        let mut dead_slots = HashSet::new();
        let mut new_shrink_candidates: ShrinkCandidates = HashMap::new();
        let mut measure = Measure::start("remove");
        for (slot, account_info) in reclaims {
            // No cached accounts should make it here
            assert_ne!(account_info.store_id, CACHE_VIRTUAL_STORAGE_ID);
            if let Some(ref mut reclaimed_offsets) = reclaimed_offsets {
                reclaimed_offsets
                    .entry(account_info.store_id)
                    .or_default()
                    .insert(account_info.offset);
            }
            if let Some(expected_slot) = expected_slot {
                assert_eq!(*slot, expected_slot);
            }
            if let Some(store) = self
                .storage
                .get_account_storage_entry(*slot, account_info.store_id)
            {
                assert_eq!(
                    *slot, store.slot(),
                    "AccountDB::accounts_index corrupted. Storage pointed to: {}, expected: {}, should only point to one slot",
                    store.slot(), *slot
                );
                let count = store.remove_account(account_info.stored_size, reset_accounts);
                if count == 0 {
                    self.dirty_stores
                        .insert((*slot, store.append_vec_id()), store.clone());
                    dead_slots.insert(*slot);
                } else if self.caching_enabled
                    && Self::is_shrinking_productive(*slot, &[store.clone()])
                    && self.is_candidate_for_shrink(&store)
                {
                    // Checking that this single storage entry is ready for shrinking,
                    // should be a sufficient indication that the slot is ready to be shrunk
                    // because slots should only have one storage entry, namely the one that was
                    // created by `flush_slot_cache()`.
                    {
                        new_shrink_candidates
                            .entry(*slot)
                            .or_default()
                            .insert(store.append_vec_id(), store);
                    }
                }
            }
        }
        measure.stop();
        self.clean_accounts_stats
            .remove_dead_accounts_remove_us
            .fetch_add(measure.as_us(), Ordering::Relaxed);

        if self.caching_enabled {
            let mut measure = Measure::start("shrink");
            let mut shrink_candidate_slots = self.shrink_candidate_slots.lock().unwrap();
            for (slot, slot_shrink_candidates) in new_shrink_candidates {
                for (store_id, store) in slot_shrink_candidates {
                    // count could be == 0 if multiple accounts are removed
                    // at once
                    if store.count() != 0 {
                        debug!(
                            "adding: {} {} to shrink candidates: count: {}/{} bytes: {}/{}",
                            store_id,
                            slot,
                            store.approx_stored_count(),
                            store.count(),
                            store.alive_bytes(),
                            store.total_bytes()
                        );

                        shrink_candidate_slots
                            .entry(slot)
                            .or_default()
                            .insert(store_id, store);
                    }
                }
            }
            measure.stop();
            self.clean_accounts_stats
                .remove_dead_accounts_shrink_us
                .fetch_add(measure.as_us(), Ordering::Relaxed);
        }

        dead_slots.retain(|slot| {
            if let Some(slot_stores) = self.storage.get_slot_stores(*slot) {
                for x in slot_stores.read().unwrap().values() {
                    if x.count() != 0 {
                        return false;
                    }
                }
            }
            true
        });

        dead_slots
    }

    fn handle_reclaims(
        &self,
        reclaims: SlotSlice<AccountInfo>,
        expected_single_dead_slot: Option<Slot>,
        // TODO: coalesce `purge_stats` and `reclaim_result` together into one option, as they
        // are both either Some or None
        purge_stats: Option<&PurgeStats>,
        reclaim_result: Option<&mut ReclaimResult>,
        reset_accounts: bool,
    ) {
        if reclaims.is_empty() {
            return;
        }
        let (purged_account_slots, reclaimed_offsets) =
            if let Some((ref mut x, ref mut y)) = reclaim_result {
                (Some(x), Some(y))
            } else {
                (None, None)
            };
        let dead_slots = self.remove_dead_accounts(
            reclaims,
            expected_single_dead_slot,
            reclaimed_offsets,
            reset_accounts,
        );
        if purge_stats.is_none() {
            assert!(dead_slots.is_empty());
        } else if let Some(expected_single_dead_slot) = expected_single_dead_slot {
            assert!(dead_slots.len() <= 1);
            if dead_slots.len() == 1 {
                assert!(dead_slots.contains(&expected_single_dead_slot));
            }
        }

        if let Some(purge_stats) = purge_stats {
            self.process_dead_slots(&dead_slots, purged_account_slots, purge_stats);
        }
    }

    fn clean_stored_dead_slots(
        &self,
        dead_slots: &HashSet<Slot>,
        purged_account_slots: Option<&mut AccountSlots>,
    ) {
        let mut measure = Measure::start("clean_stored_dead_slots-ms");
        let mut stores: Vec<Arc<AccountStorageEntry>> = vec![];
        for slot in dead_slots.iter() {
            if let Some(slot_storage) = self.storage.get_slot_stores(*slot) {
                for store in slot_storage.read().unwrap().values() {
                    stores.push(store.clone());
                }
            }
        }
        let purged_slot_pubkeys: HashSet<(Slot, Pubkey)> = {
            self.thread_pool_clean.install(|| {
                stores
                    .into_par_iter()
                    .map(|store| {
                        let accounts = store.all_accounts();
                        let slot = store.slot();
                        accounts
                            .into_iter()
                            .map(|account| (slot, account.meta.pubkey))
                            .collect::<HashSet<(Slot, Pubkey)>>()
                    })
                    .reduce(HashSet::new, |mut reduced, store_pubkeys| {
                        reduced.extend(store_pubkeys);
                        reduced
                    })
            })
        };
        self.remove_dead_slots_metadata(
            dead_slots.iter(),
            purged_slot_pubkeys,
            purged_account_slots,
        );
        measure.stop();
        inc_new_counter_info!("clean_stored_dead_slots-ms", measure.as_ms() as usize);
        self.clean_accounts_stats
            .clean_stored_dead_slots_us
            .fetch_add(measure.as_us(), Ordering::Relaxed);
    }

    fn remove_dead_slots_metadata<'a>(
        &'a self,
        dead_slots_iter: impl Iterator<Item = &'a Slot> + Clone,
        purged_slot_pubkeys: HashSet<(Slot, Pubkey)>,
        // Should only be `Some` for non-cached slots
        purged_stored_account_slots: Option<&mut AccountSlots>,
    ) {
        let mut measure = Measure::start("remove_dead_slots_metadata-ms");
        self.clean_dead_slots_from_accounts_index(
            dead_slots_iter.clone(),
            purged_slot_pubkeys,
            purged_stored_account_slots,
        );
        {
            let mut bank_hashes = self.bank_hashes.write().unwrap();
            for slot in dead_slots_iter {
                bank_hashes.remove(slot);
            }
        }
        measure.stop();
        inc_new_counter_info!("remove_dead_slots_metadata-ms", measure.as_ms() as usize);
    }

    fn clean_dead_slots_from_accounts_index<'a>(
        &'a self,
        dead_slots_iter: impl Iterator<Item = &'a Slot> + Clone,
        purged_slot_pubkeys: HashSet<(Slot, Pubkey)>,
        // Should only be `Some` for non-cached slots
        purged_stored_account_slots: Option<&mut AccountSlots>,
    ) {
        let mut accounts_index_root_stats = AccountsIndexRootsStats::default();
        let mut measure = Measure::start("unref_from_storage");
        if let Some(purged_stored_account_slots) = purged_stored_account_slots {
            let len = purged_stored_account_slots.len();
            // we could build a higher level function in accounts_index to group by bin
            const BATCH_SIZE: usize = 10_000;
            let batches = 1 + (len / BATCH_SIZE);
            self.thread_pool_clean.install(|| {
                (0..batches).into_par_iter().for_each(|batch| {
                    let skip = batch * BATCH_SIZE;
                    for (_slot, pubkey) in purged_slot_pubkeys.iter().skip(skip).take(BATCH_SIZE) {
                        self.accounts_index.unref_from_storage(pubkey);
                    }
                })
            });
            for (slot, pubkey) in purged_slot_pubkeys {
                purged_stored_account_slots
                    .entry(pubkey)
                    .or_default()
                    .insert(slot);
            }
        }
        measure.stop();
        accounts_index_root_stats.clean_unref_from_storage_us += measure.as_us();

        let mut measure = Measure::start("clean_dead_slot");
        let mut rooted_cleaned_count = 0;
        let mut unrooted_cleaned_count = 0;
        let dead_slots: Vec<_> = dead_slots_iter
            .map(|slot| {
                if self
                    .accounts_index
                    .clean_dead_slot(*slot, &mut accounts_index_root_stats)
                {
                    rooted_cleaned_count += 1;
                } else {
                    unrooted_cleaned_count += 1;
                }
                *slot
            })
            .collect();
        measure.stop();
        accounts_index_root_stats.clean_dead_slot_us += measure.as_us();
        info!("remove_dead_slots_metadata: slots {:?}", dead_slots);

        accounts_index_root_stats.rooted_cleaned_count += rooted_cleaned_count;
        accounts_index_root_stats.unrooted_cleaned_count += unrooted_cleaned_count;

        self.clean_accounts_stats
            .latest_accounts_index_roots_stats
            .update(&accounts_index_root_stats);
    }

    // Must be kept private!, does sensitive cleanup that should only be called from
    // supported pipelines in AccountsDb
    fn process_dead_slots(
        &self,
        dead_slots: &HashSet<Slot>,
        purged_account_slots: Option<&mut AccountSlots>,
        purge_stats: &PurgeStats,
    ) {
        if dead_slots.is_empty() {
            return;
        }
        let mut clean_dead_slots = Measure::start("reclaims::clean_dead_slots");
        self.clean_stored_dead_slots(dead_slots, purged_account_slots);
        clean_dead_slots.stop();

        let mut purge_removed_slots = Measure::start("reclaims::purge_removed_slots");
        self.purge_dead_slots_from_storage(dead_slots.iter(), purge_stats);
        purge_removed_slots.stop();

        // If the slot is dead, remove the need to shrink the storages as
        // the storage entries will be purged.
        {
            let mut list = self.shrink_candidate_slots.lock().unwrap();
            for slot in dead_slots {
                list.remove(slot);
            }
        }

        debug!(
            "process_dead_slots({}): {} {} {:?}",
            dead_slots.len(),
            clean_dead_slots,
            purge_removed_slots,
            dead_slots,
        );
    }

    /// Purge the backing storage entries for the given slot, does not purge from
    /// the cache!
    fn purge_dead_slots_from_storage<'a>(
        &'a self,
        removed_slots: impl Iterator<Item = &'a Slot> + Clone,
        purge_stats: &PurgeStats,
    ) {
        // Check all slots `removed_slots` are no longer "relevant" roots.
        // Note that the slots here could have been rooted slots, but if they're passed here
        // for removal it means:
        // 1) All updates in that old root have been outdated by updates in newer roots
        // 2) Those slots/roots should have already been purged from the accounts index root
        // tracking metadata via `accounts_index.clean_dead_slot()`.
        let mut safety_checks_elapsed = Measure::start("safety_checks_elapsed");
        assert!(self
            .accounts_index
            .get_rooted_from_list(removed_slots.clone())
            .is_empty());
        safety_checks_elapsed.stop();
        purge_stats
            .safety_checks_elapsed
            .fetch_add(safety_checks_elapsed.as_us(), Ordering::Relaxed);

        let mut total_removed_storage_entries = 0;
        let mut total_removed_stored_bytes = 0;
        let mut all_removed_slot_storages = vec![];

        let mut remove_storage_entries_elapsed = Measure::start("remove_storage_entries_elapsed");
        for remove_slot in removed_slots {
            // Remove the storage entries and collect some metrics
            if let Some((_, slot_storages_to_be_removed)) = self.storage.0.remove(remove_slot) {
                {
                    let r_slot_removed_storages = slot_storages_to_be_removed.read().unwrap();
                    total_removed_storage_entries += r_slot_removed_storages.len();
                    total_removed_stored_bytes += r_slot_removed_storages
                        .values()
                        .map(|i| i.accounts.capacity())
                        .sum::<u64>();
                }
                all_removed_slot_storages.push(slot_storages_to_be_removed.clone());
            }
        }
        remove_storage_entries_elapsed.stop();
        let num_stored_slots_removed = all_removed_slot_storages.len();

        let recycle_stores_write_elapsed =
            self.recycle_slot_stores(total_removed_storage_entries, &all_removed_slot_storages);

        let mut drop_storage_entries_elapsed = Measure::start("drop_storage_entries_elapsed");
        // Backing mmaps for removed storages entries explicitly dropped here outside
        // of any locks
        drop(all_removed_slot_storages);
        drop_storage_entries_elapsed.stop();
        purge_stats
            .remove_storage_entries_elapsed
            .fetch_add(remove_storage_entries_elapsed.as_us(), Ordering::Relaxed);
        purge_stats
            .drop_storage_entries_elapsed
            .fetch_add(drop_storage_entries_elapsed.as_us(), Ordering::Relaxed);
        purge_stats
            .num_stored_slots_removed
            .fetch_add(num_stored_slots_removed, Ordering::Relaxed);
        purge_stats
            .total_removed_storage_entries
            .fetch_add(total_removed_storage_entries, Ordering::Relaxed);
        purge_stats
            .total_removed_stored_bytes
            .fetch_add(total_removed_stored_bytes, Ordering::Relaxed);
        purge_stats
            .recycle_stores_write_elapsed
            .fetch_add(recycle_stores_write_elapsed, Ordering::Relaxed);
    }

    fn recycle_slot_stores(
        &self,
        total_removed_storage_entries: usize,
        slot_stores: &[SlotStores],
    ) -> u64 {
        let mut recycled_count = 0;

        let mut recycle_stores_write_elapsed = Measure::start("recycle_stores_write_elapsed");
        let mut recycle_stores = self.recycle_stores.write().unwrap();
        recycle_stores_write_elapsed.stop();

        for slot_entries in slot_stores {
            let entry = slot_entries.read().unwrap();
            for (_store_id, stores) in entry.iter() {
                if recycle_stores.entry_count() > MAX_RECYCLE_STORES {
                    let dropped_count = total_removed_storage_entries - recycled_count;
                    self.stats
                        .dropped_stores
                        .fetch_add(dropped_count as u64, Ordering::Relaxed);
                    return recycle_stores_write_elapsed.as_us();
                }
                recycle_stores.add_entry(stores.clone());
                recycled_count += 1;
            }
        }
        recycle_stores_write_elapsed.as_us()
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

            #[cfg(not(test))]
            let load_limit = ABSURD_CONSECUTIVE_FAILED_ITERATIONS;

            #[cfg(test)]
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
