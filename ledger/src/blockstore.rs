use {
    crate::{
        // ancestor_iterator::AncestorIterator,
        blockstore_db::{
        columns as cf, AccessType, BlockstoreRecoveryMode, Column, Database,
        EvmTransactionReceiptsIndex, IteratorDirection, IteratorMode, LedgerColumn, Result,
        WriteBatch,
        },
        blockstore_meta::*,
        leader_schedule_cache::LeaderScheduleCache,
        next_slots_iterator::NextSlotsIterator,
        shred::{
            ErasureSetId, Result as ShredResult, Shred, ShredId, ShredType, Shredder,
            SHRED_PAYLOAD_SIZE,
        },
    },
    bincode::deserialize,
    evm::H256,
    log::*,
    rayon::{
        iter::{IntoParallelRefIterator, ParallelIterator},
        ThreadPool,
    },
    rocksdb::DBRawIterator,
    entry::entry::{create_ticks, Entry},
    measure::measure::Measure,
    metrics::{datapoint_debug, datapoint_error},
    rayon_threadlimit::get_thread_count,
    runtime::hardened_unpack::{unpack_genesis_archive, MAX_GENESIS_ARCHIVE_UNPACKED_SIZE},
    sdk::{
        clock::{Slot, UnixTimestamp, DEFAULT_TICKS_PER_SECOND, MS_PER_TICK},
        genesis_config::{GenesisConfig, DEFAULT_GENESIS_ARCHIVE, DEFAULT_GENESIS_FILE, 
            evm_genesis::{OpenEthereumAccountExtractor, GethAccountExtractor}
        },
        hash::Hash,
        pubkey::Pubkey,
        sanitize::Sanitize,
        signature::{Keypair, Signature, Signer},
        timing::timestamp,
        transaction::VersionedTransaction,
    },
    storage_proto::{StoredExtendedRewards, StoredTransactionStatusMeta},
    transaction_status::{
        ConfirmedBlock, ConfirmedTransaction, ConfirmedTransactionStatusWithSignature, Rewards,
        TransactionStatusMeta, TransactionWithMetadata,
    },

    evm_state as evm,

    std::{
    borrow::Cow,
        cell::RefCell,
        cmp,
        collections::{hash_map::Entry as HashMapEntry, BTreeMap, BTreeSet, HashMap, HashSet},
        convert::TryInto,
        fmt::Write as _,
        fs,
        io::{Error as IoError, ErrorKind},
        path::{Path, PathBuf},
        rc::Rc,
        sync::{
        atomic::{AtomicBool, Ordering},
            mpsc::{sync_channel, Receiver, Sender, SyncSender, TrySendError},
        Arc, Mutex, RwLock, RwLockWriteGuard,
        },
        time::Instant,
    },
    tempfile::{Builder, TempDir},
    thiserror::Error,
    trees::{Tree, TreeWalk},
};

pub use crate::blockstore_db::BlockstoreError;

// pub mod blockstore_purge;

pub const BLOCKSTORE_DIRECTORY: &str = "rocksdb";
pub type CompletedSlotsSender = SyncSender<Vec<Slot>>;

#[derive(PartialEq, Debug, Clone)]
enum ShredSource {
    Turbine,
    Repaired,
    Recovered,
}

#[derive(Error, Debug)]
pub enum InsertDataShredError {
    Exists,
    InvalidShred,
    BlockstoreError(#[from] BlockstoreError),
}

impl std::fmt::Display for InsertDataShredError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "insert data shred error")
    }
}

pub struct SlotMetaWorkingSetEntry {
    new_slot_meta: Rc<RefCell<SlotMeta>>,
    old_slot_meta: Option<SlotMeta>,
    // True only if at least one shred for this SlotMeta was inserted since the time this
    // struct was created.
    did_insert_occur: bool,
}

// Creates a new ledger with slot 0 full of ticks (and only ticks).
//
// Returns the blockhash that can be used to append entries with.
pub fn create_new_ledger(
    ledger_path: &Path,
    evm_state_json: EvmStateJson,
    genesis_config: &GenesisConfig,
    max_genesis_archive_unpacked_size: u64,
    access_type: AccessType,
) -> Result<Hash> {
    Blockstore::destroy(ledger_path)?;

    match evm_state_json {
        EvmStateJson::OpenEthereum(path) => {
            let extractor = OpenEthereumAccountExtractor::open_dump(path).unwrap();
            genesis_config.generate_evm_state_from_dump(ledger_path, extractor)?;
        },
        EvmStateJson::Geth(path) => {
            let extractor = GethAccountExtractor::open_dump(path).unwrap();
            genesis_config.generate_evm_state_from_dump(ledger_path, extractor)?;
        },
        EvmStateJson::None => genesis_config.generate_evm_state_empty(ledger_path)?,
    }
    genesis_config.write(ledger_path)?;

    // Fill slot 0 with ticks that link back to the genesis_config to bootstrap the ledger.
    let blockstore = Blockstore::open_with_access_type(ledger_path, access_type, None, false)?;
    let ticks_per_slot = genesis_config.ticks_per_slot;
    let hashes_per_tick = genesis_config.poh_config.hashes_per_tick.unwrap_or(0);
    let entries = create_ticks(ticks_per_slot, hashes_per_tick, genesis_config.hash());
    let last_hash = entries.last().unwrap().hash;
    let version = sdk::shred_version::version_from_hash(&last_hash);

    let shredder = Shredder::new(0, 0, 0, version).unwrap();
    let shreds = shredder
        .entries_to_shreds(
            &Keypair::new(),
            &entries,
            true, // is_last_in_slot
            0,    // next_shred_index
            0,    // next_code_index
        )
        .0;
    assert!(shreds.last().unwrap().last_in_slot());

    blockstore.insert_shreds(shreds, None, false)?;
    blockstore.set_roots(std::iter::once(&0))?;
    // Explicitly close the blockstore before we create the archived genesis file
    drop(blockstore);

    let archive_path = ledger_path.join(DEFAULT_GENESIS_ARCHIVE);
    let args = vec![
        "jcfhS",
        archive_path.to_str().unwrap(),
        "-C",
        ledger_path.to_str().unwrap(),
        DEFAULT_GENESIS_FILE,
        "rocksdb",
        "evm-state-genesis",
    ];

    let output = std::process::Command::new("tar")
        .env("COPYFILE_DISABLE", "1")
        .args(&args)
        .output()
        .unwrap();
    if !output.status.success() {
        use std::str::from_utf8;
        error!("tar stdout: {}", from_utf8(&output.stdout).unwrap_or("?"));
        error!("tar stderr: {}", from_utf8(&output.stderr).unwrap_or("?"));

        return Err(BlockstoreError::Io(IoError::new(
            ErrorKind::Other,
            format!(
                "Error trying to generate snapshot archive: {}",
                output.status
            ),
        )));
    }

    // ensure the genesis archive can be unpacked and it is under
    // max_genesis_archive_unpacked_size, immediately after creating it above.
    {
        let temp_dir = tempfile::tempdir_in(ledger_path).unwrap();
        // unpack into a temp dir, while completely discarding the unpacked files
        let unpack_check = unpack_genesis_archive(
            &archive_path,
            temp_dir.path(),
            max_genesis_archive_unpacked_size,
        );
        if let Err(unpack_err) = unpack_check {
            // stash problematic original archived genesis related files to
            // examine them later and to prevent validator and ledger-tool from
            // naively consuming them
            let mut error_messages = String::new();

            fs::rename(
                ledger_path.join(DEFAULT_GENESIS_ARCHIVE),
                ledger_path.join(format!("{}.failed", DEFAULT_GENESIS_ARCHIVE)),
            )
            .unwrap_or_else(|e| {
                let _ = write!(
                    error_messages,
                    "/failed to stash problematic {}: {}",
                    DEFAULT_GENESIS_ARCHIVE, e
                );
            });
            fs::rename(
                ledger_path.join(DEFAULT_GENESIS_FILE),
                ledger_path.join(format!("{}.failed", DEFAULT_GENESIS_FILE)),
            )
            .unwrap_or_else(|e| {
                let _ = write!(
                    error_messages, 
                    "/failed to stash problematic {}: {}", 
                    DEFAULT_GENESIS_FILE, e
                );
            });
            fs::rename(
                ledger_path.join("rocksdb"),
                ledger_path.join("rocksdb.failed"),
            )
            .unwrap_or_else(|e| {
                let _ = write!(error_messages, "/failed to stash problematic rocksdb: {}", e);
            });

            return Err(BlockstoreError::Io(IoError::new(
                ErrorKind::Other,
                format!(
                    "Error checking to unpack genesis archive: {}{}",
                    unpack_err, error_messages
                ),
            )));
        }
    }

    Ok(last_hash)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompletedDataSetInfo {
    pub slot: Slot,
    pub start_index: u32,
    pub end_index: u32,
}

// ledger window
pub struct Blockstore {
    ledger_path: PathBuf,
    db: Arc<Database>,
    meta_cf: LedgerColumn<cf::SlotMeta>,
    dead_slots_cf: LedgerColumn<cf::DeadSlots>,
    duplicate_slots_cf: LedgerColumn<cf::DuplicateSlots>,
    erasure_meta_cf: LedgerColumn<cf::ErasureMeta>,
    orphans_cf: LedgerColumn<cf::Orphans>,
    index_cf: LedgerColumn<cf::Index>,
    data_shred_cf: LedgerColumn<cf::ShredData>,
    code_shred_cf: LedgerColumn<cf::ShredCode>,
    transaction_status_cf: LedgerColumn<cf::TransactionStatus>,
    address_signatures_cf: LedgerColumn<cf::AddressSignatures>,
    transaction_memos_cf: LedgerColumn<cf::TransactionMemos>,
    transaction_status_index_cf: LedgerColumn<cf::TransactionStatusIndex>,
    active_transaction_status_index: RwLock<u64>,
    rewards_cf: LedgerColumn<cf::Rewards>,
    blocktime_cf: LedgerColumn<cf::Blocktime>,
    perf_samples_cf: LedgerColumn<cf::PerfSamples>,

    block_height_cf: LedgerColumn<cf::BlockHeight>,
    program_costs_cf: LedgerColumn<cf::ProgramCosts>,
    bank_hash_cf: LedgerColumn<cf::BankHash>,
    last_root: Arc<RwLock<Slot>>,
    insert_shreds_lock: Arc<Mutex<()>>,
    pub new_shreds_signals: Vec<SyncSender<bool>>,
    pub completed_slots_senders: Vec<CompletedSlotsSender>,
    pub lowest_cleanup_slot: Arc<parking_lot::RwLock<Slot>>,
    no_compaction: bool,

    slots_stats: Arc<Mutex<SlotsStats>>,
    // EVM scope
    evm_blocks_cf: LedgerColumn<cf::EvmBlockHeader>,
    evm_transactions_cf: LedgerColumn<cf::EvmTransactionReceipts>,
    evm_blocks_by_hash_cf: LedgerColumn<cf::EvmHeaderIndexByHash>,
    evm_blocks_by_slot_cf: LedgerColumn<cf::EvmHeaderIndexBySlot>,
}

#[derive(Default)]
pub struct BlockstoreInsertionMetrics {
    pub num_shreds: usize,
    pub insert_lock_elapsed: u64,
    pub insert_shreds_elapsed: u64,
    pub shred_recovery_elapsed: u64,
    pub chaining_elapsed: u64,
    pub commit_working_sets_elapsed: u64,
    pub write_batch_elapsed: u64,
    pub total_elapsed: u64,
    pub num_inserted: u64,
    pub num_repair: u64,
    pub num_recovered: usize,
    num_recovered_blockstore_error: usize,
    pub num_recovered_inserted: usize,
    pub num_recovered_failed_sig: usize,
    pub num_recovered_failed_invalid: usize,
    pub num_recovered_exists: usize,
    pub index_meta_time: u64,
    num_data_shreds_exists: usize,
    num_data_shreds_invalid: usize,
    num_data_shreds_blockstore_error: usize,
    num_coding_shreds_exists: usize,
    num_coding_shreds_invalid: usize,
    num_coding_shreds_invalid_erasure_config: usize,
    num_coding_shreds_inserted: usize,
}

struct SlotsStats {
    last_cleanup_ts: Instant,
    stats: BTreeMap<Slot, SlotStats>,
}

impl Default for SlotsStats {
    fn default() -> Self {
        SlotsStats {
            last_cleanup_ts: Instant::now(),
            stats: BTreeMap::new(),
        }
    }
}

#[derive(Default)]
struct SlotStats {
    num_repaired: usize,
    num_recovered: usize,
}

impl Blockstore {
    pub fn destroy(ledger_path: &Path) -> Result<()> {
        // Database::destroy() fails if the path doesn't exist
        fs::create_dir_all(ledger_path)?;
        let blockstore_path = ledger_path.join(BLOCKSTORE_DIRECTORY);
        Database::destroy(&blockstore_path)
    }

    pub fn open_with_access_type(
        ledger_path: &Path,
        access_type: AccessType,
        recovery_mode: Option<BlockstoreRecoveryMode>,
        enforce_ulimit_nofile: bool,
    ) -> Result<Blockstore> {
        Self::do_open(
            ledger_path,
            access_type,
            recovery_mode,
            enforce_ulimit_nofile,
        )
    }

    fn do_open(
        ledger_path: &Path,
        access_type: AccessType,
        recovery_mode: Option<BlockstoreRecoveryMode>,
        enforce_ulimit_nofile: bool,
    ) -> Result<Blockstore> {
        fs::create_dir_all(ledger_path)?;
        let blockstore_path = ledger_path.join(BLOCKSTORE_DIRECTORY);

        adjust_ulimit_nofile(enforce_ulimit_nofile)?;

        // Open the database
        let mut measure = Measure::start("open");
        info!("Opening database at {:?}", blockstore_path);
        let db = Database::open(&blockstore_path, access_type, recovery_mode)?;

        // Create the metadata column family
        let meta_cf = db.column();

        // Create the dead slots column family
        let dead_slots_cf = db.column();
        let duplicate_slots_cf = db.column();
        let erasure_meta_cf = db.column();

        // Create the orphans column family. An "orphan" is defined as
        // the head of a detached chain of slots, i.e. a slot with no
        // known parent
        let orphans_cf = db.column();
        let index_cf = db.column();

        let data_shred_cf = db.column();
        let code_shred_cf = db.column();
        let transaction_status_cf = db.column();
        let address_signatures_cf = db.column();
        let transaction_memos_cf = db.column();
        let transaction_status_index_cf = db.column();
        let rewards_cf = db.column();
        let blocktime_cf = db.column();
        let perf_samples_cf = db.column();
        let block_height_cf = db.column();

        let evm_blocks_cf = db.column();
        let program_costs_cf = db.column();
        let bank_hash_cf = db.column();
        let evm_transactions_cf = db.column();
        let evm_blocks_by_hash_cf = db.column();
        let evm_blocks_by_slot_cf = db.column();

        let db = Arc::new(db);

        // Get max root or 0 if it doesn't exist
        let max_root = db
            .iter::<cf::Root>(IteratorMode::End)?
            .next()
            .map(|(slot, _)| slot)
            .unwrap_or(0);
        let last_root = Arc::new(RwLock::new(max_root));

        // Get active transaction-status index or 0
        let active_transaction_status_index = db
            .iter::<cf::TransactionStatusIndex>(IteratorMode::Start)?
            .next();
        let initialize_transaction_status_index = active_transaction_status_index.is_none();
        let active_transaction_status_index = active_transaction_status_index
            .and_then(|(_, data)| {
                let index0: TransactionStatusIndexMeta = deserialize(&data).unwrap();
                if index0.frozen {
                    Some(1)
                } else {
                    None
                }
            })
            .unwrap_or(0);

        measure.stop();
        info!("{:?} {}", blockstore_path, measure);
        let blockstore = Blockstore {
            ledger_path: ledger_path.to_path_buf(),
            db,
            meta_cf,
            dead_slots_cf,
            duplicate_slots_cf,
            erasure_meta_cf,
            orphans_cf,
            index_cf,
            data_shred_cf,
            code_shred_cf,
            transaction_status_cf,
            address_signatures_cf,
            transaction_memos_cf,
            transaction_status_index_cf,
            active_transaction_status_index: RwLock::new(active_transaction_status_index),
            rewards_cf,
            blocktime_cf,
            perf_samples_cf,
            block_height_cf,
            program_costs_cf,
            bank_hash_cf,
            new_shreds_signals: vec![],
            completed_slots_senders: vec![],
            insert_shreds_lock: Arc::new(Mutex::new(())),
            last_root,
            lowest_cleanup_slot: Arc::new(parking_lot::RwLock::new(0)),
            no_compaction: false,
            slots_stats: Arc::new(Mutex::new(SlotsStats::default())),
            evm_blocks_cf,
            evm_transactions_cf,
            evm_blocks_by_hash_cf,
            evm_blocks_by_slot_cf,
        };
        if initialize_transaction_status_index {
            blockstore.initialize_transaction_status_index()?;
        }
        Ok(blockstore)
    }

    /// Initializes the TransactionStatusIndex column family with two records, `0` and `1`,
    /// which are used as the primary index for entries in the TransactionStatus and
    /// AddressSignatures columns. At any given time, one primary index is active (ie. new records
    /// are stored under this index), the other is frozen.
    fn initialize_transaction_status_index(&self) -> Result<()> {
        self.transaction_status_index_cf
            .put(0, &TransactionStatusIndexMeta::default())?;
        self.transaction_status_index_cf
            .put(1, &TransactionStatusIndexMeta::default())?;
        // This dummy status improves compaction performance
        let default_status = TransactionStatusMeta::default().into();
        self.transaction_status_cf
            .put_protobuf(cf::TransactionStatus::as_index(2), &default_status)?;
        self.address_signatures_cf.put(
            cf::AddressSignatures::as_index(2),
            &AddressSignatureMeta::default(),
        )
    }


    pub fn insert_shreds(
        &self,
        shreds: Vec<Shred>,
        leader_schedule: Option<&LeaderScheduleCache>,
        is_trusted: bool,
    ) -> Result<(Vec<CompletedDataSetInfo>, Vec<usize>)> {
        let shreds_len = shreds.len();
        self.insert_shreds_handle_duplicate(
            shreds,
            vec![false; shreds_len],
            leader_schedule,
            is_trusted,
            None,    // retransmit-sender
            &|_| {}, // handle-duplicates
            &mut BlockstoreInsertionMetrics::default(),
        )
    }

    pub fn insert_shreds_handle_duplicate<F>(
        &self,
        shreds: Vec<Shred>,
        is_repaired: Vec<bool>,
        leader_schedule: Option<&LeaderScheduleCache>,
        is_trusted: bool,
        retransmit_sender: Option<&Sender<Vec<Shred>>>,
        handle_duplicate: &F,
        metrics: &mut BlockstoreInsertionMetrics,
    ) -> Result<(Vec<CompletedDataSetInfo>, Vec<usize>)>
    where
        F: Fn(Shred),
    {
        assert_eq!(shreds.len(), is_repaired.len());
        let mut total_start = Measure::start("Total elapsed");
        let mut start = Measure::start("Blockstore lock");
        let _lock = self.insert_shreds_lock.lock().unwrap();
        start.stop();
        metrics.insert_lock_elapsed += start.as_us();

        let db = &*self.db;
        let mut write_batch = db.batch()?;

        let mut just_inserted_shreds = HashMap::with_capacity(shreds.len());
        let mut erasure_metas = HashMap::new();
        let mut slot_meta_working_set = HashMap::new();
        let mut index_working_set = HashMap::new();

        metrics.num_shreds += shreds.len();
        let mut start = Measure::start("Shred insertion");
        let mut index_meta_time = 0;
        let mut newly_completed_data_sets: Vec<CompletedDataSetInfo> = vec![];
        let mut inserted_indices = Vec::new();
        for (i, (shred, is_repaired)) in shreds.into_iter().zip(is_repaired).enumerate() {
            match shred.shred_type() {
                ShredType::Data => {
                    let shred_source = if is_repaired {
                        ShredSource::Repaired
                    } else {
                        ShredSource::Turbine
                    };
                    match self.check_insert_data_shred(
                        shred,
                        &mut erasure_metas,
                        &mut index_working_set,
                        &mut slot_meta_working_set,
                        &mut write_batch,
                        &mut just_inserted_shreds,
                        &mut index_meta_time,
                        is_trusted,
                        handle_duplicate,
                        leader_schedule,
                        shred_source,
                    ) {
                        Err(InsertDataShredError::Exists) => metrics.num_data_shreds_exists += 1,
                        Err(InsertDataShredError::InvalidShred) => {
                            metrics.num_data_shreds_invalid += 1
                        }
                        Err(InsertDataShredError::BlockstoreError(err)) => {
                            metrics.num_data_shreds_blockstore_error += 1;
                            error!("blockstore error: {}", err);
                        }
                        Ok(completed_data_sets) => {
                            newly_completed_data_sets.extend(completed_data_sets);
                            inserted_indices.push(i);
                            metrics.num_inserted += 1;
                        }
                    };
                }
                ShredType::Code => {
                    self.check_insert_coding_shred(
                        shred,
                        &mut erasure_metas,
                        &mut index_working_set,
                        &mut write_batch,
                        &mut just_inserted_shreds,
                        &mut index_meta_time,
                        handle_duplicate,
                        is_trusted,
                        is_repaired,
                        metrics,
                    );
                }
            };
        }
        start.stop();

        metrics.insert_shreds_elapsed += start.as_us();
        let mut start = Measure::start("Shred recovery");
        if let Some(leader_schedule_cache) = leader_schedule {
            let recovered_data_shreds = Self::try_shred_recovery(
                db,
                &erasure_metas,
                &mut index_working_set,
                &just_inserted_shreds,
            );

            metrics.num_recovered += recovered_data_shreds.len();
            let recovered_data_shreds: Vec<_> = recovered_data_shreds
                .into_iter()
                .filter_map(|shred| {
                    let leader =
                        leader_schedule_cache.slot_leader_at(shred.slot(), /*bank=*/ None)?;
                    if !shred.verify(&leader) {
                        metrics.num_recovered_failed_sig += 1;
                        return None;
                    }
                    match self.check_insert_data_shred(
                        shred.clone(),
                        &mut erasure_metas,
                        &mut index_working_set,
                        &mut slot_meta_working_set,
                        &mut write_batch,
                        &mut just_inserted_shreds,
                        &mut index_meta_time,
                        is_trusted,
                        &handle_duplicate,
                        leader_schedule,
                        ShredSource::Recovered,
                    ) {
                        Err(InsertDataShredError::Exists) => {
                            metrics.num_recovered_exists += 1;
                            None
                        }
                        Err(InsertDataShredError::InvalidShred) => {
                            metrics.num_recovered_failed_invalid += 1;
                            None
                        }
                        Err(InsertDataShredError::BlockstoreError(err)) => {
                            metrics.num_recovered_blockstore_error += 1;
                            error!("blockstore error: {}", err);
                            None
                        }
                        Ok(completed_data_sets) => {
                            newly_completed_data_sets.extend(completed_data_sets);
                            metrics.num_recovered_inserted += 1;
                            Some(shred)
                        }
                    }
                })
                // Always collect recovered-shreds so that above insert code is
                // executed even if retransmit-sender is None.
                .collect();
            if !recovered_data_shreds.is_empty() {
                if let Some(retransmit_sender) = retransmit_sender {
                    let _ = retransmit_sender.send(recovered_data_shreds);
                }
            }
        }
        start.stop();
        metrics.shred_recovery_elapsed += start.as_us();

        let mut start = Measure::start("Shred recovery");
        // Handle chaining for the members of the slot_meta_working_set that were inserted into,
        // drop the others
        handle_chaining(&self.db, &mut write_batch, &mut slot_meta_working_set)?;
        start.stop();
        metrics.chaining_elapsed += start.as_us();

        let mut start = Measure::start("Commit Working Sets");
        let (should_signal, newly_completed_slots) = commit_slot_meta_working_set(
            &slot_meta_working_set,
            &self.completed_slots_senders,
            &mut write_batch,
        )?;

        for (erasure_set, erasure_meta) in erasure_metas {
            write_batch.put::<cf::ErasureMeta>(erasure_set.store_key(), &erasure_meta)?;
        }

        for (&slot, index_working_set_entry) in index_working_set.iter() {
            if index_working_set_entry.did_insert_occur {
                write_batch.put::<cf::Index>(slot, &index_working_set_entry.index)?;
            }
        }
        start.stop();
        metrics.commit_working_sets_elapsed += start.as_us();

        let mut start = Measure::start("Write Batch");
        self.db.write(write_batch)?;
        start.stop();
        metrics.write_batch_elapsed += start.as_us();

        send_signals(
            &self.new_shreds_signals,
            &self.completed_slots_senders,
            should_signal,
            newly_completed_slots,
        );

        total_start.stop();

        metrics.total_elapsed += total_start.as_us();
        metrics.index_meta_time += index_meta_time;

        Ok((newly_completed_data_sets, inserted_indices))
    }

    pub fn set_roots<'a>(&self, rooted_slots: impl Iterator<Item = &'a Slot>) -> Result<()> {
        let mut write_batch = self.db.batch()?;
        let mut max_new_rooted_slot = 0;
        for slot in rooted_slots {
            max_new_rooted_slot = std::cmp::max(max_new_rooted_slot, *slot);
            write_batch.put::<cf::Root>(*slot, &true)?;
        }

        self.db.write(write_batch)?;

        let mut last_root = self.last_root.write().unwrap();
        if *last_root == std::u64::MAX {
            *last_root = 0;
        }
        *last_root = cmp::max(max_new_rooted_slot, *last_root);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::map_entry)]
    fn check_insert_data_shred<F>(
        &self,
        shred: Shred,
        erasure_metas: &mut HashMap<ErasureSetId, ErasureMeta>,
        index_working_set: &mut HashMap<u64, IndexMetaWorkingSetEntry>,
        slot_meta_working_set: &mut HashMap<u64, SlotMetaWorkingSetEntry>,
        write_batch: &mut WriteBatch,
        just_inserted_shreds: &mut HashMap<ShredId, Shred>,
        index_meta_time: &mut u64,
        is_trusted: bool,
        handle_duplicate: &F,
        leader_schedule: Option<&LeaderScheduleCache>,
        shred_source: ShredSource,
    ) -> std::result::Result<Vec<CompletedDataSetInfo>, InsertDataShredError>
    where
        F: Fn(Shred),
    {
        let slot = shred.slot();
        let shred_index = u64::from(shred.index());

        let index_meta_working_set_entry =
            get_index_meta_entry(&self.db, slot, index_working_set, index_meta_time);

        let index_meta = &mut index_meta_working_set_entry.index;
        let slot_meta_entry = get_slot_meta_entry(
            &self.db,
            slot_meta_working_set,
            slot,
            shred
                .parent()
                .map_err(|_| InsertDataShredError::InvalidShred)?,
        );

        let slot_meta = &mut slot_meta_entry.new_slot_meta.borrow_mut();

        if !is_trusted {
            if Self::is_data_shred_present(&shred, slot_meta, index_meta.data()) {
                handle_duplicate(shred);
                return Err(InsertDataShredError::Exists);
            }

            if shred.last_in_slot() && shred_index < slot_meta.received && !slot_meta.is_full() {
                // We got a last shred < slot_meta.received, which signals there's an alternative,
                // shorter version of the slot. Because also `!slot_meta.is_full()`, then this
                // means, for the current version of the slot, we might never get all the
                // shreds < the current last index, never replay this slot, and make no
                // progress (for instance if a leader sends an additional detached "last index"
                // shred with a very high index, but none of the intermediate shreds). Ideally, we would
                // just purge all shreds > the new last index slot, but because replay may have already
                // replayed entries past the newly detected "last" shred, then mark the slot as dead
                // and wait for replay to dump and repair the correct version.
                warn!("Received *last* shred index {} less than previous shred index {}, and slot {} is not full, marking slot dead", shred_index, slot_meta.received, slot);
                write_batch.put::<cf::DeadSlots>(slot, &true).unwrap();
            }

            if !self.should_insert_data_shred(
                &shred,
                slot_meta,
                just_inserted_shreds,
                &self.last_root,
                leader_schedule,
                shred_source.clone(),
            ) {
                return Err(InsertDataShredError::InvalidShred);
            }
        }

        let erasure_set = shred.erasure_set();
        let newly_completed_data_sets = self.insert_data_shred(
            slot_meta,
            index_meta.data_mut(),
            &shred,
            write_batch,
            shred_source,
        )?;
        just_inserted_shreds.insert(shred.id(), shred);
        index_meta_working_set_entry.did_insert_occur = true;
        slot_meta_entry.did_insert_occur = true;
        if let HashMapEntry::Vacant(entry) = erasure_metas.entry(erasure_set) {
            if let Some(meta) = self.erasure_meta(erasure_set).unwrap() {
                entry.insert(meta);
            }
        }
        Ok(newly_completed_data_sets)
    }

    #[allow(clippy::too_many_arguments)]
    fn check_insert_coding_shred<F>(
        &self,
        shred: Shred,
        erasure_metas: &mut HashMap<ErasureSetId, ErasureMeta>,
        index_working_set: &mut HashMap<u64, IndexMetaWorkingSetEntry>,
        write_batch: &mut WriteBatch,
        just_received_shreds: &mut HashMap<ShredId, Shred>,
        index_meta_time: &mut u64,
        handle_duplicate: &F,
        is_trusted: bool,
        is_repaired: bool,
        metrics: &mut BlockstoreInsertionMetrics,
    ) -> bool
    where
        F: Fn(Shred),
    {
        let slot = shred.slot();
        let shred_index = u64::from(shred.index());

        let index_meta_working_set_entry =
            get_index_meta_entry(&self.db, slot, index_working_set, index_meta_time);

        let index_meta = &mut index_meta_working_set_entry.index;

        // This gives the index of first coding shred in this FEC block
        // So, all coding shreds in a given FEC block will have the same set index

        if !is_trusted {
            if index_meta.coding().contains(shred_index) {
                metrics.num_coding_shreds_exists += 1;
                handle_duplicate(shred);
                return false;
            }

            if !Blockstore::should_insert_coding_shred(&shred, &self.last_root) {
                metrics.num_coding_shreds_invalid += 1;
                return false;
            }
        }

        let erasure_set = shred.erasure_set();
        let erasure_meta = erasure_metas.entry(erasure_set).or_insert_with(|| {
            self.erasure_meta(erasure_set)
                .expect("Expect database get to succeed")
                .unwrap_or_else(|| ErasureMeta::from_coding_shred(&shred).unwrap())
        });

        // TODO: handle_duplicate is not invoked and so duplicate shreds are
        // not gossiped to the rest of cluster.
        if !erasure_meta.check_coding_shred(&shred) {
            metrics.num_coding_shreds_invalid_erasure_config += 1;
            let conflicting_shred = self.find_conflicting_coding_shred(
                &shred,
                slot,
                erasure_meta,
                just_received_shreds,
            );
            if let Some(conflicting_shred) = conflicting_shred {
                if self
                    .store_duplicate_if_not_existing(slot, conflicting_shred, shred.payload.clone())
                    .is_err()
                {
                    warn!("bad duplicate store..");
                }
            } else {
                datapoint_info!("bad-conflict-shred", ("slot", slot, i64));
            }

            // ToDo: This is a potential slashing condition
            warn!("Received multiple erasure configs for the same erasure set!!!");
            warn!(
                "Slot: {}, shred index: {}, erasure_set: {:?}, is_duplicate: {}, stored config: {:#?}, new config: {:#?}",
                slot, shred.index(), erasure_set, self.has_duplicate_shreds_in_slot(slot), erasure_meta.config(), shred.coding_header,
            );

            return false;
        }

        if is_repaired {
            let mut slots_stats = self.slots_stats.lock().unwrap();
            let mut e = slots_stats.stats.entry(slot).or_default();
            e.num_repaired += 1;
        }

        // insert coding shred into rocks
        let result = self
            .insert_coding_shred(index_meta, &shred, write_batch)
            .is_ok();

        if result {
            index_meta_working_set_entry.did_insert_occur = true;
            metrics.num_inserted += 1;
        }

        if let HashMapEntry::Vacant(entry) = just_received_shreds.entry(shred.id()) {
            metrics.num_coding_shreds_inserted += 1;
            entry.insert(shred);
        }

        result
    }

    fn try_shred_recovery(
        db: &Database,
        erasure_metas: &HashMap<ErasureSetId, ErasureMeta>,
        index_working_set: &mut HashMap<u64, IndexMetaWorkingSetEntry>,
        prev_inserted_shreds: &HashMap<ShredId, Shred>,
    ) -> Vec<Shred> {
        let data_cf = db.column::<cf::ShredData>();
        let code_cf = db.column::<cf::ShredCode>();
        let mut recovered_data_shreds = vec![];
        // Recovery rules:
        // 1. Only try recovery around indexes for which new data or coding shreds are received
        // 2. For new data shreds, check if an erasure set exists. If not, don't try recovery
        // 3. Before trying recovery, check if enough number of shreds have been received
        // 3a. Enough number of shreds = (#data + #coding shreds) > erasure.num_data
        for (erasure_set, erasure_meta) in erasure_metas.iter() {
            let slot = erasure_set.slot();
            let index_meta_entry = index_working_set.get_mut(&slot).expect("Index");
            let index = &mut index_meta_entry.index;
            match erasure_meta.status(index) {
                ErasureMetaStatus::CanRecover => {
                    Self::recover_shreds(
                        index,
                        erasure_meta,
                        prev_inserted_shreds,
                        &mut recovered_data_shreds,
                        &data_cf,
                        &code_cf,
                    );
                }
                ErasureMetaStatus::DataFull => {
                    Self::submit_metrics(slot, erasure_meta, false, "complete".into(), 0);
                }
                ErasureMetaStatus::StillNeed(needed) => {
                    Self::submit_metrics(
                        slot,
                        erasure_meta,
                        false,
                        format!("still need: {}", needed),
                        0,
                    );
                }
            };
        }
        recovered_data_shreds
    }

}

pub enum EvmStateJson<'a> {
    OpenEthereum(&'a Path),
    Geth(&'a Path),
    None
}

#[cfg(unix)]
fn adjust_ulimit_nofile(enforce_ulimit_nofile: bool) -> Result<()> {
    // Rocks DB likes to have many open files.  The default open file descriptor limit is
    // usually not enough
    let desired_nofile = 500000;

    fn get_nofile() -> libc::rlimit {
        let mut nofile = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut nofile) } != 0 {
            warn!("getrlimit(RLIMIT_NOFILE) failed");
        }
        nofile
    }

    let mut nofile = get_nofile();
    if nofile.rlim_cur < desired_nofile {
        nofile.rlim_cur = desired_nofile;
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &nofile) } != 0 {
            error!(
                "Unable to increase the maximum open file descriptor limit to {}",
                desired_nofile
            );

            if cfg!(target_os = "macos") {
                error!(
                    "On mac OS you may need to run |sudo launchctl limit maxfiles {} {}| first",
                    desired_nofile, desired_nofile,
                );
            }
            if enforce_ulimit_nofile {
                return Err(BlockstoreError::UnableToSetOpenFileDescriptorLimit);
            }
        }

        nofile = get_nofile();
    }
    info!("Maximum open file descriptors: {}", nofile.rlim_cur);
    Ok(())
}

// Chaining based on latest discussion here: https://github.com/solana-labs/solana/pull/2253
fn handle_chaining(
    db: &Database,
    write_batch: &mut WriteBatch,
    working_set: &mut HashMap<u64, SlotMetaWorkingSetEntry>,
) -> Result<()> {
    // Handle chaining for all the SlotMetas that were inserted into
    working_set.retain(|_, entry| entry.did_insert_occur);
    let mut new_chained_slots = HashMap::new();
    let working_set_slots: Vec<_> = working_set.keys().collect();
    for slot in working_set_slots {
        handle_chaining_for_slot(db, write_batch, working_set, &mut new_chained_slots, *slot)?;
    }

    // Write all the newly changed slots in new_chained_slots to the write_batch
    for (slot, meta) in new_chained_slots.iter() {
        let meta: &SlotMeta = &RefCell::borrow(meta);
        write_batch.put::<cf::SlotMeta>(*slot, meta)?;
    }
    Ok(())
}