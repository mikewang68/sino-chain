use {
    crate::{
        ancestor_iterator::AncestorIterator,
        blockstore_db::{
        columns as cf, AccessType, BlockstoreRecoveryMode, Column, Database,
        EvmTransactionReceiptsIndex, IteratorDirection, IteratorMode, LedgerColumn, Result,
        WriteBatch,
        },
        blockstore_meta::*,
        leader_schedule_cache::LeaderScheduleCache,
        // next_slots_iterator::NextSlotsIterator,
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
        ConfirmedBlock, ConfirmedTransaction, 
        ConfirmedTransactionStatusWithSignature, 
        Rewards,
        TransactionStatusMeta, 
        TransactionWithMetadata,
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
type CompletedRanges = Vec<(u32, u32)>;

// An upper bound on maximum number of data shreds we can handle in a slot
// 32K shreds would allow ~320K peak TPS
// (32K shreds per slot * 4 TX per shred * 2.5 slots per sec)
pub const MAX_DATA_SHREDS_PER_SLOT: usize = 32_768;

thread_local!(static PAR_THREAD_POOL: RefCell<ThreadPool> = RefCell::new(rayon::ThreadPoolBuilder::new()
                    .num_threads(get_thread_count())
                    .thread_name(|ix| format!("blockstore_{}", ix))
                    .build()
                    .unwrap()));

#[derive(PartialEq, Debug, Clone)]
enum ShredSource {
    Turbine,
    Repaired,
    Recovered,
}

#[derive(Default)]
pub struct SignatureInfosForAddress {
    pub infos: Vec<ConfirmedTransactionStatusWithSignature>,
    pub found_before: bool,
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

impl SlotMetaWorkingSetEntry {
    fn new(new_slot_meta: Rc<RefCell<SlotMeta>>, old_slot_meta: Option<SlotMeta>) -> Self {
        Self {
            new_slot_meta,
            old_slot_meta,
            did_insert_occur: false,
        }
    }
}

pub struct IndexMetaWorkingSetEntry {
    index: Index,
    // true only if at least one shred for this Index was inserted since the time this
    // struct was created
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

    // 将evm账户存入数据库，并创建evm state包含第一个slot和块哈希
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

    // 将genesis config输出到ledger_path下的genesis.bin文件
    genesis_config.write(ledger_path)?;

    // Fill slot 0 with ticks that link back to the genesis_config to bootstrap the ledger.
    let blockstore = Blockstore::open_with_access_type(ledger_path, access_type, None, false)?;
    let ticks_per_slot = genesis_config.ticks_per_slot;
    let hashes_per_tick = genesis_config.poh_config.hashes_per_tick.unwrap_or(0);
    // 将 slot 0 填充
    let entries = create_ticks(ticks_per_slot, hashes_per_tick, genesis_config.hash());
    let last_hash = entries.last().unwrap().hash;
    // 由块0的哈希计算version
    let version = sdk::shred_version::version_from_hash(&last_hash);
    // 将 slot 0 切片
    let shredder = Shredder::new(0, 0, 0, version).unwrap();
    let shreds: Vec<Shred> = shredder
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
    
    // ledger_path/genesis.tar.bz2
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
    // tar jcfhS ~/velas-chain-old/config/ledger/genesis.tar.bz2 -C ~/velas-chain-old/config/ledger genesis.bin rocksdb evm-state-genesis
    // 将账本路径下的genesis.bin rocksdb evm-state-genesis压缩到genesis.tar.bz2
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

fn get_last_hash<'a>(iterator: impl Iterator<Item = &'a Entry> + 'a) -> Option<Hash> {
    iterator.last().map(|entry| entry.hash)
}

impl Blockstore {
    pub fn is_root(&self, slot: Slot) -> bool {
        matches!(self.db.get::<cf::Root>(slot), Ok(Some(true)))
    }

    pub fn meta(&self, slot: Slot) -> Result<Option<SlotMeta>> {
        self.meta_cf.get(slot)
    }

    /// Opens a Ledger in directory, provides "infinite" window of shreds
    pub fn open(ledger_path: &Path) -> Result<Blockstore> {
        Self::do_open(ledger_path, AccessType::PrimaryOnly, None, true)
    }

    pub fn destroy(ledger_path: &Path) -> Result<()> {
        // Database::destroy() fails if the path doesn't exist
        fs::create_dir_all(ledger_path)?;
        let blockstore_path = ledger_path.join(BLOCKSTORE_DIRECTORY);
        Database::destroy(&blockstore_path)
    }

    pub fn write_transaction_status(
        &self,
        slot: Slot,
        signature: Signature,
        writable_keys: Vec<&Pubkey>,
        readonly_keys: Vec<&Pubkey>,
        status: TransactionStatusMeta,
    ) -> Result<()> {
        let status = status.into();
        // This write lock prevents interleaving issues with the transaction_status_index_cf by gating
        // writes to that column
        let w_active_transaction_status_index =
            self.active_transaction_status_index.write().unwrap();
        let primary_index =
            self.get_primary_index_to_write(slot, &w_active_transaction_status_index)?;
        self.transaction_status_cf
            .put_protobuf((primary_index, signature, slot), &status)?;
        for address in writable_keys {
            self.address_signatures_cf.put(
                (primary_index, *address, slot, signature),
                &AddressSignatureMeta { writeable: true },
            )?;
        }
        for address in readonly_keys {
            self.address_signatures_cf.put(
                (primary_index, *address, slot, signature),
                &AddressSignatureMeta { writeable: false },
            )?;
        }
        Ok(())
    }

    pub fn get_recent_perf_samples(&self, num: usize) -> Result<Vec<(Slot, PerfSample)>> {
        Ok(self
            .db
            .iter::<cf::PerfSamples>(IteratorMode::End)?
            .take(num)
            .map(|(slot, data)| {
                let perf_sample = deserialize(&data).unwrap();
                (slot, perf_sample)
            })
            .collect())
    }

    ///
    /// Return reverse iterator over evm blocks.
    /// There can be more than one block with same block number and different slot numbers.
    ///
    /// TODO: naming (check evm_blocks_iterator: same naming, different semantic)
    pub fn evm_blocks_reverse_iterator(
        &self,
    ) -> Result<impl Iterator<Item = ((evm::BlockNum, Option<Slot>), evm::BlockHeader)> + '_> {
        Ok(self
            .evm_blocks_cf
            .iter(IteratorMode::End)?
            .map(move |(block_num, block_header)| {
                (
                    block_num,
                    self.evm_blocks_cf
                        .deserialize_protobuf_or_bincode::<evm::BlockHeader>(&block_header)
                        .unwrap_or_else(|e| {
                            panic!(
                            "Could not deserialize BlockHeader for block_num {} slot {:?}: {:?}",
                            block_num.0, block_num.1, e
                        )
                        })
                        .try_into()
                        .expect("Convertation should always pass"),
                )
            }))
    }

    pub fn get_last_available_evm_block(&self) -> Result<Option<evm::BlockNum>> {
        Ok(self
            .evm_blocks_cf
            .iter(IteratorMode::End)?
            .map(|((block, _slot), _)| block)
            .next())
    }

    // DEPRECATED
    pub fn get_confirmed_signatures_for_address(
        &self,
        pubkey: Pubkey,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<Vec<Signature>> {
        datapoint_info!(
            "blockstore-rpc-api",
            (
                "method",
                "get_confirmed_signatures_for_address",
                String
            )
        );
        self.find_address_signatures(pubkey, start_slot, end_slot)
            .map(|signatures| signatures.iter().map(|(_, signature)| *signature).collect())
    }

    // Returns all rooted signatures for an address, ordered by slot that the transaction was
    // processed in. Within each slot the transactions will be ordered by signature, and NOT by
    // the order in which the transactions exist in the block
    //
    // DEPRECATED
    fn find_address_signatures(
        &self,
        pubkey: Pubkey,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<Vec<(Slot, Signature)>> {
        let (lock, lowest_available_slot) = self.ensure_lowest_cleanup_slot();

        let mut signatures: Vec<(Slot, Signature)> = vec![];
        for transaction_status_cf_primary_index in 0..=1 {
            let index_iterator = self.address_signatures_cf.iter(IteratorMode::From(
                (
                    transaction_status_cf_primary_index,
                    pubkey,
                    start_slot.max(lowest_available_slot),
                    Signature::default(),
                ),
                IteratorDirection::Forward,
            ))?;
            for ((i, address, slot, signature), _) in index_iterator {
                if i != transaction_status_cf_primary_index || slot > end_slot || address != pubkey
                {
                    break;
                }
                if self.is_root(slot) {
                    signatures.push((slot, signature));
                }
            }
        }
        drop(lock);
        signatures.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap().then(a.1.cmp(&b.1)));
        Ok(signatures)
    }

    fn ensure_lowest_cleanup_slot(&self) -> (parking_lot::RwLockReadGuard<Slot>, Slot) {
        // Ensures consistent result by using lowest_cleanup_slot as the lower bound
        // for reading columns that do not employ strong read consistency with slot-based
        // delete_range
        let lowest_cleanup_slot = self.lowest_cleanup_slot.read_recursive();
        let lowest_available_slot = (*lowest_cleanup_slot)
            .checked_add(1)
            .expect("overflow from trusted value");

        // Make caller hold this lock properly; otherwise LedgerCleanupService can purge/compact
        // needed slots here at any given moment.
        // Blockstore callers, like rpc, can process concurrent read queries
        (lowest_cleanup_slot, lowest_available_slot)
    }

    /// The first complete block that is available in the Blockstore ledger
    pub fn get_first_available_block(&self) -> Result<Slot> {
        let mut root_iterator = self.rooted_slot_iterator(self.lowest_slot())?;
        // The block at root-index 0 cannot be complete, because it is missing its parent
        // blockhash. A parent blockhash must be calculated from the entries of the previous block.
        // Therefore, the first available complete block is that at root-index 1.
        Ok(root_iterator.nth(1).unwrap_or_default())
    }

    pub fn rooted_slot_iterator(&self, slot: Slot) -> Result<impl Iterator<Item = u64> + '_> {
        let slot_iterator = self
            .db
            .iter::<cf::Root>(IteratorMode::From(slot, IteratorDirection::Forward))?;
        Ok(slot_iterator.map(move |(rooted_slot, _)| rooted_slot))
    }

    // find the first available slot in blockstore that has some data in it
    pub fn lowest_slot(&self) -> Slot {
        for (slot, meta) in self
            .slot_meta_iterator(0)
            .expect("unable to iterate over meta")
        {
            if slot > 0 && meta.received > 0 {
                return slot;
            }
        }
        // This means blockstore is empty, should never get here aside from right at boot.
        self.last_root()
    }

    /// Returns true if a slot is between the rooted slot bounds of the ledger, but has not itself
    /// been rooted. This is either because the slot was skipped, or due to a gap in ledger data,
    /// as when booting from a newer snapshot.
    pub fn is_skipped(&self, slot: Slot) -> bool {
        let lowest_root = self
            .rooted_slot_iterator(0)
            .ok()
            .and_then(|mut iter| iter.next())
            .unwrap_or_default();
        match self.db.get::<cf::Root>(slot).ok().flatten() {
            Some(_) => false,
            None => slot < self.max_root() && slot > lowest_root,
        }
    }

    // Get max root or 0 if it doesn't exist
    pub fn max_root(&self) -> Slot {
        self.db
            .iter::<cf::Root>(IteratorMode::End)
            .expect("Couldn't get rooted iterator for max_root()")
            .next()
            .map(|(slot, _)| slot)
            .unwrap_or(0)
    }

    pub fn read_evm_block_id_by_hash(&self, hash: H256) -> Result<Option<evm_state::BlockNum>> {
        let result = self
            .evm_blocks_by_hash_cf
            .get_protobuf_or_bincode::<evm_state::BlockNum>((0, hash))?;
        if result.is_none() {
            Ok(self
                .evm_blocks_by_hash_cf
                .get_protobuf_or_bincode::<evm_state::BlockNum>((1, hash))?)
        } else {
            Ok(result)
        }
    }

    /// Returns EVM block, and flag if that block was rooted (confirmed)
    pub fn get_evm_block(&self, block_number: evm::BlockNum) -> Result<(evm::Block, bool)> {
        datapoint_info!(
            "blockstore-rpc-api",
            ("method", "get_evm_block", String)
        );
        // TODO: Integrate with cleanup service
        // let lowest_cleanup_slot = self.lowest_cleanup_slot.read().unwrap();
        // // lowest_cleanup_slot is the last slot that was not cleaned up by
        // // LedgerCleanupService
        // if *lowest_cleanup_slot > 0 && *lowest_cleanup_slot >= slot {
        //     return Err(BlockstoreError::SlotCleanedUp);
        // }

        let mut block_headers = self.read_evm_block_headers(block_number)?;

        if block_headers.is_empty() {
            return Err(BlockstoreError::SlotCleanedUp);
        };
        // we need to find one block from array:
        // If confirmed block is present, then return it.
        // Otherways return first block

        let confirmed_block = block_headers
            .iter()
            .enumerate()
            .find(|(_idx, b)| self.is_root(b.native_chain_slot))
            .map(|(idx, _b)| idx);

        let block_header = block_headers.remove(confirmed_block.unwrap_or_default());

        let mut txs = Vec::new();
        for hash in &block_header.transactions {
            let tx = self.read_evm_transaction((
                *hash,
                block_header.block_number,
                Some(block_header.native_chain_slot),
            ))?;
            if let Some(tx) = tx {
                txs.push((*hash, tx))
            } else {
                warn!(
                    "Requesting block {}, evm transaction = {}, was cleaned up, while block still exist,",
                    block_number, hash
                );
                return Err(BlockstoreError::SlotCleanedUp);
            };
        }

        let confirmed = self.is_root(block_header.native_chain_slot);
        Ok((
            evm::Block {
                header: block_header,
                transactions: txs,
            },
            confirmed,
        ))
    }

    /// Returns iterator over evm blocks.
    /// If more than one evm block have been found on same block_num, this function return multiple items.
    ///
    pub fn read_evm_block_headers(
        &self,
        block_index: evm::BlockNum,
    ) -> Result<Vec<evm::BlockHeader>> {
        Ok(self
            .evm_blocks_iterator(block_index)?
            .take_while(|((block_num, _slot), _block)| *block_num == block_index)
            .map(|((_block_num, _slot), block)| block)
            .collect())
    }

    /// Returns a complete transaction
    pub fn get_complete_transaction(
        &self,
        signature: Signature,
        highest_confirmed_slot: Slot,
    ) -> Result<Option<ConfirmedTransaction>> {
        datapoint_info!(
            "blockstore-rpc-api",
            ("method", "get_complete_transaction", String)
        );
        let last_root = self.last_root();
        let confirmed_unrooted_slots: Vec<_> =
            AncestorIterator::new_inclusive(highest_confirmed_slot, self)
                .take_while(|&slot| slot > last_root)
                .collect();
        self.get_transaction_with_status(signature, &confirmed_unrooted_slots)
    }

    /// Returns a transaction status
    pub fn get_rooted_transaction_status(
        &self,
        signature: Signature,
    ) -> Result<Option<(Slot, TransactionStatusMeta)>> {
        datapoint_info!(
            "blockstore-rpc-api",
            (
                "method",
                "get_rooted_transaction_status",
                String
            )
        );
        self.get_transaction_status(signature, &[])
    }

    pub fn get_confirmed_signatures_for_address2(
        &self,
        address: Pubkey,
        highest_slot: Slot, // highest_confirmed_root or highest_confirmed_slot
        before: Option<Signature>,
        until: Option<Signature>,
        limit: usize,
    ) -> Result<SignatureInfosForAddress> {
        datapoint_info!(
            "blockstore-rpc-api",
            (
                "method",
                "get_confirmed_signatures_for_address2",
                String
            )
        );
        let last_root = self.last_root();
        let confirmed_unrooted_slots: Vec<_> = AncestorIterator::new_inclusive(highest_slot, self)
            .take_while(|&slot| slot > last_root)
            .collect();

        // Figure the `slot` to start listing signatures at, based on the ledger location of the
        // `before` signature if present.  Also generate a HashSet of signatures that should
        // be excluded from the results.
        let mut get_before_slot_timer = Measure::start("get_before_slot_timer");
        let (slot, mut before_excluded_signatures) = match before {
            None => (highest_slot, None),
            Some(before) => {
                let transaction_status =
                    self.get_transaction_status(before, &confirmed_unrooted_slots)?;
                match transaction_status {
                    None => return Ok(SignatureInfosForAddress::default()),
                    Some((slot, _)) => {
                        let mut slot_signatures = self.get_sorted_block_signatures(slot)?;
                        if let Some(pos) = slot_signatures.iter().position(|&x| x == before) {
                            slot_signatures.truncate(pos + 1);
                        }

                        (
                            slot,
                            Some(slot_signatures.into_iter().collect::<HashSet<_>>()),
                        )
                    }
                }
            }
        };
        get_before_slot_timer.stop();

        // Generate a HashSet of signatures that should be excluded from the results based on
        // `until` signature
        let mut get_until_slot_timer = Measure::start("get_until_slot_timer");
        let (lowest_slot, until_excluded_signatures) = match until {
            None => (0, HashSet::new()),
            Some(until) => {
                let transaction_status =
                    self.get_transaction_status(until, &confirmed_unrooted_slots)?;
                match transaction_status {
                    None => (0, HashSet::new()),
                    Some((slot, _)) => {
                        let mut slot_signatures = self.get_sorted_block_signatures(slot)?;
                        if let Some(pos) = slot_signatures.iter().position(|&x| x == until) {
                            slot_signatures = slot_signatures.split_off(pos);
                        }

                        (slot, slot_signatures.into_iter().collect::<HashSet<_>>())
                    }
                }
            }
        };
        get_until_slot_timer.stop();

        // Fetch the list of signatures that affect the given address
        let first_available_block = self.get_first_available_block()?;
        let mut address_signatures = vec![];

        // Get signatures in `slot`
        let mut get_initial_slot_timer = Measure::start("get_initial_slot_timer");
        let mut signatures = self.find_address_signatures_for_slot(address, slot)?;
        signatures.reverse();
        if let Some(excluded_signatures) = before_excluded_signatures.take() {
            address_signatures.extend(
                signatures
                    .into_iter()
                    .filter(|(_, signature)| !excluded_signatures.contains(signature)),
            )
        } else {
            address_signatures.append(&mut signatures);
        }
        get_initial_slot_timer.stop();

        // Check the active_transaction_status_index to see if it contains slot. If so, start with
        // that index, as it will contain higher slots
        let starting_primary_index = *self.active_transaction_status_index.read().unwrap();
        let next_primary_index = u64::from(starting_primary_index == 0);
        let next_max_slot = self
            .transaction_status_index_cf
            .get(next_primary_index)?
            .unwrap()
            .max_slot;

        let mut starting_primary_index_iter_timer = Measure::start("starting_primary_index_iter");
        if slot > next_max_slot {
            let mut starting_iterator = self.address_signatures_cf.iter(IteratorMode::From(
                (starting_primary_index, address, slot, Signature::default()),
                IteratorDirection::Reverse,
            ))?;

            // Iterate through starting_iterator until limit is reached
            while address_signatures.len() < limit {
                if let Some(((i, key_address, slot, signature), _)) = starting_iterator.next() {
                    if slot == next_max_slot || slot < lowest_slot {
                        break;
                    }
                    if i == starting_primary_index
                        && key_address == address
                        && slot >= first_available_block
                    {
                        if self.is_root(slot) || confirmed_unrooted_slots.contains(&slot) {
                            address_signatures.push((slot, signature));
                        }
                        continue;
                    }
                }
                break;
            }

            // Handle slots that cross primary indexes
            if next_max_slot >= lowest_slot {
                let mut signatures =
                    self.find_address_signatures_for_slot(address, next_max_slot)?;
                signatures.reverse();
                address_signatures.append(&mut signatures);
            }
        }
        starting_primary_index_iter_timer.stop();

        // Iterate through next_iterator until limit is reached
        let mut next_primary_index_iter_timer = Measure::start("next_primary_index_iter_timer");
        let mut next_iterator = self.address_signatures_cf.iter(IteratorMode::From(
            (next_primary_index, address, slot, Signature::default()),
            IteratorDirection::Reverse,
        ))?;
        while address_signatures.len() < limit {
            if let Some(((i, key_address, slot, signature), _)) = next_iterator.next() {
                // Skip next_max_slot, which is already included
                if slot == next_max_slot {
                    continue;
                }
                if slot < lowest_slot {
                    break;
                }
                if i == next_primary_index
                    && key_address == address
                    && slot >= first_available_block
                {
                    if self.is_root(slot) || confirmed_unrooted_slots.contains(&slot) {
                        address_signatures.push((slot, signature));
                    }
                    continue;
                }
            }
            break;
        }
        next_primary_index_iter_timer.stop();
        let mut address_signatures: Vec<(Slot, Signature)> = address_signatures
            .into_iter()
            .filter(|(_, signature)| !until_excluded_signatures.contains(signature))
            .collect();
        address_signatures.truncate(limit);

        // Fill in the status information for each found transaction
        let mut get_status_info_timer = Measure::start("get_status_info_timer");
        let mut infos = vec![];
        for (slot, signature) in address_signatures.into_iter() {
            let transaction_status =
                self.get_transaction_status(signature, &confirmed_unrooted_slots)?;
            let err = transaction_status.and_then(|(_slot, status)| status.status.err());
            let memo = self.read_transaction_memos(signature)?;
            let block_time = self.get_block_time(slot)?;
            infos.push(ConfirmedTransactionStatusWithSignature {
                signature,
                slot,
                err,
                memo,
                block_time,
            });
        }
        get_status_info_timer.stop();

        datapoint_info!(
            "blockstore-get-conf-sigs-for-addr-2",
            (
                "get_before_slot_us",
                get_before_slot_timer.as_us() as i64,
                i64
            ),
            (
                "get_initial_slot_us",
                get_initial_slot_timer.as_us() as i64,
                i64
            ),
            (
                "starting_primary_index_iter_us",
                starting_primary_index_iter_timer.as_us() as i64,
                i64
            ),
            (
                "next_primary_index_iter_us",
                next_primary_index_iter_timer.as_us() as i64,
                i64
            ),
            (
                "get_status_info_us",
                get_status_info_timer.as_us() as i64,
                i64
            ),
            (
                "get_until_slot_us",
                get_until_slot_timer.as_us() as i64,
                i64
            )
        );

        Ok(SignatureInfosForAddress {
            infos,
            found_before: true, // if `before` signature was not found, this method returned early
        })
    }

    fn get_sorted_block_signatures(&self, slot: Slot) -> Result<Vec<Signature>> {
        let block = self.get_complete_block(slot, false).map_err(|err| {
                BlockstoreError::Io(IoError::new(
                    ErrorKind::Other,
                format!("Unable to get block: {}", err),
                ))
            })?;

// Load all signatures for the block
        let mut slot_signatures: Vec<_> = block
.transactions
.into_iter()
.filter_map(|transaction_with_meta| {
transaction_with_meta
    .transaction
    .signatures
    .into_iter()
    .next()
})
.collect();

// Reverse sort signatures as a way to entire a stable ordering within a slot, as
// the AddressSignatures column is ordered by signatures within a slot,
// not by block ordering
slot_signatures.sort_unstable_by(|a, b| b.cmp(a));

Ok(slot_signatures)
}

pub fn read_transaction_memos(&self, signature: Signature) -> Result<Option<String>> {
    self.transaction_memos_cf.get(signature)
}

// Returns all signatures for an address in a particular slot, regardless of whether that slot
    // has been rooted. The transactions will be ordered by signature, and NOT by the order in
    // which the transactions exist in the block
    fn find_address_signatures_for_slot(
        &self,
        pubkey: Pubkey,
        slot: Slot,
    ) -> Result<Vec<(Slot, Signature)>> {
        let (lock, lowest_available_slot) = self.ensure_lowest_cleanup_slot();
        let mut signatures: Vec<(Slot, Signature)> = vec![];
        for transaction_status_cf_primary_index in 0..=1 {
            let index_iterator = self.address_signatures_cf.iter(IteratorMode::From(
                (
                    transaction_status_cf_primary_index,
                    pubkey,
                    slot.max(lowest_available_slot),
                    Signature::default(),
                ),
                IteratorDirection::Forward,
            ))?;
            for ((i, address, transaction_slot, signature), _) in index_iterator {
                if i != transaction_status_cf_primary_index
                    || transaction_slot > slot
                    || address != pubkey
                {
                    break;
                }
                signatures.push((slot, signature));
            }
        }
        drop(lock);
        signatures.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap().then(a.1.cmp(&b.1)));
        Ok(signatures)
    }

    pub fn get_rooted_block(
        &self,
        slot: Slot,
        require_previous_blockhash: bool,
    ) -> Result<ConfirmedBlock> {
        datapoint_info!(
            "blockstore-rpc-api",
            ("method", "get_rooted_block", String)
        );
        let _lock = self.check_lowest_cleanup_slot(slot)?;

        if self.is_root(slot) {
            return self.get_complete_block(slot, require_previous_blockhash);
        }
        Err(BlockstoreError::SlotNotRooted)
    }

    pub fn read_evm_transaction(
        &self,
        index: (H256, evm::BlockNum, Option<Slot>),
    ) -> Result<Option<evm::TransactionReceipt>> {
        let (hash, block_num, slot) = index;
        // search transaction in 0 | 1 primary indexes, with and without slot.
        for slot in slot.map(Some).into_iter().chain(Some(None)) {
            for primary_index in 0..=1 {
                if let Some(tx) = self
                    .evm_transactions_cf
                    .get_protobuf_or_bincode::<evm::TransactionReceipt>(
                        EvmTransactionReceiptsIndex {
                            index: primary_index,
                            hash,
                            block_num,
                            slot,
                        },
                    )?
                    .and_then(|meta| meta.try_into().ok())
                {
                    return Ok(Some(tx));
                }
            }
        }
        Ok(None)
    }

    /// Return iterator over evm blocks.
    /// There can be more than one block with same block number and different slot numbers.
    ///
    pub fn evm_blocks_iterator(
        &self,
        block_num: evm::BlockNum,
    ) -> Result<impl Iterator<Item = ((evm::BlockNum, Option<Slot>), evm::BlockHeader)> + '_> {
        let blocks_headers = self.evm_blocks_cf.iter(IteratorMode::From(
            cf::EvmBlockHeader::as_index(block_num),
            IteratorDirection::Forward,
        ))?;
        Ok(blocks_headers.map(move |(block_num, block_header)| {
            (
                block_num,
                self.evm_blocks_cf
                    .deserialize_protobuf_or_bincode::<evm::BlockHeader>(&block_header)
                    .unwrap_or_else(|e| {
                        panic!(
                            "Could not deserialize BlockHeader for block_num {} slot {:?}: {:?}",
                            block_num.0, block_num.1, e
                        )
                    })
                    .try_into()
                    .expect("Convertation should always pass"),
            )
        }))
    }

    pub fn find_evm_transaction(&self, hash: H256) -> Result<Option<evm::TransactionReceipt>> {
        // collect all transactions by hash, from both primary indexes (0 | 1), for any blocks.
        let mut transactions: Vec<_> = self
            .evm_transactions_cf
            .iter(IteratorMode::From(
                EvmTransactionReceiptsIndex {
                    index: 0,
                    hash,
                    block_num: 0,
                    slot: None,
                },
                IteratorDirection::Forward,
            ))?
            .take_while(
                |(
                    EvmTransactionReceiptsIndex {
                        hash: found_hash, ..
                    },
                    _data,
                )| *found_hash == hash,
            )
            .collect();
        transactions.extend(
            self.evm_transactions_cf
                .iter(IteratorMode::From(
                    EvmTransactionReceiptsIndex {
                        index: 1,
                        hash,
                        block_num: 0,
                        slot: None,
                    },
                    IteratorDirection::Forward,
                ))?
                .take_while(
                    |(
                        EvmTransactionReceiptsIndex {
                            hash: found_hash, ..
                        },
                        _data,
                    )| *found_hash == hash,
                ),
        );

        // find first transaction with confirmed slot
        let mut confirmed_transaction_data = transactions
            .iter()
            .find(|(EvmTransactionReceiptsIndex { slot, .. }, _)| {
                if let Some(slot) = slot {
                    if self.is_root(*slot) {
                        return true;
                    }
                }
                false
            })
            .map(|(_, data)| data);

        if confirmed_transaction_data.is_none() {
            // find transactions with confirmed blocks. (Old version of db where is no slot for transaction)
            // need to remove it later.
            for (
                EvmTransactionReceiptsIndex {
                    hash, block_num, ..
                },
                data,
            ) in &transactions
            {
                let blocks = if let Ok(b) = self.evm_blocks_iterator(*block_num) {
                    b
                } else {
                    continue;
                };
                let confirmed_block_found = blocks
                    .take_while(|((block_index, _slot), _block)| block_index == block_num)
                    .any(|(_, header)| {
                        self.is_root(header.native_chain_slot) && header.transactions.contains(hash)
                    });

                if confirmed_block_found {
                    confirmed_transaction_data = Some(data);
                    break;
                }
            }
        }

        // if no confirmed block found for transaction, return any tx.
        let transaction_data =
            confirmed_transaction_data.or_else(|| transactions.first().map(|(_, data)| data));

        let transaction_data = match transaction_data {
            Some(tx_data) => {
                let tx_receipt = self
                    .evm_transactions_cf
                    .deserialize_protobuf_or_bincode::<evm::TransactionReceipt>(tx_data)?;
                let tx_receipt: evm::TransactionReceipt =
                    tx_receipt.try_into().map_err(BlockstoreError::Other)?;
                Some(tx_receipt)
            }
            None => None,
        };

        // let mb_tx = transaction_data
        //     .map(|data| {
        //         self.evm_transactions_cf
        //             .deserialize_protobuf_or_bincode::<evm::TransactionReceipt>(&data)
        //     })
        //     .transpose()?
        //     .map(|tx_receipt| tx_receipt.try_into())
        //     .

        Ok(transaction_data)
    }

    fn get_primary_index_to_write(
        &self,
        slot: Slot,
        // take WriteGuard to require critical section semantics at call site
        w_active_transaction_status_index: &RwLockWriteGuard<Slot>,
    ) -> Result<u64> {
        let i = **w_active_transaction_status_index;
        let mut index_meta = self.transaction_status_index_cf.get(i)?.unwrap();
        if slot > index_meta.max_slot {
            assert!(!index_meta.frozen);
            index_meta.max_slot = slot;
            self.transaction_status_index_cf.put(i, &index_meta)?;
        }
        Ok(i)
    }

    pub fn get_first_available_evm_block(&self) -> Result<evm::BlockNum> {
        Ok(self
            .evm_blocks_cf
            .iter(IteratorMode::Start)?
            .map(|((block, _slot), _)| block)
            .next()
            .unwrap_or(evm::BlockNum::MAX))
    }

    pub fn filter_block_logs(
        block: &evm::Block,
        masks: &[evm::Bloom],
        filter: &evm::LogFilter,
    ) -> Result<Vec<evm::LogWithLocation>> {
        // First filterout all blocks that not contain any of our masks (each mask represent address + topic set)
        if masks
            .iter()
            .all(|mask| !block.header.logs_bloom.contains_bloom(mask))
        {
            trace!(
                target: "evm",
                "Blocks not matching bloom filter blocks_bloom = {:?}, blooms={:?}",
                block.header.logs_bloom,
                masks
            );
            return Ok(vec![]);
        }
        let mut logs = Vec::new();
        for (id, (hash, tx)) in block.transactions.iter().enumerate() {
            // Second filterout all transactions that not contain ALL topic + addresses
            if !masks.iter().any(|mask| tx.logs_bloom.contains_bloom(mask)) {
                trace!(target: "evm",
                    "tx not matching bloom filter blocks_bloom = {:?}, blooms={:?}",
                    tx.logs_bloom,
                    masks
                );
                continue;
            }
            // Then match precisely
            tx.logs.iter().enumerate().for_each(|(idx, log)| {
                if filter.is_log_match(log) {
                    trace!(target: "evm", "Adding transaction log to result = {:?}", log);
                    logs.push(evm::LogWithLocation {
                        transaction_hash: *hash,
                        transaction_id: id as u64,
                        block_num: block.header.block_number,
                        block_hash: block.header.hash(),
                        data: log.data.clone(),
                        log_index: idx,
                        topics: log.topics.clone(),
                        address: log.address,
                    })
                }
            });
        }
        Ok(logs)
    }

    pub fn write_transaction_memos(&self, signature: &Signature, memos: String) -> Result<()> {
        self.transaction_memos_cf.put(*signature, &memos)
    }

    pub fn get_complete_block(
        &self,
        slot: Slot,
        require_previous_blockhash: bool,
    ) -> Result<ConfirmedBlock> {
        let slot_meta_cf = self.db.column::<cf::SlotMeta>();
        let slot_meta = match slot_meta_cf.get(slot)? {
            Some(slot_meta) => slot_meta,
            None => {
                info!("SlotMeta not found for slot {}", slot);
                return Err(BlockstoreError::SlotUnavailable);
            }
        };
        if slot_meta.is_full() {
            let slot_entries = self.get_slot_entries(slot, 0)?;
            if !slot_entries.is_empty() {
                let blockhash = slot_entries
                    .last()
                    .map(|entry| entry.hash)
                    .unwrap_or_else(|| panic!("Rooted slot {:?} must have blockhash", slot));
                let slot_transaction_iterator = slot_entries
                    .into_iter()
                    .flat_map(|entry| entry.transactions)
                    .map(|transaction| {
                        if let Err(err) = transaction.sanitize() {
                            warn!(
                                "Blockstore::get_block sanitize failed: {:?}, \
                                slot: {:?}, \
                                {:?}",
                                err, slot, transaction,
                            );
                        }
                        transaction
                    });
                let parent_slot_entries = slot_meta
                    .parent_slot
                    .and_then(|parent_slot| {
                        self.get_slot_entries(parent_slot, /*shred_start_index:*/ 0)
                            .ok()
                    })
                    .unwrap_or_default();
                if parent_slot_entries.is_empty() && require_previous_blockhash {
                    return Err(BlockstoreError::ParentEntriesUnavailable);
                }
                let previous_blockhash = if !parent_slot_entries.is_empty() {
                    get_last_hash(parent_slot_entries.iter()).unwrap()
                } else {
                    Hash::default()
                };

                let rewards = self
                    .rewards_cf
                    .get_protobuf_or_bincode::<StoredExtendedRewards>(slot)?
                    .unwrap_or_default()
                    .into();

                // The Blocktime and BlockHeight column families are updated asynchronously; they
                // may not be written by the time the complete slot entries are available. In this
                // case, these fields will be `None`.
                let block_time = self.blocktime_cf.get(slot)?;
                let block_height = self.block_height_cf.get(slot)?;

                let block = ConfirmedBlock {
                    previous_blockhash: previous_blockhash.to_string(),
                    blockhash: blockhash.to_string(),
                    // If the slot is full it should have parent_slot populated
                    // from shreds received.
                    parent_slot: slot_meta.parent_slot.unwrap(),
                    transactions: self
                        .map_transactions_to_statuses(slot, slot_transaction_iterator)?,
                    rewards,
                    block_time,
                    block_height,
                };
                return Ok(block);
            }
        }
        Err(BlockstoreError::SlotUnavailable)
    }

    /// Returns the entry vector for the slot starting with `shred_start_index`
    pub fn get_slot_entries(&self, slot: Slot, shred_start_index: u64) -> Result<Vec<Entry>> {
        self.get_slot_entries_with_shred_info(slot, shred_start_index, false)
            .map(|x| x.0)
    }

    /// Returns the entry vector for the slot starting with `shred_start_index`, the number of
    /// shreds that comprise the entry vector, and whether the slot is full (consumed all shreds).
    pub fn get_slot_entries_with_shred_info(
        &self,
        slot: Slot,
        start_index: u64,
        allow_dead_slots: bool,
    ) -> Result<(Vec<Entry>, u64, bool)> {
        let (completed_ranges, slot_meta) = self.get_completed_ranges(slot, start_index)?;

        // Check if the slot is dead *after* fetching completed ranges to avoid a race
        // where a slot is marked dead by another thread before the completed range query finishes.
        // This should be sufficient because full slots will never be marked dead from another thread,
        // this can only happen during entry processing during replay stage.
        if self.is_dead(slot) && !allow_dead_slots {
            return Err(BlockstoreError::DeadSlot);
        } else if completed_ranges.is_empty() {
            return Ok((vec![], 0, false));
        }

        let slot_meta = slot_meta.unwrap();
        let num_shreds = completed_ranges
            .last()
            .map(|(_, end_index)| u64::from(*end_index) - start_index + 1)
            .unwrap_or(0);

        let entries: Result<Vec<Vec<Entry>>> = PAR_THREAD_POOL.with(|thread_pool| {
            thread_pool.borrow().install(|| {
                completed_ranges
                    .par_iter()
                    .map(|(start_index, end_index)| {
                        self.get_entries_in_data_block(
                            slot,
                            *start_index,
                            *end_index,
                            Some(&slot_meta),
                        )
                    })
                    .collect()
            })
        });

        let entries: Vec<Entry> = entries?.into_iter().flatten().collect();
        Ok((entries, num_shreds, slot_meta.is_full()))
    }

    pub fn map_transactions_to_statuses(
        &self,
        slot: Slot,
        iterator: impl Iterator<Item = VersionedTransaction>,
    ) -> Result<Vec<TransactionWithMetadata>> {
        iterator
            .map(|versioned_tx| {
                // TODO: add support for versioned transactions
                if let Some(transaction) = versioned_tx.into_legacy_transaction() {
                    let signature = transaction.signatures[0];
                    Ok(TransactionWithMetadata {
                        transaction,
                        meta: self
                            .read_transaction_status((signature, slot))?
                            .ok_or(BlockstoreError::MissingTransactionMetadata)?,
                    })
                } else {
                    Err(BlockstoreError::UnsupportedTransactionVersion)
                }
            })
            .collect()
    }

    fn get_completed_ranges(
        &self,
        slot: Slot,
        start_index: u64,
    ) -> Result<(CompletedRanges, Option<SlotMeta>)> {
        let _lock = self.check_lowest_cleanup_slot(slot)?;

        let slot_meta_cf = self.db.column::<cf::SlotMeta>();
        let slot_meta = slot_meta_cf.get(slot)?;
        if slot_meta.is_none() {
            return Ok((vec![], slot_meta));
        }

        let slot_meta = slot_meta.unwrap();
        // Find all the ranges for the completed data blocks
        let completed_ranges = Self::get_completed_data_ranges(
            start_index as u32,
            &slot_meta.completed_data_indexes,
            slot_meta.consumed as u32,
        );

        Ok((completed_ranges, Some(slot_meta)))
    }

    /// Returns a complete transaction if it was processed in a root
    pub fn get_rooted_transaction(
        &self,
        signature: Signature,
    ) -> Result<Option<ConfirmedTransaction>> {
        datapoint_info!(
            "blockstore-rpc-api",
            ("method", "get_rooted_transaction", String)
        );
        self.get_transaction_with_status(signature, &[])
    }

    fn get_transaction_with_status(
        &self,
        signature: Signature,
        confirmed_unrooted_slots: &[Slot],
    ) -> Result<Option<ConfirmedTransaction>> {
        if let Some((slot, meta)) = self.get_transaction_status(signature, confirmed_unrooted_slots)?
        {
            let transaction = self
                .find_transaction_in_slot(slot, signature)?
                .ok_or(BlockstoreError::TransactionStatusSlotMismatch)?; // Should not happen

            // TODO: support retrieving versioned transactions
            let transaction = transaction
                .into_legacy_transaction()
                .ok_or(BlockstoreError::UnsupportedTransactionVersion)?;

            let block_time = self.get_block_time(slot)?;
            Ok(Some(ConfirmedTransaction {
                slot,
                transaction: TransactionWithMetadata { transaction, meta },
                block_time,
            }))
        } else {
            Ok(None)
        }
    }

    /// Returns a transaction status
    pub fn get_transaction_status(
        &self,
        signature: Signature,
        confirmed_unrooted_slots: &[Slot],
    ) -> Result<Option<(Slot, TransactionStatusMeta)>> {
        datapoint_info!(
            "blockstore-rpc-api",
            ("method", "get_transaction_status", String)
        );
        self.get_transaction_status_with_counter(signature, confirmed_unrooted_slots)
            .map(|(status, _)| status)
    }

    // Returns a transaction status, as well as a loop counter for unit testing
    fn get_transaction_status_with_counter(
        &self,
        signature: Signature,
        confirmed_unrooted_slots: &[Slot],
    ) -> Result<(Option<(Slot, TransactionStatusMeta)>, u64)> {
        let mut counter = 0;
        let (lock, lowest_available_slot) = self.ensure_lowest_cleanup_slot();

        for transaction_status_cf_primary_index in 0..=1 {
            let index_iterator = self.transaction_status_cf.iter(IteratorMode::From(
                (
                    transaction_status_cf_primary_index,
                    signature,
                    lowest_available_slot,
                ),
                IteratorDirection::Forward,
            ))?;
            for ((i, sig, slot), _data) in index_iterator {
                counter += 1;
                if i != transaction_status_cf_primary_index || sig != signature {
                    break;
                }
                if !self.is_root(slot) && !confirmed_unrooted_slots.contains(&slot) {
                    continue;
                }
                let status = self
                    .transaction_status_cf
                    .get_protobuf_or_bincode::<StoredTransactionStatusMeta>((i, sig, slot))?
                    .and_then(|status| status.try_into().ok())
                    .map(|status| (slot, status));
                return Ok((status, counter));
            }
        }
        drop(lock);

        Ok((None, counter))
    }

    fn find_transaction_in_slot(
        &self,
        slot: Slot,
        signature: Signature,
    ) -> Result<Option<VersionedTransaction>> {
        let slot_entries = self.get_slot_entries(slot, 0)?;
        Ok(slot_entries
            .iter()
            .cloned()
            .flat_map(|entry| entry.transactions)
            .map(|transaction| {
                if let Err(err) = transaction.sanitize() {
                    warn!(
                        "Blockstore::find_transaction_in_slot sanitize failed: {:?}, \
                        slot: {:?}, \
                        {:?}",
                        err, slot, transaction,
                    );
                }
                transaction
            })
            .find(|transaction| transaction.signatures[0] == signature))
    }

    pub fn get_block_time(&self, slot: Slot) -> Result<Option<UnixTimestamp>> {
        datapoint_info!(
            "blockstore-rpc-api",
            ("method", "get_block_time", String)
        );
        let _lock = self.check_lowest_cleanup_slot(slot)?;
        self.blocktime_cf.get(slot)
    }

    pub fn is_dead(&self, slot: Slot) -> bool {
        matches!(
            self.db
                .get::<cf::DeadSlots>(slot)
                .expect("fetch from DeadSlots column family failed"),
            Some(true)
        )
    }

    pub fn get_entries_in_data_block(
        &self,
        slot: Slot,
        start_index: u32,
        end_index: u32,
        slot_meta: Option<&SlotMeta>,
    ) -> Result<Vec<Entry>> {
        let data_shred_cf = self.db.column::<cf::ShredData>();

        // Short circuit on first error
        let data_shreds: Result<Vec<Shred>> = (start_index..=end_index)
            .map(|i| {
                data_shred_cf
                    .get_bytes((slot, u64::from(i)))
                    .and_then(|serialized_shred| {
                        if serialized_shred.is_none() {
                            if let Some(slot_meta) = slot_meta {
                                panic!(
                                    "Shred with
                                    slot: {},
                                    index: {},
                                    consumed: {},
                                    completed_indexes: {:?}
                                    must exist if shred index was included in a range: {} {}",
                                    slot,
                                    i,
                                    slot_meta.consumed,
                                    slot_meta.completed_data_indexes,
                                    start_index,
                                    end_index
                                );
                            } else {
                                return Err(BlockstoreError::InvalidShredData(Box::new(
                                    bincode::ErrorKind::Custom(format!(
                                        "Missing shred for slot {}, index {}",
                                        slot, i
                                    )),
                                )));
                            }
                        }

                        Shred::new_from_serialized_shred(serialized_shred.unwrap()).map_err(|err| {
                            BlockstoreError::InvalidShredData(Box::new(bincode::ErrorKind::Custom(
                                format!(
                                    "Could not reconstruct shred from shred payload: {:?}",
                                    err
                                ),
                            )))
                        })
                    })
            })
            .collect();

        let data_shreds = data_shreds?;
        let last_shred = data_shreds.last().unwrap();
        assert!(last_shred.data_complete() || last_shred.last_in_slot());

        let deshred_payload = Shredder::deshred(&data_shreds).map_err(|e| {
            BlockstoreError::InvalidShredData(Box::new(bincode::ErrorKind::Custom(format!(
                "Could not reconstruct data block from constituent shreds, error: {:?}",
                e
            ))))
        })?;

        debug!("{:?} shreds in last FEC set", data_shreds.len(),);
        bincode::deserialize::<Vec<Entry>>(&deshred_payload).map_err(|e| {
            BlockstoreError::InvalidShredData(Box::new(bincode::ErrorKind::Custom(format!(
                "could not reconstruct entries: {:?}",
                e
            ))))
        })
    }

    fn check_lowest_cleanup_slot(&self, slot: Slot) -> Result<parking_lot::RwLockReadGuard<Slot>> {
        // lowest_cleanup_slot is the last slot that was not cleaned up by LedgerCleanupService
        let lowest_cleanup_slot = self.lowest_cleanup_slot.read_recursive();
        if *lowest_cleanup_slot > 0 && *lowest_cleanup_slot >= slot {
            return Err(BlockstoreError::SlotCleanedUp);
        }
        // Make caller hold this lock properly; otherwise LedgerCleanupService can purge/compact
        // needed slots here at any given moment
        Ok(lowest_cleanup_slot)
    }

    // Get the range of indexes [start_index, end_index] of every completed data block
    fn get_completed_data_ranges(
        start_index: u32,
        completed_data_indexes: &BTreeSet<u32>,
        consumed: u32,
    ) -> CompletedRanges {
        // `consumed` is the next missing shred index, but shred `i` existing in
        // completed_data_end_indexes implies it's not missing
        assert!(!completed_data_indexes.contains(&consumed));
        completed_data_indexes
            .range(start_index..consumed)
            .scan(start_index, |begin, index| {
                let out = (*begin, *index);
                *begin = index + 1;
                Some(out)
            })
            .collect()
    }

    pub fn read_transaction_status(
        &self,
        index: (Signature, Slot),
    ) -> Result<Option<TransactionStatusMeta>> {
        let (signature, slot) = index;
        let result = self
            .transaction_status_cf
            .get_protobuf_or_bincode::<StoredTransactionStatusMeta>((0, signature, slot))?;
        if result.is_none() {
            Ok(self
                .transaction_status_cf
                .get_protobuf_or_bincode::<StoredTransactionStatusMeta>((1, signature, slot))?
                .and_then(|meta| meta.try_into().ok()))
        } else {
            Ok(result.and_then(|meta| meta.try_into().ok()))
        }
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
            leader_schedule, //none
            is_trusted, //f
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
        // 获取表头？？
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
        // 检查是否有任何元数据被更改，如果有，将更新的元数据送入write batch
        let (should_signal, newly_completed_slots) = commit_slot_meta_working_set(
            &slot_meta_working_set,
            &self.completed_slots_senders,
            &mut write_batch,
        )?;

        // 擦除错误coding信息
        for (erasure_set, erasure_meta) in erasure_metas {
            write_batch.put::<cf::ErasureMeta>(erasure_set.store_key(), &erasure_meta)?;
        }

        // 索引相关
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
        erasure_metas: &mut HashMap<ErasureSetId, ErasureMeta>, // 输入的空hashmap
        index_working_set: &mut HashMap<u64, IndexMetaWorkingSetEntry>, // 输入的空hashmap
        slot_meta_working_set: &mut HashMap<u64, SlotMetaWorkingSetEntry>, // 输入的空hashmap
        write_batch: &mut WriteBatch,
        just_inserted_shreds: &mut HashMap<ShredId, Shred>, // 输入的空hashmap
        index_meta_time: &mut u64, // 0
        is_trusted: bool,
        handle_duplicate: &F,
        leader_schedule: Option<&LeaderScheduleCache>,
        shred_source: ShredSource,
    ) -> std::result::Result<Vec<CompletedDataSetInfo>, InsertDataShredError>
    where
        F: Fn(Shred),
    {   
        // 获取ShredCommonHeader中的slot
        let slot = shred.slot();
        // 获取ShredCommonHeader中的index
        let shred_index = u64::from(shred.index());

        // 获取index_working_set 中 ShredCommonHeader里的slot对应的IndexMetaWorkingSetEntry， 
        // 如果没有则从数据库中获取；若数据库中没有，则在该slot处新建一个默认的IndexMetaWorkingSetEntry
        let index_meta_working_set_entry =
            get_index_meta_entry(&self.db, slot, index_working_set, index_meta_time);

        let index_meta = &mut index_meta_working_set_entry.index;
        
        // 检查是否已经将这个分片的slot元数据插入到数据库中，取没插入数据库中的数据
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

        // 获取切片中需要擦除的slot
        let erasure_set = shred.erasure_set();
        // 获取需要插入的切片数据
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
        // 检查erasure_metas中是否存在erasure_set键的条目，如果不存在，则将blockstore中的erasure_meta插入到这个键的位置上。
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

    fn is_data_shred_present(shred: &Shred, slot_meta: &SlotMeta, data_index: &ShredIndex) -> bool {
        let shred_index = u64::from(shred.index());
        // Check that the shred doesn't already exist in blockstore
        shred_index < slot_meta.consumed || data_index.contains(shred_index)
    }

    fn should_insert_data_shred(
        &self,
        shred: &Shred,
        slot_meta: &SlotMeta,
        just_inserted_shreds: &HashMap<ShredId, Shred>,
        last_root: &RwLock<u64>,
        leader_schedule: Option<&LeaderScheduleCache>,
        shred_source: ShredSource,
    ) -> bool {
        let shred_index = u64::from(shred.index());
        let slot = shred.slot();
        let last_in_slot = if shred.last_in_slot() {
            debug!("got last in slot");
            true
        } else {
            false
        };

        if shred.data_header.size == 0 {
            let leader_pubkey = leader_schedule
                .and_then(|leader_schedule| leader_schedule.slot_leader_at(slot, None));

            datapoint_error!(
                "blockstore_error",
                (
                    "error",
                    format!(
                        "Leader {:?}, slot {}: received index {} is empty",
                        leader_pubkey, slot, shred_index,
                    ),
                    String
                )
            );
            return false;
        }
        if shred.payload.len() > SHRED_PAYLOAD_SIZE {
            let leader_pubkey = leader_schedule
                .and_then(|leader_schedule| leader_schedule.slot_leader_at(slot, None));

            datapoint_error!(
                "blockstore_error",
                (
                    "error",
                    format!(
                        "Leader {:?}, slot {}: received index {} shred.payload.len() > SHRED_PAYLOAD_SIZE",
                        leader_pubkey, slot, shred_index,
                    ),
                    String
                )
            );
            return false;
        }

        // Check that we do not receive shred_index >= than the last_index
        // for the slot
        let last_index = slot_meta.last_index;
        if last_index.map(|ix| shred_index >= ix).unwrap_or_default() {
            let leader_pubkey = leader_schedule
                .and_then(|leader_schedule| leader_schedule.slot_leader_at(slot, None));

            let ending_shred: Cow<Vec<u8>> = self.get_data_shred_from_just_inserted_or_db(
                just_inserted_shreds,
                slot,
                last_index.unwrap(),
            );

            if self
                .store_duplicate_if_not_existing(
                    slot,
                    ending_shred.into_owned(),
                    shred.payload.clone(),
                )
                .is_err()
            {
                warn!("store duplicate error");
            }

            datapoint_error!(
                    "blockstore_error",
                    (
                        "error",
                        format!(
                        "Leader {:?}, slot {}: received index {} >= slot.last_index {:?}, shred_source: {:?}",
                        leader_pubkey, slot, shred_index, last_index, shred_source
                        ),
                        String
                    )
                );
            return false;
        }
        // Check that we do not receive a shred with "last_index" true, but shred_index
        // less than our current received
        if last_in_slot && shred_index < slot_meta.received {
            let leader_pubkey = leader_schedule
                .and_then(|leader_schedule| leader_schedule.slot_leader_at(slot, None));

            let ending_shred: Cow<Vec<u8>> = self.get_data_shred_from_just_inserted_or_db(
                just_inserted_shreds,
                slot,
                slot_meta.received - 1,
            );

            if self
                .store_duplicate_if_not_existing(
                    slot,
                    ending_shred.into_owned(),
                    shred.payload.clone(),
                )
                .is_err()
            {
                warn!("store duplicate error");
            }

            datapoint_error!(
                    "blockstore_error",
                    (
                        "error",
                        format!(
                        "Leader {:?}, slot {}: received shred_index {} < slot.received {}, shred_source: {:?}",
                        leader_pubkey, slot, shred_index, slot_meta.received, shred_source
                        ),
                        String
                    )
                );
            return false;
        }

        let last_root = *last_root.read().unwrap();
        // TODO Shouldn't this use shred.parent() instead and update
        // slot_meta.parent_slot accordingly?
        slot_meta
            .parent_slot
            .map(|parent_slot| verify_shred_slots(slot, parent_slot, last_root))
            .unwrap_or_default()
    }

    fn insert_data_shred(
        &self,
        slot_meta: &mut SlotMeta,
        data_index: &mut ShredIndex,
        shred: &Shred,
        write_batch: &mut WriteBatch,
        shred_source: ShredSource,
    ) -> Result<Vec<CompletedDataSetInfo>> {
        let slot = shred.slot();
        let index = u64::from(shred.index());

        let last_in_slot = if shred.last_in_slot() {
            debug!("got last in slot");
            true
        } else {
            false
        };

        let last_in_data = if shred.data_complete() {
            debug!("got last in data");
            true
        } else {
            false
        };

        // Parent for slot meta should have been set by this point
        assert!(!is_orphan(slot_meta));

        let new_consumed = if slot_meta.consumed == index {
            let mut current_index = index + 1;

            while data_index.contains(current_index) {
                current_index += 1;
            }
            current_index
        } else {
            slot_meta.consumed
        };

        // Commit step: commit all changes to the mutable structures at once, or none at all.
        // We don't want only a subset of these changes going through.
        // 向数据库中的ShredData列添加数据，payload为切片data_header的大小
        write_batch.put_bytes::<cf::ShredData>(
            (slot, index),
            // Payload will be padded out to SHRED_PAYLOAD_SIZE
            // But only need to store the bytes within data_header.size
            &shred.payload[..shred.data_header.size as usize],
        )?;
        // 将切片index插入data_index
        data_index.insert(index);
        let newly_completed_data_sets = update_slot_meta(
            last_in_slot,
            last_in_data,
            slot_meta,
            index as u32,
            new_consumed,
            shred.reference_tick(),
            data_index,
        )
        .into_iter()
        .map(|(start_index, end_index)| CompletedDataSetInfo {
            slot,
            start_index,
            end_index,
        })
        .collect();
        if shred_source == ShredSource::Repaired || shred_source == ShredSource::Recovered {
            let mut slots_stats = self.slots_stats.lock().unwrap();
            let mut e = slots_stats.stats.entry(slot_meta.slot).or_default();
            if shred_source == ShredSource::Repaired {
                e.num_repaired += 1;
            }
            if shred_source == ShredSource::Recovered {
                e.num_recovered += 1;
            }
        }
        if slot_meta.is_full() {
            let (num_repaired, num_recovered) = {
                let mut slots_stats = self.slots_stats.lock().unwrap();
                if let Some(e) = slots_stats.stats.remove(&slot_meta.slot) {
                    if slots_stats.last_cleanup_ts.elapsed().as_secs() > 30 {
                        let root = self.last_root();
                        slots_stats.stats = slots_stats.stats.split_off(&root);
                        slots_stats.last_cleanup_ts = Instant::now();
                    }
                    (e.num_repaired, e.num_recovered)
                } else {
                    (0, 0)
                }
            };
            datapoint_info!(
                "shred_insert_is_full",
                (
                    "total_time_ms",
                    sdk::timing::timestamp() - slot_meta.first_shred_timestamp,
                    i64
                ),
                ("slot", slot_meta.slot, i64),
                (
                    "last_index",
                    slot_meta
                        .last_index
                        .and_then(|ix| i64::try_from(ix).ok())
                        .unwrap_or(-1),
                    i64
                ),
                ("num_repaired", num_repaired, i64),
                ("num_recovered", num_recovered, i64),
            );
        }
        trace!("inserted shred into slot {:?} and index {:?}", slot, index);
        Ok(newly_completed_data_sets)
    }

    fn erasure_meta(&self, erasure_set: ErasureSetId) -> Result<Option<ErasureMeta>> {
        self.erasure_meta_cf.get(erasure_set.store_key())
    }

    fn should_insert_coding_shred(shred: &Shred, last_root: &RwLock<u64>) -> bool {
        shred.is_code() && shred.sanitize() && shred.slot() > *last_root.read().unwrap()
    }

    fn find_conflicting_coding_shred(
        &self,
        shred: &Shred,
        slot: Slot,
        erasure_meta: &ErasureMeta,
        just_received_shreds: &HashMap<ShredId, Shred>,
    ) -> Option<Vec<u8>> {
        // Search for the shred which set the initial erasure config, either inserted,
        // or in the current batch in just_received_shreds.
        for coding_index in erasure_meta.coding_shreds_indices() {
            let maybe_shred = self.get_coding_shred(slot, coding_index);
            if let Ok(Some(shred_data)) = maybe_shred {
                let potential_shred = Shred::new_from_serialized_shred(shred_data).unwrap();
                if Self::erasure_mismatch(&potential_shred, shred) {
                    return Some(potential_shred.payload);
                }
            } else if let Some(potential_shred) = {
                let key = ShredId::new(slot, u32::try_from(coding_index).unwrap(), ShredType::Code);
                just_received_shreds.get(&key)
            } {
                if Self::erasure_mismatch(potential_shred, shred) {
                    return Some(potential_shred.payload.clone());
                }
            }
        }
        None
    }

    pub fn store_duplicate_if_not_existing(
        &self,
        slot: Slot,
        shred1: Vec<u8>,
        shred2: Vec<u8>,
    ) -> Result<()> {
        if !self.has_duplicate_shreds_in_slot(slot) {
            self.store_duplicate_slot(slot, shred1, shred2)
        } else {
            Ok(())
        }
    }

    fn insert_coding_shred(
        &self,
        index_meta: &mut Index,
        shred: &Shred,
        write_batch: &mut WriteBatch,
    ) -> Result<()> {
        let slot = shred.slot();
        let shred_index = u64::from(shred.index());

        // Assert guaranteed by integrity checks on the shred that happen before
        // `insert_coding_shred` is called
        assert!(shred.is_code() && shred.sanitize());

        // Commit step: commit all changes to the mutable structures at once, or none at all.
        // We don't want only a subset of these changes going through.
        write_batch.put_bytes::<cf::ShredCode>((slot, shred_index), &shred.payload)?;
        index_meta.coding_mut().insert(shred_index);

        Ok(())
    }

    pub fn has_duplicate_shreds_in_slot(&self, slot: Slot) -> bool {
        self.duplicate_slots_cf
            .get(slot)
            .expect("fetch from DuplicateSlots column family failed")
            .is_some()
    }

    fn recover_shreds(
        index: &mut Index,
        erasure_meta: &ErasureMeta,
        prev_inserted_shreds: &HashMap<ShredId, Shred>,
        recovered_data_shreds: &mut Vec<Shred>,
        data_cf: &LedgerColumn<cf::ShredData>,
        code_cf: &LedgerColumn<cf::ShredCode>,
    ) {
        // Find shreds for this erasure set and try recovery
        let slot = index.slot;
        let available_shreds: Vec<_> = Self::get_recovery_data_shreds(
            index,
            slot,
            erasure_meta,
            prev_inserted_shreds,
            data_cf,
        )
        .chain(Self::get_recovery_coding_shreds(
            index,
            slot,
            erasure_meta,
            prev_inserted_shreds,
            code_cf,
        ))
        .collect();
        if let Ok(mut result) = Shredder::try_recovery(available_shreds) {
            Self::submit_metrics(slot, erasure_meta, true, "complete".into(), result.len());
            recovered_data_shreds.append(&mut result);
        } else {
            Self::submit_metrics(slot, erasure_meta, true, "incomplete".into(), 0);
        }
    }

    fn submit_metrics(
        slot: Slot,
        erasure_meta: &ErasureMeta,
        attempted: bool,
        status: String,
        recovered: usize,
    ) {
        let mut data_shreds_indices = erasure_meta.data_shreds_indices();
        let start_index = data_shreds_indices.next().unwrap_or_default();
        let end_index = data_shreds_indices.last().unwrap_or(start_index);
        datapoint_debug!(
            "blockstore-erasure",
            ("slot", slot as i64, i64),
            ("start_index", start_index, i64),
            ("end_index", end_index + 1, i64),
            ("recovery_attempted", attempted, bool),
            ("recovery_status", status, String),
            ("recovered", recovered as i64, i64),
        );
    }

    fn get_data_shred_from_just_inserted_or_db<'a>(
        &'a self,
        just_inserted_shreds: &'a HashMap<ShredId, Shred>,
        slot: Slot,
        index: u64,
    ) -> Cow<'a, Vec<u8>> {
        let key = ShredId::new(slot, u32::try_from(index).unwrap(), ShredType::Data);
        if let Some(shred) = just_inserted_shreds.get(&key) {
            Cow::Borrowed(&shred.payload)
        } else {
            // If it doesn't exist in the just inserted set, it must exist in
            // the backing store
            Cow::Owned(self.get_data_shred(slot, index).unwrap().unwrap())
        }
    }

    pub fn last_root(&self) -> Slot {
        *self.last_root.read().unwrap()
    }

    fn erasure_mismatch(shred1: &Shred, shred2: &Shred) -> bool {
        shred1.coding_header.num_coding_shreds != shred2.coding_header.num_coding_shreds
            || shred1.coding_header.num_data_shreds != shred2.coding_header.num_data_shreds
            || shred1.first_coding_index() != shred2.first_coding_index()
    }

    pub fn store_duplicate_slot(&self, slot: Slot, shred1: Vec<u8>, shred2: Vec<u8>) -> Result<()> {
        let duplicate_slot_proof = DuplicateSlotProof::new(shred1, shred2);
        self.duplicate_slots_cf.put(slot, &duplicate_slot_proof)
    }

    pub fn get_coding_shred(&self, slot: Slot, index: u64) -> Result<Option<Vec<u8>>> {
        self.code_shred_cf.get_bytes((slot, index))
    }

    fn get_recovery_data_shreds<'a>(
        index: &'a Index,
        slot: Slot,
        erasure_meta: &'a ErasureMeta,
        prev_inserted_shreds: &'a HashMap<ShredId, Shred>,
        data_cf: &'a LedgerColumn<cf::ShredData>,
    ) -> impl Iterator<Item = Shred> + 'a {
        erasure_meta.data_shreds_indices().filter_map(move |i| {
            let key = ShredId::new(slot, u32::try_from(i).unwrap(), ShredType::Data);
            if let Some(shred) = prev_inserted_shreds.get(&key) {
                return Some(shred.clone());
            }
            if !index.data().contains(i) {
                return None;
            }
            match data_cf.get_bytes((slot, i)).unwrap() {
                None => {
                    warn!("Data shred deleted while reading for recovery");
                    None
                }
                Some(data) => Shred::new_from_serialized_shred(data).ok(),
            }
        })
    }

    fn get_recovery_coding_shreds<'a>(
        index: &'a Index,
        slot: Slot,
        erasure_meta: &'a ErasureMeta,
        prev_inserted_shreds: &'a HashMap<ShredId, Shred>,
        code_cf: &'a LedgerColumn<cf::ShredCode>,
    ) -> impl Iterator<Item = Shred> + 'a {
        erasure_meta.coding_shreds_indices().filter_map(move |i| {
            let key = ShredId::new(slot, u32::try_from(i).unwrap(), ShredType::Code);
            if let Some(shred) = prev_inserted_shreds.get(&key) {
                return Some(shred.clone());
            }
            if !index.coding().contains(i) {
                return None;
            }
            match code_cf.get_bytes((slot, i)).unwrap() {
                None => {
                    warn!("Code shred deleted while reading for recovery");
                    None
                }
                Some(code) => Shred::new_from_serialized_shred(code).ok(),
            }
        })
    }

    pub fn get_data_shred(&self, slot: Slot, index: u64) -> Result<Option<Vec<u8>>> {
        self.data_shred_cf.get_bytes((slot, index)).map(|data| {
            data.map(|mut d| {
                // Only data_header.size bytes stored in the blockstore so
                // pad the payload out to SHRED_PAYLOAD_SIZE so that the
                // erasure recovery works properly.
                d.resize(cmp::max(d.len(), SHRED_PAYLOAD_SIZE), 0);
                d
            })
        })
    }

    pub fn slot_meta_iterator(
        &self,
        slot: Slot,
    ) -> Result<impl Iterator<Item = (Slot, SlotMeta)> + '_> {
        let meta_iter = self
            .db
            .iter::<cf::SlotMeta>(IteratorMode::From(slot, IteratorDirection::Forward))?;
        Ok(meta_iter.map(|(slot, slot_meta_bytes)| {
            (
                slot,
                deserialize(&slot_meta_bytes).unwrap_or_else(|e| {
                    panic!("Could not deserialize SlotMeta for slot {}: {:?}", slot, e)
                }),
            )
        }))
    }
    
}

pub enum EvmStateJson<'a> {
    OpenEthereum(&'a Path),
    Geth(&'a Path),
    None
}

#[macro_export]
macro_rules! tmp_ledger_name {
    () => {
        &format!("{}-{}", file!(), line!())
    };
}

#[macro_export]
macro_rules! get_tmp_ledger_path {
    () => {
        $crate::blockstore::get_ledger_path_from_name($crate::tmp_ledger_name!())
    };
}


pub fn get_ledger_path_from_name(name: &str) -> PathBuf {
    use std::env;
    let out_dir = env::var("FARF_DIR").unwrap_or_else(|_| "farf".to_string());
    let keypair = Keypair::new();

    let path = [
        out_dir,
        "ledger".to_string(),
        format!("{}-{}", name, keypair.pubkey()),
    ]
    .iter()
    .collect();

    // whack any possible collision
    let _ignored = fs::remove_dir_all(&path);

    path
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

/// 检查是否有任何元数据被更改，如果有，将更新的元数据送入write batch
fn commit_slot_meta_working_set(
    slot_meta_working_set: &HashMap<u64, SlotMetaWorkingSetEntry>,
    completed_slots_senders: &[SyncSender<Vec<u64>>],
    write_batch: &mut WriteBatch,
) -> Result<(bool, Vec<u64>)> {
    let mut should_signal = false;
    let mut newly_completed_slots = vec![];

    // Check if any metadata was changed, if so, insert the new version of the
    // metadata into the write batch
    for (slot, slot_meta_entry) in slot_meta_working_set.iter() {
        // Any slot that wasn't written to should have been filtered out by now.
        assert!(slot_meta_entry.did_insert_occur);
        let meta: &SlotMeta = &RefCell::borrow(&*slot_meta_entry.new_slot_meta);
        let meta_backup = &slot_meta_entry.old_slot_meta;
        if !completed_slots_senders.is_empty() && is_newly_completed_slot(meta, meta_backup) {
            newly_completed_slots.push(*slot);
        }
        // Check if the working copy of the metadata has changed
        if Some(meta) != meta_backup.as_ref() {
            should_signal = should_signal || slot_has_updates(meta, meta_backup);
            write_batch.put::<cf::SlotMeta>(*slot, meta)?;
        }
    }

    Ok((should_signal, newly_completed_slots))
}

fn send_signals(
    new_shreds_signals: &[SyncSender<bool>],
    completed_slots_senders: &[SyncSender<Vec<u64>>],
    should_signal: bool,
    newly_completed_slots: Vec<u64>,
) {
    if should_signal {
        for signal in new_shreds_signals {
            let _ = signal.try_send(true);
        }
    }

    if !completed_slots_senders.is_empty() && !newly_completed_slots.is_empty() {
        let mut slots: Vec<_> = (0..completed_slots_senders.len() - 1)
            .map(|_| newly_completed_slots.clone())
            .collect();

        slots.push(newly_completed_slots);

        for (signal, slots) in completed_slots_senders.iter().zip(slots.into_iter()) {
            let res = signal.try_send(slots);
            if let Err(TrySendError::Full(_)) = res {
                datapoint_error!(
                    "blockstore_error",
                    (
                        "error",
                        "Unable to send newly completed slot because channel is full",
                        String
                    ),
                );
            }
        }
    }
}

/// 获取index_working_set 中 ShredCommonHeader中的slot对应的IndexMetaWorkingSetEntry，
/// 如果没有则从数据库中获取；若数据库中没有，则在该slot处新建一个默认的IndexMetaWorkingSetEntry
fn get_index_meta_entry<'a>(
    db: &Database,
    slot: Slot, // ShredCommonHeader中的slot
    index_working_set: &'a mut HashMap<u64, IndexMetaWorkingSetEntry>, // 输入的空hashmap
    index_meta_time: &mut u64, // 0 
) -> &'a mut IndexMetaWorkingSetEntry {
    // 读取Index列
    let index_cf = db.column::<cf::Index>();
    let mut total_start = Measure::start("Total elapsed");
    let res = index_working_set.entry(slot).or_insert_with(|| {
        let newly_inserted_meta = index_cf
            .get(slot)
            .unwrap()
            .unwrap_or_else(|| Index::new(slot));
        IndexMetaWorkingSetEntry {
            index: newly_inserted_meta,
            did_insert_occur: false,
        }
    });
    total_start.stop();
    *index_meta_time += total_start.as_us();
    res
}

/// 检查是否已经将这个分片的slot元数据插入到数据库中，取没插入数据库中的数据
fn get_slot_meta_entry<'a>(
    db: &Database,
    slot_meta_working_set: &'a mut HashMap<u64, SlotMetaWorkingSetEntry>,
    slot: Slot,
    parent_slot: Slot,
) -> &'a mut SlotMetaWorkingSetEntry {
    // 取数据库中SlotMeta列数据
    let meta_cf = db.column::<cf::SlotMeta>();

    // Check if we've already inserted the slot metadata for this shred's slot
    slot_meta_working_set.entry(slot).or_insert_with(|| {
        // Store a 2-tuple of the metadata (working copy, backup copy)
        // 从数据库中获取slot键值对应的数据
        if let Some(mut meta) = meta_cf.get(slot).expect("Expect database get to succeed") {
            // 复制数据，作为备份
            let backup = Some(meta.clone());
            // If parent_slot == None, then this is one of the orphans inserted
            // during the chaining process, see the function find_slot_meta_in_cached_state()
            // for details. Slots that are orphans are missing a parent_slot, so we should
            // fill in the parent now that we know it.
            
            // 如果meta数据没有父slot，将输入的父slot赋给meta数据
            if is_orphan(&meta) {
                meta.parent_slot = Some(parent_slot);
            }
            // 建立SlotMetaWorkingSetEntry
            SlotMetaWorkingSetEntry::new(Rc::new(RefCell::new(meta)), backup)
        } else {
            SlotMetaWorkingSetEntry::new(
                Rc::new(RefCell::new(SlotMeta::new(slot, Some(parent_slot)))),
                None,
            )
        }
    })
}

pub fn verify_shred_slots(slot: Slot, parent_slot: Slot, last_root: Slot) -> bool {
    if !is_valid_write_to_slot_0(slot, parent_slot, last_root) {
        // Check that the parent_slot < slot
        if parent_slot >= slot {
            return false;
        }

        // Ignore shreds that chain to slots before the last root
        if parent_slot < last_root {
            return false;
        }

        // Above two checks guarantee that by this point, slot > last_root
    }

    true
}

pub fn entries_to_test_shreds(
    entries: Vec<Entry>,
    slot: Slot,
    parent_slot: Slot,
    is_full_slot: bool,
    version: u16,
) -> Vec<Shred> {
    Shredder::new(slot, parent_slot, 0, version)
        .unwrap()
        .entries_to_shreds(
            &Keypair::new(),
            &entries,
            is_full_slot,
            0, // next_shred_index,
            0, // next_code_index
        )
        .0
}

fn update_slot_meta(
    is_last_in_slot: bool,
    is_last_in_data: bool,
    slot_meta: &mut SlotMeta,
    index: u32,
    new_consumed: u64,
    reference_tick: u8,
    received_data_shreds: &ShredIndex,
) -> Vec<(u32, u32)> {
    let maybe_first_insert = slot_meta.received == 0;
    // Index is zero-indexed, while the "received" height starts from 1,
    // so received = index + 1 for the same shred.
    slot_meta.received = cmp::max(u64::from(index) + 1, slot_meta.received);
    if maybe_first_insert && slot_meta.received > 0 {
        // predict the timestamp of what would have been the first shred in this slot
        let slot_time_elapsed = u64::from(reference_tick) * 1000 / DEFAULT_TICKS_PER_SECOND;
        slot_meta.first_shred_timestamp = timestamp() - slot_time_elapsed;
    }
    slot_meta.consumed = new_consumed;
    // If the last index in the slot hasn't been set before, then
    // set it to this shred index
    if is_last_in_slot && slot_meta.last_index.is_none() {
        slot_meta.last_index = Some(u64::from(index));
    }
    update_completed_data_indexes(
        is_last_in_slot || is_last_in_data,
        index,
        received_data_shreds,
        &mut slot_meta.completed_data_indexes,
    )
}

fn is_orphan(meta: &SlotMeta) -> bool {
    // If we have no parent, then this is the head of a detached chain of
    // slots
    meta.parent_slot.is_none()
}

fn is_newly_completed_slot(slot_meta: &SlotMeta, backup_slot_meta: &Option<SlotMeta>) -> bool {
    slot_meta.is_full()
        && (backup_slot_meta.is_none()
            || slot_meta.consumed != backup_slot_meta.as_ref().unwrap().consumed)
}

fn handle_chaining_for_slot(
    db: &Database,
    write_batch: &mut WriteBatch,
    working_set: &HashMap<u64, SlotMetaWorkingSetEntry>,
    new_chained_slots: &mut HashMap<u64, Rc<RefCell<SlotMeta>>>,
    slot: Slot,
) -> Result<()> {
    let slot_meta_entry = working_set
        .get(&slot)
        .expect("Slot must exist in the working_set hashmap");

    let meta = &slot_meta_entry.new_slot_meta;
    let meta_backup = &slot_meta_entry.old_slot_meta;

    {
        let mut meta_mut = meta.borrow_mut();
        let was_orphan_slot = meta_backup.is_some() && is_orphan(meta_backup.as_ref().unwrap());

        // If:
        // 1) This is a new slot
        // 2) slot != 0
        // then try to chain this slot to a previous slot
        if slot != 0 && meta_mut.parent_slot.is_some() {
            let prev_slot = meta_mut.parent_slot.unwrap();

            // Check if the slot represented by meta_mut is either a new slot or a orphan.
            // In both cases we need to run the chaining logic b/c the parent on the slot was
            // previously unknown.
            if meta_backup.is_none() || was_orphan_slot {
                let prev_slot_meta =
                    find_slot_meta_else_create(db, working_set, new_chained_slots, prev_slot)?;

                // This is a newly inserted slot/orphan so run the chaining logic to link it to a
                // newly discovered parent
                chain_new_slot_to_prev_slot(&mut prev_slot_meta.borrow_mut(), slot, &mut meta_mut);

                // If the parent of `slot` is a newly inserted orphan, insert it into the orphans
                // column family
                if is_orphan(&RefCell::borrow(&*prev_slot_meta)) {
                    write_batch.put::<cf::Orphans>(prev_slot, &true)?;
                }
            }
        }

        // At this point this slot has received a parent, so it's no longer an orphan
        if was_orphan_slot {
            write_batch.delete::<cf::Orphans>(slot)?;
        }
    }

    // If this is a newly inserted slot, then we know the children of this slot were not previously
    // connected to the trunk of the ledger. Thus if slot.is_connected is now true, we need to
    // update all child slots with `is_connected` = true because these children are also now newly
    // connected to trunk of the ledger
    let should_propagate_is_connected =
        is_newly_completed_slot(&RefCell::borrow(meta), meta_backup)
            && RefCell::borrow(meta).is_connected;

    if should_propagate_is_connected {
        // slot_function returns a boolean indicating whether to explore the children
        // of the input slot
        let slot_function = |slot: &mut SlotMeta| {
            slot.is_connected = true;

            // We don't want to set the is_connected flag on the children of non-full
            // slots
            slot.is_full()
        };

        traverse_children_mut(
            db,
            slot,
            meta,
            working_set,
            new_chained_slots,
            slot_function,
        )?;
    }

    Ok(())
}

fn slot_has_updates(slot_meta: &SlotMeta, slot_meta_backup: &Option<SlotMeta>) -> bool {
    // We should signal that there are updates if we extended the chain of consecutive blocks starting
    // from block 0, which is true iff:
    // 1) The block with index prev_block_index is itself part of the trunk of consecutive blocks
    // starting from block 0,
    slot_meta.is_connected &&
        // AND either:
        // 1) The slot didn't exist in the database before, and now we have a consecutive
        // block for that slot
        ((slot_meta_backup.is_none() && slot_meta.consumed != 0) ||
        // OR
        // 2) The slot did exist, but now we have a new consecutive block for that slot
        (slot_meta_backup.is_some() && slot_meta_backup.as_ref().unwrap().consumed != slot_meta.consumed))
}

// Update the `completed_data_indexes` with a new shred `new_shred_index`. If a
// data set is complete, return the range of shred indexes [start_index, end_index]
// for that completed data set.
fn update_completed_data_indexes(
    is_last_in_data: bool,
    new_shred_index: u32,
    received_data_shreds: &ShredIndex,
    // Shreds indices which are marked data complete.
    completed_data_indexes: &mut BTreeSet<u32>,
) -> Vec<(u32, u32)> {
    let start_shred_index = completed_data_indexes
        .range(..new_shred_index)
        .next_back()
        .map(|index| index + 1)
        .unwrap_or_default();
    // Consecutive entries i, k, j in this vector represent potential ranges [i, k),
    // [k, j) that could be completed data ranges
    let mut shred_indices = vec![start_shred_index];
    // `new_shred_index` is data complete, so need to insert here into the
    // `completed_data_indexes`
    if is_last_in_data {
        completed_data_indexes.insert(new_shred_index);
        shred_indices.push(new_shred_index + 1);
    }
    if let Some(index) = completed_data_indexes.range(new_shred_index + 1..).next() {
        shred_indices.push(index + 1);
    }
    shred_indices
        .windows(2)
        .filter(|ix| {
            let (begin, end) = (ix[0] as u64, ix[1] as u64);
            let num_shreds = (end - begin) as usize;
            received_data_shreds.range(begin..end).count() == num_shreds
        })
        .map(|ix| (ix[0], ix[1] - 1))
        .collect()
}

fn is_valid_write_to_slot_0(slot_to_write: u64, parent_slot: Slot, last_root: u64) -> bool {
    slot_to_write == 0 && last_root == 0 && parent_slot == 0
}

// 1) Find the slot metadata in the cache of dirty slot metadata we've previously touched,
// else:
// 2) Search the database for that slot metadata. If still no luck, then:
// 3) Create a dummy orphan slot in the database
fn find_slot_meta_else_create<'a>(
    db: &Database,
    working_set: &'a HashMap<u64, SlotMetaWorkingSetEntry>,
    chained_slots: &'a mut HashMap<u64, Rc<RefCell<SlotMeta>>>,
    slot_index: u64,
) -> Result<Rc<RefCell<SlotMeta>>> {
    let result = find_slot_meta_in_cached_state(working_set, chained_slots, slot_index);
    if let Some(slot) = result {
        Ok(slot)
    } else {
        find_slot_meta_in_db_else_create(db, slot_index, chained_slots)
    }
}

// 1) Chain current_slot to the previous slot defined by prev_slot_meta
// 2) Determine whether to set the is_connected flag
fn chain_new_slot_to_prev_slot(
    prev_slot_meta: &mut SlotMeta,
    current_slot: Slot,
    current_slot_meta: &mut SlotMeta,
) {
    prev_slot_meta.next_slots.push(current_slot);
    current_slot_meta.is_connected = prev_slot_meta.is_connected && prev_slot_meta.is_full();
}

fn traverse_children_mut<F>(
    db: &Database,
    slot: Slot,
    slot_meta: &Rc<RefCell<SlotMeta>>,
    working_set: &HashMap<u64, SlotMetaWorkingSetEntry>,
    new_chained_slots: &mut HashMap<u64, Rc<RefCell<SlotMeta>>>,
    slot_function: F,
) -> Result<()>
where
    F: Fn(&mut SlotMeta) -> bool,
{
    let mut next_slots: Vec<(u64, Rc<RefCell<SlotMeta>>)> = vec![(slot, slot_meta.clone())];
    while !next_slots.is_empty() {
        let (_, current_slot) = next_slots.pop().unwrap();
        // Check whether we should explore the children of this slot
        if slot_function(&mut current_slot.borrow_mut()) {
            let current_slot = &RefCell::borrow(&*current_slot);
            for next_slot_index in current_slot.next_slots.iter() {
                let next_slot = find_slot_meta_else_create(
                    db,
                    working_set,
                    new_chained_slots,
                    *next_slot_index,
                )?;
                next_slots.push((*next_slot_index, next_slot));
            }
        }
    }

    Ok(())
}

// Search the database for that slot metadata. If still no luck, then
// create a dummy orphan slot in the database
fn find_slot_meta_in_db_else_create(
    db: &Database,
    slot: Slot,
    insert_map: &mut HashMap<u64, Rc<RefCell<SlotMeta>>>,
) -> Result<Rc<RefCell<SlotMeta>>> {
    if let Some(slot_meta) = db.column::<cf::SlotMeta>().get(slot)? {
        insert_map.insert(slot, Rc::new(RefCell::new(slot_meta)));
    } else {
        // If this slot doesn't exist, make a orphan slot. This way we
        // remember which slots chained to this one when we eventually get a real shred
        // for this slot
        insert_map.insert(slot, Rc::new(RefCell::new(SlotMeta::new_orphan(slot))));
    }
    Ok(insert_map.get(&slot).unwrap().clone())
}

// Find the slot metadata in the cache of dirty slot metadata we've previously touched
fn find_slot_meta_in_cached_state<'a>(
    working_set: &'a HashMap<u64, SlotMetaWorkingSetEntry>,
    chained_slots: &'a HashMap<u64, Rc<RefCell<SlotMeta>>>,
    slot: Slot,
) -> Option<Rc<RefCell<SlotMeta>>> {
    if let Some(entry) = working_set.get(&slot) {
        Some(entry.new_slot_meta.clone())
    } else {
        chained_slots.get(&slot).cloned()
    }
}