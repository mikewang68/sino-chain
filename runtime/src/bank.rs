//! The `bank` module tracks client accounts and the progress of on-chain
//! programs.
//!
//! A single bank relates to a block produced by a single leader and each bank
//! except for the genesis bank points back to a parent bank.
//!
//! The bank is the main entrypoint for processing verified transactions with the function
//! `Bank::process_transactions`
//!
//! It does this by loading the accounts using the reference it holds on the account store,
//! and then passing those to an InvokeContext which handles loading the programs specified
//! by the Transaction and executing it.
//!
//! The bank then stores the results to the accounts store.
//!
//! It then has apis for retrieving if a transaction has been processed and it's status.
//! See `get_signature_status` et al.
//!
//! Bank lifecycle:
//!
//! A bank is newly created and open to transactions. Transactions are applied
//! until either the bank reached the tick count when the node is the leader for that slot, or the
//! node has applied all transactions present in all `Entry`s in the slot.
//!
//! Once it is complete, the bank can then be frozen. After frozen, no more transactions can
//! be applied or state changes made. At the frozen step, rent will be applied and various
//! sysvar special accounts update to the new state of the system.
//!
//! After frozen, and the bank has had the appropriate number of votes on it, then it can become
//! rooted. At this point, it will not be able to be removed from the chain and the
//! state is finalized.
//!
//! It offers a high-level API that signs transactions
//! on behalf of the caller, and a low-level API for when they have
//! already been signed and verified.
#[allow(deprecated)]
// use sdk::{recent_blockhashes_account, recent_evm_blockhashes_account};
use {
    crate::{
        blockhash_queue::{BlockHashEvm, BlockhashQueue},
        accounts::{
            Accounts, 
        },
        accounts_db::{
            /*AccountShrinkThreshold, AccountsDbConfig,*/ SnapshotStorages,
            /*ACCOUNTS_DB_CONFIG_FOR_BENCHMARKS, ACCOUNTS_DB_CONFIG_FOR_TESTING,*/
        },
        ancestors::{Ancestors},
        status_cache::{StatusCache},
        rent_collector::{RentCollector},
        epoch_stakes::{EpochStakes},
        stakes::{StakesCache, Stakes},
        builtins::{BuiltinFeatureTransition},
        cost_tracker::CostTracker,
    },
    program_runtime::{
        compute_budget::{ComputeBudget},
        sysvar_cache::SysvarCache,
        invoke_context::{
            BuiltinProgram, Executor
        },
    },
    log::*,
    measure::measure::Measure,
    itertools::Itertools,
    sdk::{
        account::{
            create_account_shared_data_with_fields as create_account, from_account, Account,
            AccountSharedData, InheritableAccountFields, ReadableAccount, WritableAccount,
        },
        clock::{
            BankId, Epoch, Slot, UnixTimestamp,SlotIndex,
        },
        epoch_schedule::EpochSchedule,
        feature_set::{
             FeatureSet,
        },
        sysvar::{self, Sysvar, SysvarId},
        fee::FeeStructure,
        fee_calculator::{FeeCalculator, FeeRateGovernor},
        genesis_config::{ClusterType},
        hard_forks::HardForks,
        hash::{Hash},
        inflation::Inflation,
        pubkey::Pubkey,
        signature::{Signature},
        transaction::{
            Result
        },
    },
    std::{
        fmt,
        collections::{HashMap, HashSet},
        sync::{
            atomic::{
                AtomicBool, AtomicU64,Ordering::Relaxed
            },
            Arc, RwLock,
        },
    },
};

use crate::{status_cache::SlotDelta, ancestors::AncestorsForSerialization};

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Copy)]
pub enum RewardType {
    Fee,
    Rent,
    Staking,
    Voting,
}

#[derive(Serialize, Deserialize, AbiExample, AbiEnumVisitor, Debug, PartialEq)]
pub enum TransactionLogCollectorFilter {
    All,
    AllWithVotes,
    None,
    OnlyMentionedAddresses,
}

impl Default for TransactionLogCollectorFilter {
    fn default() -> Self {
        Self::None
    }
}

type BankStatusCache = StatusCache<Result<()>>;

/// A list of log messages emitted during a transaction
pub type TransactionLogMessages = Vec<String>;

#[derive(Debug, Default)]
pub struct OptionalDropCallback(Option<Box<dyn DropCallback + Send + Sync>>);

#[cfg(RUSTC_WITH_SPECIALIZATION)]
impl AbiExample for OptionalDropCallback {
    fn example() -> Self {
        Self(None)
    }
}

pub trait DropCallback: fmt::Debug {
    fn callback(&self, b: &Bank);
    fn clone_box(&self) -> Box<dyn DropCallback + Send + Sync>;
}

pub struct TransactionSimulationResult {
    pub result: Result<()>,
    pub logs: TransactionLogMessages,
    pub post_simulation_accounts: Vec<(Pubkey, AccountSharedData)>,
    pub units_consumed: u64,
}

#[derive(AbiExample, Clone, Debug, PartialEq)]
pub struct TransactionLogInfo {
    pub signature: Signature,
    pub result: Result<()>,
    pub is_vote: bool,
    pub log_messages: TransactionLogMessages,
}

#[derive(AbiExample, Default, Debug)]
pub struct TransactionLogCollector {
    // All the logs collected for from this Bank.  Exact contents depend on the
    // active `TransactionLogCollectorFilter`
    pub logs: Vec<TransactionLogInfo>,

    // For each `mentioned_addresses`, maintain a list of indices into `logs` to easily
    // locate the logs from transactions that included the mentioned addresses.
    pub mentioned_address_map: HashMap<Pubkey, Vec<usize>>,
}

impl TransactionLogCollector {
    pub fn get_logs_for_address(
        &self,
        address: Option<&Pubkey>,
    ) -> Option<Vec<TransactionLogInfo>> {
        match address {
            None => Some(self.logs.clone()),
            Some(address) => self.mentioned_address_map.get(address).map(|log_indices| {
                log_indices
                    .iter()
                    .filter_map(|i| self.logs.get(*i).cloned())
                    .collect()
            }),
        }
    }
}


#[derive(AbiExample, Debug, Default)]
pub struct TransactionLogCollectorConfig {
    pub mentioned_addresses: HashSet<Pubkey>,
    pub filter: TransactionLogCollectorFilter,
}

const MAX_CACHED_EXECUTORS: usize = 256;

#[derive(Debug)]
struct CachedExecutorsEntry {
    prev_epoch_count: u64,
    epoch_count: AtomicU64,
    executor: Arc<dyn Executor>,
    hit_count: AtomicU64,
}

impl Clone for CachedExecutorsEntry {
    fn clone(&self) -> Self {
        Self {
            prev_epoch_count: self.prev_epoch_count,
            epoch_count: AtomicU64::new(self.epoch_count.load(Relaxed)),
            executor: self.executor.clone(),
            hit_count: AtomicU64::new(self.hit_count.load(Relaxed)),
        }
    }
}


/// LFU Cache of executors with single-epoch memory of usage counts
#[derive(Debug)]
struct CachedExecutors {
    capacity: usize,
    current_epoch: Epoch,
    pub(self) executors: HashMap<Pubkey, CachedExecutorsEntry>,
    stats: executor_cache::Stats,
}

impl Default for CachedExecutors {
    fn default() -> Self {
        Self {
            capacity: MAX_CACHED_EXECUTORS,
            current_epoch: Epoch::default(),
            executors: HashMap::default(),
            stats: executor_cache::Stats::default(),
        }
    }
}

#[derive(Default, Debug, AbiExample)]
pub struct StatusCacheRc {
    /// where all the Accounts are stored
    /// A cache of signature statuses
    pub status_cache: Arc<RwLock<BankStatusCache>>,
}

impl StatusCacheRc {
    pub fn slot_deltas(&self, slots: &[Slot]) -> Vec<BankSlotDelta> {
        let sc = self.status_cache.read().unwrap();
        sc.slot_deltas(slots)
    }

    pub fn roots(&self) -> Vec<Slot> {
        self.status_cache
            .read()
            .unwrap()
            .roots()
            .iter()
            .cloned()
            .sorted()
            .collect()
    }

}

#[frozen_abi(digest = "HdYCU65Jwfv9sF3C8k6ZmjUAaXSkJwazebuur21v8JtY")]
pub type BankSlotDelta = SlotDelta<Result<()>>;

#[derive(Debug, Clone, Default)]
pub struct BuiltinPrograms {
    pub vec: Vec<BuiltinProgram>,
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
impl AbiExample for BuiltinPrograms {
    fn example() -> Self {
        Self::default()
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, AbiExample, Clone, Copy)]
pub struct RewardInfo {
    pub reward_type: RewardType,
    pub lamports: i64,          // Reward amount
    pub post_balance: u64,      // Account balance in lamports after `lamports` was applied
    pub commission: Option<u8>, // Vote account commission when the reward was credited, only present for voting and staking rewards
}


/// Manager for the state of all accounts and programs after processing its entries.
/// AbiExample is needed even without Serialize/Deserialize; actual (de-)serialization
/// are implemented elsewhere for versioning
#[derive(AbiExample, Debug)]
pub struct Bank {
    /// References to accounts, parent and signature status
    pub rc: BankRc,

    pub src: StatusCacheRc,

    /// FIFO queue of `recent_blockhash` items
    blockhash_queue: RwLock<BlockhashQueue>,

    evm_blockhashes: RwLock<BlockHashEvm>,

    /// The set of parents including this bank
    pub ancestors: Ancestors,

    pub evm_chain_id: u64,
    pub evm_state: RwLock<evm_state::EvmState>,
    pub evm_changed_list: RwLock<Option<(evm_state::H256, evm_state::ChangedState)>>,

    /// Hash of this Bank's state. Only meaningful after freezing.
    hash: RwLock<Hash>,

    /// Hash of this Bank's parent's state
    parent_hash: Hash,

    /// parent's slot
    parent_slot: Slot,

    /// slots to hard fork at
    hard_forks: Arc<RwLock<HardForks>>,

    /// The number of transactions processed without error
    transaction_count: AtomicU64,

    /// The number of transaction errors in this slot
    transaction_error_count: AtomicU64,

    /// The number of transaction entries in this slot
    transaction_entries_count: AtomicU64,

    /// The max number of transaction in an entry in this slot
    transactions_per_entry_max: AtomicU64,

    /// Bank tick height
    tick_height: AtomicU64,

    /// The number of signatures from valid transactions in this slot
    signature_count: AtomicU64,

    /// Total capitalization, used to calculate inflation
    capitalization: AtomicU64,

    // Bank max_tick_height
    max_tick_height: u64,

    /// The number of hashes in each tick. None value means hashing is disabled.
    hashes_per_tick: Option<u64>,

    /// The number of ticks in each slot.
    ticks_per_slot: u64,

    /// length of a slot in ns
    pub ns_per_slot: u128,

    /// genesis time, used for computed clock
    genesis_creation_time: UnixTimestamp,

    /// The number of slots per year, used for inflation
    slots_per_year: f64,

    /// Bank slot (i.e. block)
    slot: Slot,

    bank_id: BankId,

    /// Bank epoch
    epoch: Epoch,

    /// Bank block_height
    block_height: u64,

    /// The pubkey to send transactions fees to.
    collector_id: Pubkey,

    /// Fees that have been collected
    collector_fees: AtomicU64,

    /// Deprecated, do not use
    /// Latest transaction fees for transactions processed by this bank
    fee_calculator: FeeCalculator,

    /// Track cluster signature throughput and adjust fee rate
    fee_rate_governor: FeeRateGovernor,

    /// Rent that has been collected
    collected_rent: AtomicU64,

    /// latest rent collector, knows the epoch
    rent_collector: RentCollector,

    /// initialized from genesis
    epoch_schedule: EpochSchedule,

    /// inflation specs
    inflation: Arc<RwLock<Inflation>>,

    /// cache of vote_account and stake_account state for this fork
    stakes_cache: StakesCache,

    /// staked nodes on epoch boundaries, saved off when a bank.slot() is at
    ///   a leader schedule calculation boundary
    epoch_stakes: HashMap<Epoch, EpochStakes>,

    /// A boolean reflecting whether any entries were recorded into the PoH
    /// stream for the slot == self.slot
    is_delta: AtomicBool,

    /// The builtin programs
    builtin_programs: BuiltinPrograms,

    compute_budget: Option<ComputeBudget>,

    /// Dynamic feature transitions for builtin programs
    #[allow(clippy::rc_buffer)]
    builtin_feature_transitions: Arc<Vec<BuiltinFeatureTransition>>,

    /// Protocol-level rewards that were distributed by this bank
    pub rewards: RwLock<Vec<(Pubkey, RewardInfo)>>,

    pub cluster_type: Option<ClusterType>,

    pub lazy_rent_collection: AtomicBool,

    // this is temporary field only to remove rewards_pool entirely
    pub rewards_pool_pubkeys: Arc<HashSet<Pubkey>>,

    /// Cached executors
    cached_executors: RwLock<CachedExecutors>,

    transaction_debug_keys: Option<Arc<HashSet<Pubkey>>>,

    // Global configuration for how transaction logs should be collected across all banks
    pub transaction_log_collector_config: Arc<RwLock<TransactionLogCollectorConfig>>,

    // Logs from transactions that this Bank executed collected according to the criteria in
    // `transaction_log_collector_config`
    pub transaction_log_collector: Arc<RwLock<TransactionLogCollector>>,

    pub feature_set: Arc<FeatureSet>,

    pub drop_callback: RwLock<OptionalDropCallback>,

    pub freeze_started: AtomicBool,

    vote_only_bank: bool,

    pub cost_tracker: RwLock<CostTracker>,

    sysvar_cache: RwLock<SysvarCache>,

    /// Current size of the accounts data.  Used when processing messages to enforce a limit on its
    /// maximum size.
    accounts_data_len: AtomicU64,

    /// Transaction fee structure
    pub fee_structure: FeeStructure,
}

impl Bank {
    /// given a slot, return the epoch and offset into the epoch this slot falls
    /// e.g. with a fixed number for slots_per_epoch, the calculation is simply:
    ///
    ///  ( slot/slots_per_epoch, slot % slots_per_epoch )
    ///
    pub fn get_epoch_and_slot_index(&self, slot: Slot) -> (Epoch, SlotIndex) {
        self.epoch_schedule.get_epoch_and_slot_index(slot)
    }

    pub fn epoch_staked_nodes(&self, epoch: Epoch) -> Option<Arc<HashMap<Pubkey, u64>>> {
        Some(self.epoch_stakes.get(&epoch)?.stakes().staked_nodes())
    }

    /// Return the number of slots per epoch for the given epoch
    pub fn get_slots_in_epoch(&self, epoch: Epoch) -> u64 {
        self.epoch_schedule.get_slots_in_epoch(epoch)
    }

    /// Return the block_height of this bank
    pub fn block_height(&self) -> u64 {
        self.block_height
    }

    /// Return the total capitalization of the Bank
    pub fn capitalization(&self) -> u64 {
        self.capitalization.load(Relaxed)
    }

    pub fn cluster_type(&self) -> ClusterType {
        // unwrap is safe; self.cluster_type is ensured to be Some() always...
        // we only using Option here for ABI compatibility...
        self.cluster_type.unwrap()
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn get_account_modified_slot(&self, pubkey: &Pubkey) -> Option<(AccountSharedData, Slot)> {
        self.load_slow(&self.ancestors, pubkey)
    }

    // Hi! leaky abstraction here....
    // try to use get_account_with_fixed_root() if it's called ONLY from on-chain runtime account
    // processing. That alternative fn provides more safety.
    pub fn get_account(&self, pubkey: &Pubkey) -> Option<AccountSharedData> {
        self.get_account_modified_slot(pubkey)
            .map(|(acc, _slot)| acc)
    }

    pub fn read_balance(account: &AccountSharedData) -> u64 {
        account.wens()
    }

    /// Each program would need to be able to introspect its own state
    /// this is hard-coded to the Budget language
    pub fn get_balance(&self, pubkey: &Pubkey) -> u64 {
        self.get_account(pubkey)
            .map(|x| Self::read_balance(&x))
            .unwrap_or(0)
    }


    // pub fn clock(&self) -> sysvar::clock::Clock {
    //     from_account(&self.get_account(&sysvar::clock::id()).unwrap_or_default())
    //         .unwrap_or_default()
    // }

    // Hi! leaky abstraction here....
    // try to use get_account_with_fixed_root() if it's called ONLY from on-chain runtime account
    // processing. That alternative fn provides more safety.
    // pub fn get_account(&self, pubkey: &Pubkey) -> Option<AccountSharedData> {
    //     self.get_account_modified_slot(pubkey)
    //         .map(|(acc, _slot)| acc)
    // }

    // Hi! leaky abstraction here....
    // use this over get_account() if it's called ONLY from on-chain runtime account
    // processing (i.e. from in-band replay/banking stage; that ensures root is *fixed* while
    // running).
    // pro: safer assertion can be enabled inside AccountsDb
    // con: panics!() if called from off-chain processing
    // pub fn get_account_with_fixed_root(&self, pubkey: &Pubkey) -> Option<AccountSharedData> {
    //     self.load_slow_with_fixed_root(&self.ancestors, pubkey)
    //         .map(|(acc, _slot)| acc)
    // }

    // pub fn get_account_modified_slot(&self, pubkey: &Pubkey) -> Option<(AccountSharedData, Slot)> {
    //     self.load_slow(&self.ancestors, pubkey)
    // }

    fn load_slow(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
    ) -> Option<(AccountSharedData, Slot)> {
        // get_account (= primary this fn caller) may be called from on-chain Bank code even if we
        // try hard to use get_account_with_fixed_root for that purpose...
        // so pass safer LoadHint:Unspecified here as a fallback
        self.rc.accounts.load_without_fixed_root(ancestors, pubkey)
    }

    fn load_slow_with_fixed_root(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
    ) -> Option<(AccountSharedData, Slot)> {
        self.rc.accounts.load_with_fixed_root(ancestors, pubkey)
    }

    pub fn is_complete(&self) -> bool {
        self.tick_height() == self.max_tick_height()
    }

    /// used only by filler accounts in debug path
    /// previous means slot - 1, not parent
    pub fn variable_cycle_partition_from_previous_slot(
        epoch_schedule: &EpochSchedule,
        slot: Slot,
    ) -> Partition {
        // similar code to Bank::variable_cycle_partitions
        let (current_epoch, current_slot_index) = epoch_schedule.get_epoch_and_slot_index(slot);
        let (parent_epoch, mut parent_slot_index) =
            epoch_schedule.get_epoch_and_slot_index(slot.saturating_sub(1));
        let cycle_params = Self::rent_single_epoch_collection_cycle_params(
            current_epoch,
            epoch_schedule.get_slots_in_epoch(current_epoch),
        );

        if parent_epoch < current_epoch {
            parent_slot_index = 0;
        }

        let generated_for_gapped_epochs = false;
        Self::get_partition_from_slot_indexes(
            cycle_params,
            parent_slot_index,
            current_slot_index,
            generated_for_gapped_epochs,
        )
    }

    // Mostly, the pair (start_index & end_index) is equivalent to this range:
    // start_index..=end_index. But it has some exceptional cases, including
    // this important and valid one:
    //   0..=0: the first partition in the new epoch when crossing epochs
    pub fn pubkey_range_from_partition(
        (start_index, end_index, partition_count): Partition,
    ) -> RangeInclusive<Pubkey> {
        assert!(start_index <= end_index);
        assert!(start_index < partition_count);
        assert!(end_index < partition_count);
        assert!(0 < partition_count);

        type Prefix = u64;
        const PREFIX_SIZE: usize = mem::size_of::<Prefix>();
        const PREFIX_MAX: Prefix = Prefix::max_value();

        let mut start_pubkey = [0x00u8; 32];
        let mut end_pubkey = [0xffu8; 32];

        if partition_count == 1 {
            assert_eq!(start_index, 0);
            assert_eq!(end_index, 0);
            return Pubkey::new_from_array(start_pubkey)..=Pubkey::new_from_array(end_pubkey);
        }

        // not-overflowing way of `(Prefix::max_value() + 1) / partition_count`
        let partition_width = (PREFIX_MAX - partition_count + 1) / partition_count + 1;
        let mut start_key_prefix = if start_index == 0 && end_index == 0 {
            0
        } else if start_index + 1 == partition_count {
            PREFIX_MAX
        } else {
            (start_index + 1) * partition_width
        };

        let mut end_key_prefix = if end_index + 1 == partition_count {
            PREFIX_MAX
        } else {
            (end_index + 1) * partition_width - 1
        };

        if start_index != 0 && start_index == end_index {
            // n..=n (n != 0): a noop pair across epochs without a gap under
            // multi_epoch_cycle, just nullify it.
            if end_key_prefix == PREFIX_MAX {
                start_key_prefix = end_key_prefix;
                start_pubkey = end_pubkey;
            } else {
                end_key_prefix = start_key_prefix;
                end_pubkey = start_pubkey;
            }
        }

        start_pubkey[0..PREFIX_SIZE].copy_from_slice(&start_key_prefix.to_be_bytes());
        end_pubkey[0..PREFIX_SIZE].copy_from_slice(&end_key_prefix.to_be_bytes());
        trace!(
            "pubkey_range_from_partition: ({}-{})/{} [{}]: {}-{}",
            start_index,
            end_index,
            partition_count,
            (end_key_prefix - start_key_prefix),
            start_pubkey.iter().map(|x| format!("{:02x}", x)).join(""),
            end_pubkey.iter().map(|x| format!("{:02x}", x)).join(""),
        );
        // should be an inclusive range (a closed interval) like this:
        // [0xgg00-0xhhff], [0xii00-0xjjff], ... (where 0xii00 == 0xhhff + 1)
        Pubkey::new_from_array(start_pubkey)..=Pubkey::new_from_array(end_pubkey)
    }

    /// Return the number of ticks since genesis.
    pub fn tick_height(&self) -> u64 {
        self.tick_height.load(Relaxed)
    }

    /// Return this bank's max_tick_height
    pub fn max_tick_height(&self) -> u64 {
        self.max_tick_height
    }

    // /// squash the parent's state up into this Bank,
    // ///   this Bank becomes a root
    // pub fn squash(&self) -> SquashTiming {
    //     self.freeze();

    //     //this bank and all its parents are now on the rooted path
    //     let mut roots = vec![self.slot()];
    //     roots.append(&mut self.parents().iter().map(|p| p.slot()).collect());

    //     let mut total_index_us = 0;
    //     let mut total_cache_us = 0;
    //     let mut total_store_us = 0;

    //     let mut squash_accounts_time = Measure::start("squash_accounts_time");
    //     for slot in roots.iter().rev() {
    //         // root forks cannot be purged
    //         let add_root_timing = self.rc.accounts.add_root(*slot);
    //         total_index_us += add_root_timing.index_us;
    //         total_cache_us += add_root_timing.cache_us;
    //         total_store_us += add_root_timing.store_us;
    //     }
    //     squash_accounts_time.stop();

    //     *self.rc.parent.write().unwrap() = None;

    //     let mut squash_cache_time = Measure::start("squash_cache_time");
    //     roots
    //         .iter()
    //         .for_each(|slot| self.src.status_cache.write().unwrap().add_root(*slot));
    //     squash_cache_time.stop();

    //     SquashTiming {
    //         squash_accounts_ms: squash_accounts_time.as_ms(),
    //         squash_accounts_index_ms: total_index_us / 1000,
    //         squash_accounts_cache_ms: total_cache_us / 1000,
    //         squash_accounts_store_ms: total_store_us / 1000,

    //         squash_cache_ms: squash_cache_time.as_ms(),
    //     }
    // }

    pub fn get_snapshot_storages(&self, base_slot: Option<Slot>) -> SnapshotStorages {
        self.rc
            .accounts
            .accounts_db
            .get_snapshot_storages(self.slot(), base_slot, None)
            .0
    }

    pub fn slot(&self) -> Slot {
        self.slot
    }

    pub fn get_accounts_hash(&self) -> Hash {
        self.rc.accounts.accounts_db.get_accounts_hash(self.slot)
    }
    
    // pub fn clean_accounts(
    //     &self,
    //     skip_last: bool,
    //     is_startup: bool,
    //     last_full_snapshot_slot: Option<Slot>,
    // ) {
    //     // Don't clean the slot we're snapshotting because it may have zero-lamport
    //     // accounts that were included in the bank delta hash when the bank was frozen,
    //     // and if we clean them here, any newly created snapshot's hash for this bank
    //     // may not match the frozen hash.
    //     //
    //     // So when we're snapshotting, set `skip_last` to true so the highest slot to clean is
    //     // lowered by one.
    //     let highest_slot_to_clean = skip_last.then(|| self.slot().saturating_sub(1));

    //     self.rc.accounts.accounts_db.clean_accounts(
    //         highest_slot_to_clean,
    //         is_startup,
    //         last_full_snapshot_slot,
    //     );
    // }

    // /// A snapshot bank should be purged of 0 lamport accounts which are not part of the hash
    // /// calculation and could shield other real accounts.
    // pub fn verify_snapshot_bank(
    //     &self,
    //     test_hash_calculation: bool,
    //     accounts_db_skip_shrink: bool,
    //     last_full_snapshot_slot: Option<Slot>,
    // ) -> bool {
    //     info!("cleaning..");
    //     let mut clean_time = Measure::start("clean");
    //     if self.slot() > 0 {
    //         self.clean_accounts(true, true, last_full_snapshot_slot);
    //     }
    //     clean_time.stop();

    //     self.rc
    //         .accounts
    //         .accounts_db
    //         .accounts_index
    //         .set_startup(true);
    //     let mut shrink_all_slots_time = Measure::start("shrink_all_slots");
    //     if !accounts_db_skip_shrink && self.slot() > 0 {
    //         info!("shrinking..");
    //         self.shrink_all_slots(true, last_full_snapshot_slot);
    //     }
    //     shrink_all_slots_time.stop();

    //     info!("verify_bank_hash..");
    //     let mut verify_time = Measure::start("verify_bank_hash");
    //     let mut verify = self.verify_bank_hash(test_hash_calculation);
    //     verify_time.stop();
    //     self.rc
    //         .accounts
    //         .accounts_db
    //         .accounts_index
    //         .set_startup(false);

    //     info!("verify_hash..");
    //     let mut verify2_time = Measure::start("verify_hash");
    //     // Order and short-circuiting is significant; verify_hash requires a valid bank hash
    //     verify = verify && self.verify_hash();
    //     verify2_time.stop();

    //     datapoint_info!(
    //         "verify_snapshot_bank",
    //         ("clean_us", clean_time.as_us(), i64),
    //         ("shrink_all_slots_us", shrink_all_slots_time.as_us(), i64),
    //         ("verify_bank_hash_us", verify_time.as_us(), i64),
    //         ("verify_hash_us", verify2_time.as_us(), i64),
    //     );

    //     verify
    // }

    // pub fn slot(&self) -> Slot {
    //     self.slot
    // }

}

#[derive(Debug)]
pub struct BankRc {
    /// where all the Accounts are stored
    pub accounts: Arc<Accounts>,

    /// Previous checkpoint of this bank
    pub(crate) parent: RwLock<Option<Arc<Bank>>>,

    /// Current slot
    pub(crate) slot: Slot,

    pub(crate) bank_id_generator: Arc<AtomicU64>,
}

mod executor_cache {
    use super::*;
    use log::*; // 原: use log;

    #[derive(Debug, Default)]
    pub struct Stats {
        pub hits: AtomicU64,
        pub misses: AtomicU64,
        pub evictions: HashMap<Pubkey, u64>,
        pub insertions: AtomicU64,
        pub replacements: AtomicU64,
        pub one_hit_wonders: AtomicU64,
    }

    impl Stats {
        pub fn submit(&self, slot: Slot) {
            let hits = self.hits.load(Relaxed);
            let misses = self.misses.load(Relaxed);
            let insertions = self.insertions.load(Relaxed);
            let replacements = self.replacements.load(Relaxed);
            let one_hit_wonders = self.one_hit_wonders.load(Relaxed);
            let evictions: u64 = self.evictions.values().sum();
            datapoint_info!(
                "bank-executor-cache-stats",
                ("slot", slot, i64),
                ("hits", hits, i64),
                ("misses", misses, i64),
                ("evictions", evictions, i64),
                ("insertions", insertions, i64),
                ("replacements", replacements, i64),
                ("one_hit_wonders", one_hit_wonders, i64),
            );
            debug!(
                "Executor Cache Stats -- Hits: {}, Misses: {}, Evictions: {}, Insertions: {}, Replacements: {}, One-Hit-Wonders: {}",
                hits, misses, evictions, insertions, replacements, one_hit_wonders,
            );
            if log_enabled!(log::Level::Trace) && !self.evictions.is_empty() {
                let mut evictions = self.evictions.iter().collect::<Vec<_>>();
                evictions.sort_by_key(|e| e.1);
                let evictions = evictions
                    .into_iter()
                    .rev()
                    .map(|(program_id, evictions)| {
                        format!("  {:<44}  {}", program_id.to_string(), evictions)
                    })
                    .collect::<Vec<_>>();
                let evictions = evictions.join("\n");
                trace!(
                    "Eviction Details:\n  {:<44}  {}\n{}",
                    "Program",
                    "Count",
                    evictions
                );
            }
        }
    }

}

// Bank's common fields shared by all supported snapshot versions for deserialization.
// Sync fields with BankFieldsToSerialize! This is paired with it.
// All members are made public to remain Bank's members private and to make versioned deserializer workable on this
#[derive(Clone, Debug, Default)]
pub(crate) struct BankFieldsToDeserialize {
    pub(crate) blockhash_queue: BlockhashQueue,
    pub(crate) ancestors: AncestorsForSerialization,
    pub(crate) hash: Hash,
    pub(crate) parent_hash: Hash,
    pub(crate) parent_slot: Slot,
    pub(crate) hard_forks: HardForks,
    pub(crate) transaction_count: u64,
    pub(crate) tick_height: u64,
    pub(crate) signature_count: u64,
    pub(crate) capitalization: u64,
    pub(crate) max_tick_height: u64,
    pub(crate) hashes_per_tick: Option<u64>,
    pub(crate) ticks_per_slot: u64,
    pub(crate) ns_per_slot: u128,
    pub(crate) genesis_creation_time: UnixTimestamp,
    pub(crate) slots_per_year: f64,
    pub(crate) slot: Slot,
    pub(crate) epoch: Epoch,
    pub(crate) block_height: u64,
    pub(crate) collector_id: Pubkey,
    pub(crate) collector_fees: u64,
    pub(crate) fee_calculator: FeeCalculator,
    pub(crate) fee_rate_governor: FeeRateGovernor,
    pub(crate) collected_rent: u64,
    pub(crate) rent_collector: RentCollector,
    pub(crate) epoch_schedule: EpochSchedule,
    pub(crate) inflation: Inflation,
    pub(crate) stakes: Stakes,
    pub(crate) epoch_stakes: HashMap<Epoch, EpochStakes>,
    pub(crate) is_delta: bool,
    pub(crate) evm_chain_id: u64,
    pub(crate) evm_persist_fields: evm_state::EvmPersistState,
    pub(crate) evm_blockhashes: BlockHashEvm,
    pub(crate) accounts_data_len: u64,
}

// This is separated from BankFieldsToDeserialize to avoid cloning by using refs.
// So, sync fields with BankFieldsToDeserialize!
// all members are made public to keep Bank private and to make versioned serializer workable on this
#[derive(Debug)]
pub(crate) struct BankFieldsToSerialize<'a> {
    pub(crate) blockhash_queue: &'a RwLock<BlockhashQueue>,
    pub(crate) ancestors: &'a AncestorsForSerialization,
    pub(crate) hash: Hash,
    pub(crate) parent_hash: Hash,
    pub(crate) parent_slot: Slot,
    pub(crate) hard_forks: &'a RwLock<HardForks>,
    pub(crate) transaction_count: u64,
    pub(crate) tick_height: u64,
    pub(crate) signature_count: u64,
    pub(crate) capitalization: u64,
    pub(crate) max_tick_height: u64,
    pub(crate) hashes_per_tick: Option<u64>,
    pub(crate) ticks_per_slot: u64,
    pub(crate) ns_per_slot: u128,
    pub(crate) genesis_creation_time: UnixTimestamp,
    pub(crate) slots_per_year: f64,
    pub(crate) slot: Slot,
    pub(crate) epoch: Epoch,
    pub(crate) block_height: u64,
    pub(crate) collector_id: Pubkey,
    pub(crate) collector_fees: u64,
    pub(crate) fee_calculator: FeeCalculator,
    pub(crate) fee_rate_governor: FeeRateGovernor,
    pub(crate) collected_rent: u64,
    pub(crate) rent_collector: RentCollector,
    pub(crate) epoch_schedule: EpochSchedule,
    pub(crate) inflation: Inflation,
    pub(crate) stakes: &'a StakesCache,
    pub(crate) epoch_stakes: &'a HashMap<Epoch, EpochStakes>,
    pub(crate) is_delta: bool,
    pub(crate) evm_chain_id: u64,
    pub(crate) evm_persist_fields: evm_state::EvmPersistState,
    pub(crate) evm_blockhashes: &'a RwLock<BlockHashEvm>,
    pub(crate) accounts_data_len: u64,
}