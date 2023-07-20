use {
    crate::{
        accounts_db::{
            AccountsAddRootTiming,
            /*AccountShrinkThreshold, AccountsAddRootTiming, AccountsDb, AccountsDbConfig,*/
            /*BankHashInfo,*/ LoadHint, /*LoadedAccount, ScanStorageResult,*/
            /*ACCOUNTS_DB_CONFIG_FOR_BENCHMARKS, ACCOUNTS_DB_CONFIG_FOR_TESTING,*/
        },
        accounts_db::{
            AccountsDb,
        },
        ancestors::Ancestors,
        accounts_index::{AccountIndex, IndexKey, ScanConfig, ScanResult, ScanError},
    },
    sdk::{
        clock::{BankId, Slot, INITIAL_RENT_EPOCH},
        account::{Account, AccountSharedData, ReadableAccount, WritableAccount},
        pubkey::Pubkey,
    },

    std::{
        ops::RangeBounds,
        collections::{HashMap, HashSet},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    },
};

#[derive(Debug, Default, AbiExample)]
pub struct AccountLocks {
    write_locks: HashSet<Pubkey>,
    readonly_locks: HashMap<Pubkey, u64>,
}

/// This structure handles synchronization for db
#[derive(Debug, AbiExample)]
pub struct Accounts {
    /// Single global AccountsDb
    pub accounts_db: Arc<AccountsDb>,

    /// set of read-only and writable accounts which are currently
    /// being processed by banking/replay threads
    pub(crate) account_locks: Mutex<AccountLocks>,
}

impl Accounts{
    /// Add a slot to root.  Root slots cannot be purged
    pub fn add_root(&self, slot: Slot) -> AccountsAddRootTiming {
        self.accounts_db.add_root(slot)
    }

    pub fn store_slow_cached(&self, slot: Slot, pubkey: &Pubkey, account: &AccountSharedData) {
        self.accounts_db.store_cached(slot, &[(pubkey, account)]);
    }

    pub fn load_to_collect_rent_eagerly<R: RangeBounds<Pubkey> + std::fmt::Debug>(
        &self,
        ancestors: &Ancestors,
        range: R,
    ) -> Vec<(Pubkey, AccountSharedData)> {
        self.accounts_db.range_scan_accounts(
            "load_to_collect_rent_eagerly_scan_elapsed",
            ancestors,
            range,
            &ScanConfig::new(true),
            |collector: &mut Vec<(Pubkey, AccountSharedData)>, option| {
                Self::load_while_filtering(collector, option, |_| true)
            },
        )
    }

    pub fn hold_range_in_memory<R>(&self, range: &R, start_holding: bool)
    where
        R: RangeBounds<Pubkey> + std::fmt::Debug,
    {
        self.accounts_db
            .accounts_index
            .hold_range_in_memory(range, start_holding)
    }

    /// Slow because lock is held for 1 operation instead of many.
    /// WARNING: This noncached version is only to be used for tests/benchmarking
    /// as bypassing the cache in general is not supported
    pub fn store_slow_uncached(&self, slot: Slot, pubkey: &Pubkey, account: &AccountSharedData) {
        self.accounts_db.store_uncached(slot, &[(pubkey, account)]);
    }

    pub fn load_by_program(
        &self,
        ancestors: &Ancestors,
        bank_id: BankId,
        program_id: &Pubkey,
        config: &ScanConfig,
    ) -> ScanResult<Vec<(Pubkey, AccountSharedData)>> {
        self.accounts_db.scan_accounts(
            ancestors,
            bank_id,
            |collector: &mut Vec<(Pubkey, AccountSharedData)>, some_account_tuple| {
                Self::load_while_filtering(collector, some_account_tuple, |account| {
                    account.owner() == program_id
                })
            },
            config,
        )
    }

    fn load_while_filtering<F: Fn(&AccountSharedData) -> bool>(
        collector: &mut Vec<(Pubkey, AccountSharedData)>,
        some_account_tuple: Option<(&Pubkey, AccountSharedData, Slot)>,
        filter: F,
    ) {
        if let Some(mapped_account_tuple) = some_account_tuple
            .filter(|(_, account, _)| Self::is_loadable(account.wens()) && filter(account))
            .map(|(pubkey, account, _slot)| (*pubkey, account))
        {
            collector.push(mapped_account_tuple)
        }
    }

    fn is_loadable(lamports: u64) -> bool {
        // Don't ever load zero lamport accounts into runtime because
        // the existence of zero-lamport accounts are never deterministic!!
        lamports > 0
    }

    pub fn load_by_index_key_with_filter<F: Fn(&AccountSharedData) -> bool>(
        &self,
        ancestors: &Ancestors,
        bank_id: BankId,
        index_key: &IndexKey,
        filter: F,
        config: &ScanConfig,
        byte_limit_for_scan: Option<usize>,
    ) -> ScanResult<Vec<(Pubkey, AccountSharedData)>> {
        let sum = AtomicUsize::default();
        let config = ScanConfig {
            abort: Some(config.abort.as_ref().map(Arc::clone).unwrap_or_default()),
            collect_all_unsorted: config.collect_all_unsorted,
        };
        let result = self
            .accounts_db
            .index_scan_accounts(
                ancestors,
                bank_id,
                *index_key,
                |collector: &mut Vec<(Pubkey, AccountSharedData)>, some_account_tuple| {
                    Self::load_while_filtering(collector, some_account_tuple, |account| {
                        let use_account = filter(account);
                        if use_account {
                            if let Some(byte_limit_for_scan) = byte_limit_for_scan.as_ref() {
                                let added = account.data().len()
                                    + std::mem::size_of::<AccountSharedData>()
                                    + std::mem::size_of::<Pubkey>();
                                if sum
                                    .fetch_add(added, Ordering::Relaxed)
                                    .saturating_add(added)
                                    > *byte_limit_for_scan
                                {
                                    // total size of results exceeds size limit, so abort scan
                                    config.abort();
                                }
                            }
                        }
                        use_account
                    });
                },
                &config,
            )
            .map(|result| result.0);
        if config.is_aborted() {
            ScanResult::Err(ScanError::Aborted(
                "The accumulated scan results exceeded the limit".to_string(),
            ))
        } else {
            result
        }
    }

    fn filter_zero_lamport_account(
        account: AccountSharedData,
        slot: Slot,
    ) -> Option<(AccountSharedData, Slot)> {
        if account.wens() > 0 {
            Some((account, slot))
        } else {
            None
        }
    }

    /// Slow because lock is held for 1 operation instead of many
    fn load_slow(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
        load_hint: LoadHint,
    ) -> Option<(AccountSharedData, Slot)> {
        let (account, slot) = self.accounts_db.load(ancestors, pubkey, load_hint)?;
        Self::filter_zero_lamport_account(account, slot)
    }

    pub fn load_with_fixed_root(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
    ) -> Option<(AccountSharedData, Slot)> {
        self.load_slow(ancestors, pubkey, LoadHint::FixedMaxRoot)
    }

    pub fn load_without_fixed_root(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
    ) -> Option<(AccountSharedData, Slot)> {
        self.load_slow(ancestors, pubkey, LoadHint::Unspecified)
    }

    pub(crate) fn new_empty(accounts_db: AccountsDb) -> Self {
        Self {
            accounts_db: Arc::new(accounts_db),
            account_locks: Mutex::new(AccountLocks::default()),
        }
    }

}

pub enum AccountAddressFilter {
    Exclude, // exclude all addresses matching the filter
    Include, // only include addresses matching the filter
}

pub fn create_test_accounts(
    accounts: &Accounts,
    pubkeys: &mut Vec<Pubkey>,
    num: usize,
    slot: Slot,
) {
    for t in 0..num {
        let pubkey = sdk::pubkey::new_rand();
        let account =
            AccountSharedData::new((t + 1) as u64, 0, AccountSharedData::default().owner());
        accounts.store_slow_uncached(slot, &pubkey, &account);
        pubkeys.push(pubkey);
    }
}