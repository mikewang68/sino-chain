use {
    crate::{
        accounts_db::{
            /*AccountShrinkThreshold, AccountsAddRootTiming, AccountsDb, AccountsDbConfig,*/
            /*BankHashInfo,*/ LoadHint, /*LoadedAccount, ScanStorageResult,*/
            /*ACCOUNTS_DB_CONFIG_FOR_BENCHMARKS, ACCOUNTS_DB_CONFIG_FOR_TESTING,*/
        },
        accounts_db::{
            AccountsDb,
        },
        ancestors::Ancestors,
    },

    sdk::{
        clock::{BankId, Slot, INITIAL_RENT_EPOCH},
        account::{Account, AccountSharedData, ReadableAccount, WritableAccount},
        pubkey::Pubkey,
    },

    std::{
        collections::{HashMap, HashSet},
        sync::{
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