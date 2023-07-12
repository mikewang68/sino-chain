use {
    crate::{
        accounts_db::{
            AccountsDb,
        },
    },

    sdk::{
        pubkey::Pubkey,
        clock::Slot,
        account::AccountSharedData,
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