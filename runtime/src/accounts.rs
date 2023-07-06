use {
    crate::{
        accounts_db::{
            AccountsDb,
        },
    },

    sdk::{
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

pub enum AccountAddressFilter {
    Exclude, // exclude all addresses matching the filter
    Include, // only include addresses matching the filter
}