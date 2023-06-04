//! Persistent storage for accounts.
//!
//! For more information, see:
//!
//! <https://docs.solana.com/implemented-proposals/persistent-account-storage>

use {
    log::*,
    memmap2::MmapMut,
    serde::{Deserialize, Serialize},
    sdk::{
        account::{Account, AccountSharedData, ReadableAccount},
        clock::{Epoch, Slot},
        hash::Hash,
        pubkey::Pubkey,
    },
    std::{
        borrow::Borrow,
        convert::TryFrom,
        fs::{remove_file, OpenOptions},
        io::{self, Seek, SeekFrom, Write},
        mem,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        },
    },
};

/// A thread-safe, file-backed block of memory used to store `Account` instances. Append operations
/// are serialized such that only one thread updates the internal `append_lock` at a time. No
/// restrictions are placed on reading. That is, one may read items from one thread while another
/// is appending new items.
#[derive(Debug, AbiExample)]
pub struct AppendVec {
    /// The file path where the data is stored.
    path: PathBuf,

    /// A file-backed block of memory that is used to store the data for each appended item.
    map: MmapMut,

    /// A lock used to serialize append operations.
    append_lock: Mutex<()>,

    /// The number of bytes used to store items, not the number of items.
    current_len: AtomicUsize,

    /// The number of bytes available for storing items.
    file_size: u64,

    /// True if the file should automatically be deleted when this AppendVec is dropped.
    remove_on_drop: bool,
}

/// References to account data stored elsewhere. Getting an `Account` requires cloning
/// (see `StoredAccountMeta::clone_account()`).
#[derive(PartialEq, Debug)]
pub struct StoredAccountMeta<'a> {
    pub meta: &'a StoredMeta,
    /// account data
    pub account_meta: &'a AccountMeta,
    pub data: &'a [u8],
    pub offset: usize,
    pub stored_size: usize,
    pub hash: &'a Hash,
}

pub type StoredMetaWriteVersion = u64;
/// Meta contains enough context to recover the index from storage itself
/// This struct will be backed by mmaped and snapshotted data files.
/// So the data layout must be stable and consistent across the entire cluster!
#[derive(Clone, PartialEq, Debug)]
pub struct StoredMeta {
    /// global write version
    pub write_version: StoredMetaWriteVersion,
    /// key for the account
    pub pubkey: Pubkey,
    pub data_len: u64,
}

/// This struct will be backed by mmaped and snapshotted data files.
/// So the data layout must be stable and consistent across the entire cluster!
#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct AccountMeta {
    /// lamports in the account
    pub lamports: u64,
    /// the program that owns this account. If executable, the program that loads this account.
    pub owner: Pubkey,
    /// this account's data contains a loaded program (and is now read-only)
    pub executable: bool,
    /// the epoch at which this account will next owe rent
    pub rent_epoch: Epoch,
}