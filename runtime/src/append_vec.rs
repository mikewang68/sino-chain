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

// Data placement should be aligned at the next boundary. Without alignment accessing the memory may
// crash on some architectures.
const ALIGN_BOUNDARY_OFFSET: usize = mem::size_of::<u64>();
macro_rules! u64_align {
    ($addr: expr) => {
        ($addr + (ALIGN_BOUNDARY_OFFSET - 1)) & !(ALIGN_BOUNDARY_OFFSET - 1)
    };
}

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

impl AppendVec {

    pub fn flush(&self) -> io::Result<()> {
        self.map.flush()
    }

    pub fn get_path(&self) -> PathBuf {
        self.path.clone()
    }

    pub fn file_name(slot: Slot, id: usize) -> String {
        format!("{}.{}", slot, id)
    }

    /// Return account metadata for the account at `offset` if its data doesn't overrun
    /// the internal buffer. Otherwise return None. Also return the offset of the first byte
    /// after the requested data that falls on a 64-byte boundary.
    pub fn get_account<'a>(&'a self, offset: usize) -> Option<(StoredAccountMeta<'a>, usize)> {
        let (meta, next): (&'a StoredMeta, _) = self.get_type(offset)?;
        let (account_meta, next): (&'a AccountMeta, _) = self.get_type(next)?;
        let (hash, next): (&'a Hash, _) = self.get_type(next)?;
        let (data, next) = self.get_slice(next, meta.data_len as usize)?;
        let stored_size = next - offset;
        Some((
            StoredAccountMeta {
                meta,
                account_meta,
                data,
                offset,
                stored_size,
                hash,
            },
            next,
        ))
    }

    /// Return a reference to the type at `offset` if its data doesn't overrun the internal buffer.
    /// Otherwise return None. Also return the offset of the first byte after the requested data
    /// that falls on a 64-byte boundary.
    fn get_type<'a, T>(&self, offset: usize) -> Option<(&'a T, usize)> {
        let (data, next) = self.get_slice(offset, mem::size_of::<T>())?;
        let ptr: *const T = data.as_ptr() as *const T;
        //UNSAFE: The cast is safe because the slice is aligned and fits into the memory
        //and the lifetime of the &T is tied to self, which holds the underlying memory map
        Some((unsafe { &*ptr }, next))
    }

    pub fn len(&self) -> usize {
        self.current_len.load(Ordering::Relaxed)
    }

    /// Get a reference to the data at `offset` of `size` bytes if that slice
    /// doesn't overrun the internal buffer. Otherwise return None.
    /// Also return the offset of the first byte after the requested data that
    /// falls on a 64-byte boundary.
    fn get_slice(&self, offset: usize, size: usize) -> Option<(&[u8], usize)> {
        let (next, overflow) = offset.overflowing_add(size);
        if overflow || next > self.len() {
            return None;
        }
        let data = &self.map[offset..next];
        let next = u64_align!(next);

        Some((
            //UNSAFE: This unsafe creates a slice that represents a chunk of self.map memory
            //The lifetime of this slice is tied to &self, since it points to self.map memory
            unsafe { std::slice::from_raw_parts(data.as_ptr() as *const u8, size) },
            next,
        ))
    }
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

impl<'a> StoredAccountMeta<'a> {
    /// Return a new Account by copying all the data referenced by the `StoredAccountMeta`.
    pub fn clone_account(&self) -> AccountSharedData {
        AccountSharedData::from(Account {
            lamports: self.account_meta.lamports,
            owner: self.account_meta.owner,
            executable: self.account_meta.executable,
            rent_epoch: self.account_meta.rent_epoch,
            data: self.data.to_vec(),
        })
    }
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