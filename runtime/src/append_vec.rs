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

const MAXIMUM_APPEND_VEC_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024; // 16 GiB

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
    /// Copy each account metadata, account and hash to the internal buffer.
    /// Return the starting offset of each account metadata.
    /// After each account is appended, the internal `current_len` is updated
    /// and will be available to other threads.
    pub fn append_accounts(
        &self,
        accounts: &[(StoredMeta, Option<&impl ReadableAccount>)],
        hashes: &[impl Borrow<Hash>],
    ) -> Vec<usize> {
        let _lock = self.append_lock.lock().unwrap();
        let mut offset = self.len();
        let mut rv = Vec::with_capacity(accounts.len());
        for ((stored_meta, account), hash) in accounts.iter().zip(hashes) {
            let meta_ptr = stored_meta as *const StoredMeta;
            let account_meta = AccountMeta::from(*account);
            let account_meta_ptr = &account_meta as *const AccountMeta;
            let data_len = stored_meta.data_len as usize;
            let data_ptr = account
                .map(|account| account.data())
                .unwrap_or_default()
                .as_ptr();
            let hash_ptr = hash.borrow().as_ref().as_ptr();
            let ptrs = [
                (meta_ptr as *const u8, mem::size_of::<StoredMeta>()),
                (account_meta_ptr as *const u8, mem::size_of::<AccountMeta>()),
                (hash_ptr as *const u8, mem::size_of::<Hash>()),
                (data_ptr, data_len),
            ];
            if let Some(res) = self.append_ptrs_locked(&mut offset, &ptrs) {
                rv.push(res)
            } else {
                break;
            }
        }

        // The last entry in this offset needs to be the u64 aligned offset, because that's
        // where the *next* entry will begin to be stored.
        rv.push(u64_align!(offset));

        rv
    }

    /// Copy each value in `vals`, in order, to the first 64-byte boundary after position `offset`.
    /// If there is sufficient space, then update `offset` and the internal `current_len` to the
    /// first byte after the copied data and return the starting position of the copied data.
    /// Otherwise return None and leave `offset` unchanged.
    fn append_ptrs_locked(&self, offset: &mut usize, vals: &[(*const u8, usize)]) -> Option<usize> {
        let mut end = *offset;
        for val in vals {
            end = u64_align!(end);
            end += val.1;
        }

        if (self.file_size as usize) < end {
            return None;
        }

        let pos = u64_align!(*offset);
        for val in vals {
            self.append_ptr(offset, val.0, val.1)
        }
        self.current_len.store(*offset, Ordering::Relaxed);
        Some(pos)
    }

    /// Copy `len` bytes from `src` to the first 64-byte boundary after position `offset` of
    /// the internal buffer. Then update `offset` to the first byte after the copied data.
    fn append_ptr(&self, offset: &mut usize, src: *const u8, len: usize) {
        let pos = u64_align!(*offset);
        let data = &self.map[pos..(pos + len)];
        //UNSAFE: This mut append is safe because only 1 thread can append at a time
        //Mutex<()> guarantees exclusive write access to the memory occupied in
        //the range.
        unsafe {
            let dst = data.as_ptr() as *mut u8;
            std::ptr::copy(src, dst, len);
        };
        *offset = pos + len;
    }

    pub fn reset(&self) {
        // This mutex forces append to be single threaded, but concurrent with reads
        // See UNSAFE usage in `append_ptr`
        let _lock = self.append_lock.lock().unwrap();
        self.current_len.store(0, Ordering::Relaxed);
    }

    pub fn new(file: &Path, create: bool, size: usize) -> Self {
        let initial_len = 0;
        AppendVec::sanitize_len_and_size(initial_len, size).unwrap();

        if create {
            let _ignored = remove_file(file);
        }

        let mut data = OpenOptions::new()
            .read(true)
            .write(true)
            .create(create)
            .open(file)
            .map_err(|e| {
                panic!(
                    "Unable to {} data file {} in current dir({:?}): {:?}",
                    if create { "create" } else { "open" },
                    file.display(),
                    std::env::current_dir(),
                    e
                );
            })
            .unwrap();

        // Theoretical performance optimization: write a zero to the end of
        // the file so that we won't have to resize it later, which may be
        // expensive.
        data.seek(SeekFrom::Start((size - 1) as u64)).unwrap();
        data.write_all(&[0]).unwrap();
        data.seek(SeekFrom::Start(0)).unwrap();
        data.flush().unwrap();

        //UNSAFE: Required to create a Mmap
        let map = unsafe { MmapMut::map_mut(&data) };
        let map = map.unwrap_or_else(|e| {
            error!(
                "Failed to map the data file (size: {}): {}.\n
                    Please increase sysctl vm.max_map_count or equivalent for your platform.",
                size, e
            );
            std::process::exit(1);
        });

        AppendVec {
            path: file.to_path_buf(),
            map,
            // This mutex forces append to be single threaded, but concurrent with reads
            // See UNSAFE usage in `append_ptr`
            append_lock: Mutex::new(()),
            current_len: AtomicUsize::new(initial_len),
            file_size: size as u64,
            remove_on_drop: true,
        }
    }

    pub fn capacity(&self) -> u64 {
        self.file_size
    }

    pub fn flush(&self) -> io::Result<()> {
        self.map.flush()
    }

    pub fn get_path(&self) -> PathBuf {
        self.path.clone()
    }

    pub fn file_name(slot: Slot, id: usize) -> String {
        format!("{}.{}", slot, id)
    }

    /// Return account metadata for each account, starting from `offset`.
    pub fn accounts(&self, mut offset: usize) -> Vec<StoredAccountMeta> {
        let mut accounts = vec![];
        while let Some((account, next)) = self.get_account(offset) {
            accounts.push(account);
            offset = next;
        }
        accounts
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

    pub fn new_from_file<P: AsRef<Path>>(path: P, current_len: usize) -> io::Result<(Self, usize)> {
        let data = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(&path)?;

        let file_size = std::fs::metadata(&path)?.len();
        AppendVec::sanitize_len_and_size(current_len, file_size as usize)?;

        let map = unsafe {
            let result = MmapMut::map_mut(&data);
            if result.is_err() {
                // for vm.max_map_count, error is: {code: 12, kind: Other, message: "Cannot allocate memory"}
                info!("memory map error: {:?}. This may be because vm.max_map_count is not set correctly.", result);
            }
            result?
        };

        let new = AppendVec {
            path: path.as_ref().to_path_buf(),
            map,
            append_lock: Mutex::new(()),
            current_len: AtomicUsize::new(current_len),
            file_size,
            remove_on_drop: true,
        };

        let (sanitized, num_accounts) = new.sanitize_layout_and_length();
        if !sanitized {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "incorrect layout/length/data",
            ));
        }

        Ok((new, num_accounts))
    }

    fn sanitize_len_and_size(current_len: usize, file_size: usize) -> io::Result<()> {
        if file_size == 0 {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("too small file size {} for AppendVec", file_size),
            ))
        } else if usize::try_from(MAXIMUM_APPEND_VEC_FILE_SIZE)
            .map(|max| file_size > max)
            .unwrap_or(true)
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("too large file size {} for AppendVec", file_size),
            ))
        } else if current_len > file_size {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("current_len is larger than file size ({})", file_size),
            ))
        } else {
            Ok(())
        }
    }

    fn sanitize_layout_and_length(&self) -> (bool, usize) {
        let mut offset = 0;

        // This discards allocated accounts immediately after check at each loop iteration.
        //
        // This code should not reuse AppendVec.accounts() method as the current form or
        // extend it to be reused here because it would allow attackers to accumulate
        // some measurable amount of memory needlessly.
        let mut num_accounts = 0;
        while let Some((account, next_offset)) = self.get_account(offset) {
            if !account.sanitize() {
                return (false, num_accounts);
            }
            offset = next_offset;
            num_accounts += 1;
        }
        let aligned_current_len = u64_align!(self.current_len.load(Ordering::Relaxed));

        (offset == aligned_current_len, num_accounts)
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

    fn sanitize(&self) -> bool {
        self.sanitize_executable() && self.sanitize_lamports()
    }

    fn sanitize_executable(&self) -> bool {
        // Sanitize executable to ensure higher 7-bits are cleared correctly.
        self.ref_executable_byte() & !1 == 0
    }

    fn sanitize_lamports(&self) -> bool {
        // Sanitize 0 lamports to ensure to be same as AccountSharedData::default()
        self.account_meta.lamports != 0 || self.clone_account() == AccountSharedData::default()
    }

    fn ref_executable_byte(&self) -> &u8 {
        // Use extra references to avoid value silently clamped to 1 (=true) and 0 (=false)
        // Yes, this really happens; see test_new_from_file_crafted_executable
        let executable_bool: &bool = &self.account_meta.executable;
        // UNSAFE: Force to interpret mmap-backed bool as u8 to really read the actual memory content
        let executable_byte: &u8 = unsafe { &*(executable_bool as *const bool as *const u8) };
        executable_byte
    }
}

pub type StoredMetaWriteVersion = u64;
/// Meta contains enough context to recover the index from storage itself
/// This struct will be backed by mmaped and snapshotted data files.
/// So the data layout must be stable and consistent across the entire cluster!
// #[derive(Clone, PartialEq, Debug)]
// pub struct StoredMeta {
//     /// global write version
//     pub write_version: StoredMetaWriteVersion,
//     /// key for the account
//     pub pubkey: Pubkey,
//     pub data_len: u64,
// }

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

impl<'a, T: ReadableAccount> From<&'a T> for AccountMeta {
    fn from(account: &'a T) -> Self {
        Self {
            lamports: account.wens(),
            owner: *account.owner(),
            executable: account.executable(),
            rent_epoch: account.rent_epoch(),
        }
    }
}

impl<'a, T: ReadableAccount> From<Option<&'a T>> for AccountMeta {
    fn from(account: Option<&'a T>) -> Self {
        match account {
            Some(account) => AccountMeta::from(account),
            None => AccountMeta::default(),
        }
    }
}