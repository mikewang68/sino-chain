//! ReadOnlyAccountsCache used to store accounts, such as executable accounts,
//! which can be large, loaded many times, and rarely change.
use {
    dashmap::{mapref::entry::Entry, DashMap},
    index_list::{Index, IndexList},
    sdk::{
        account::{AccountSharedData, ReadableAccount},
        clock::Slot,
        pubkey::Pubkey,
    },
    std::sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Mutex,
    },
};

const CACHE_ENTRY_SIZE: usize =
    std::mem::size_of::<ReadOnlyAccountCacheEntry>() + 2 * std::mem::size_of::<ReadOnlyCacheKey>();

type ReadOnlyCacheKey = (Pubkey, Slot);

#[derive(Debug)]
struct ReadOnlyAccountCacheEntry {
    account: AccountSharedData,
    index: Index, // Index of the entry in the eviction queue.
}

#[derive(Debug)]
pub(crate) struct ReadOnlyAccountsCache {
    cache: DashMap<ReadOnlyCacheKey, ReadOnlyAccountCacheEntry>,
    // When an item is first entered into the cache, it is added to the end of
    // the queue. Also each time an entry is looked up from the cache it is
    // moved to the end of the queue. As a result, items in the queue are
    // always sorted in the order that they have last been accessed. When doing
    // LRU eviction, cache entries are evicted from the front of the queue.
    queue: Mutex<IndexList<ReadOnlyCacheKey>>,
    max_data_size: usize,
    data_size: AtomicUsize,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl ReadOnlyAccountsCache {
    pub(crate) fn get_and_reset_stats(&self) -> (u64, u64) {
        let hits = self.hits.swap(0, Ordering::Relaxed);
        let misses = self.misses.swap(0, Ordering::Relaxed);
        (hits, misses)
    }

    pub(crate) fn data_size(&self) -> usize {
        self.data_size.load(Ordering::Relaxed)
    }

    pub(crate) fn cache_len(&self) -> usize {
        self.cache.len()
    }

    pub(crate) fn new(max_data_size: usize) -> Self {
        Self {
            max_data_size,
            cache: DashMap::default(),
            queue: Mutex::<IndexList<ReadOnlyCacheKey>>::default(),
            data_size: AtomicUsize::default(),
            hits: AtomicU64::default(),
            misses: AtomicU64::default(),
        }
    }

    pub(crate) fn load(&self, pubkey: Pubkey, slot: Slot) -> Option<AccountSharedData> {
        let key = (pubkey, slot);
        let mut entry = match self.cache.get_mut(&key) {
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            Some(entry) => entry,
        };
        self.hits.fetch_add(1, Ordering::Relaxed);
        // Move the entry to the end of the queue.
        // self.queue is modified while holding a reference to the cache entry;
        // so that another thread cannot write to the same key.
        {
            let mut queue = self.queue.lock().unwrap();
            queue.remove(entry.index);
            entry.index = queue.insert_last(key);
        }
        Some(entry.account.clone())
    }

    fn account_size(&self, account: &AccountSharedData) -> usize {
        CACHE_ENTRY_SIZE + account.data().len()
    }

    pub(crate) fn store(&self, pubkey: Pubkey, slot: Slot, account: AccountSharedData) {
        let key = (pubkey, slot);
        let account_size = self.account_size(&account);
        self.data_size.fetch_add(account_size, Ordering::Relaxed);
        // self.queue is modified while holding a reference to the cache entry;
        // so that another thread cannot write to the same key.
        match self.cache.entry(key) {
            Entry::Vacant(entry) => {
                // Insert the entry at the end of the queue.
                let mut queue = self.queue.lock().unwrap();
                let index = queue.insert_last(key);
                entry.insert(ReadOnlyAccountCacheEntry { account, index });
            }
            Entry::Occupied(mut entry) => {
                let entry = entry.get_mut();
                let account_size = self.account_size(&entry.account);
                self.data_size.fetch_sub(account_size, Ordering::Relaxed);
                entry.account = account;
                // Move the entry to the end of the queue.
                let mut queue = self.queue.lock().unwrap();
                queue.remove(entry.index);
                entry.index = queue.insert_last(key);
            }
        };
        // Evict entries from the front of the queue.
        while self.data_size.load(Ordering::Relaxed) > self.max_data_size {
            let (pubkey, slot) = match self.queue.lock().unwrap().get_first() {
                None => break,
                Some(key) => *key,
            };
            self.remove(pubkey, slot);
        }
    }

    pub(crate) fn remove(&self, pubkey: Pubkey, slot: Slot) -> Option<AccountSharedData> {
        let (_, entry) = self.cache.remove(&(pubkey, slot))?;
        // self.queue should be modified only after removing the entry from the
        // cache, so that this is still safe if another thread writes to the
        // same key.
        self.queue.lock().unwrap().remove(entry.index);
        let account_size = self.account_size(&entry.account);
        self.data_size.fetch_sub(account_size, Ordering::Relaxed);
        Some(entry.account)
    }

}
