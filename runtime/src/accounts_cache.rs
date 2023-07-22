use {
    dashmap::DashMap,
    sdk::{
        account::{AccountSharedData, ReadableAccount},
        clock::Slot,
        hash::Hash,
        pubkey::Pubkey,
    },
    std::{
        borrow::Borrow,
        collections::BTreeSet,
        ops::Deref,
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, RwLock,
        },
    },
};
//111

pub type SlotCache = Arc<SlotCacheInner>;
pub type CachedAccount = Arc<CachedAccountInner>;
#[derive(Debug)]
pub struct CachedAccountInner {
    pub account: AccountSharedData,
    hash: RwLock<Option<Hash>>,
    slot: Slot,
    pubkey: Pubkey,
}
#[derive(Debug)]
pub struct SlotCacheInner {
    cache: DashMap<Pubkey, CachedAccount>,
    same_account_writes: AtomicU64,
    same_account_writes_size: AtomicU64,
    unique_account_writes_size: AtomicU64,
    size: AtomicU64,
    total_size: Arc<AtomicU64>,
    is_frozen: AtomicBool,
}

impl SlotCacheInner {
    pub fn is_frozen(&self) -> bool {
        self.is_frozen.load(Ordering::SeqCst)
    }

    pub fn insert(
        &self,
        pubkey: &Pubkey,
        account: AccountSharedData,
        hash: Option<impl Borrow<Hash>>,
        slot: Slot,
    ) -> CachedAccount {
        let data_len = account.data().len() as u64;
        let item = Arc::new(CachedAccountInner {
            account,
            hash: RwLock::new(hash.map(|h| *h.borrow())),
            slot,
            pubkey: *pubkey,
        });
        if let Some(old) = self.cache.insert(*pubkey, item.clone()) {
            self.same_account_writes.fetch_add(1, Ordering::Relaxed);
            self.same_account_writes_size
                .fetch_add(data_len, Ordering::Relaxed);

            let old_len = old.account.data().len() as u64;
            let grow = old_len.saturating_sub(data_len);
            if grow > 0 {
                self.size.fetch_add(grow, Ordering::Relaxed);
                self.total_size.fetch_add(grow, Ordering::Relaxed);
            } else {
                let shrink = data_len.saturating_sub(old_len);
                if shrink > 0 {
                    self.size.fetch_add(shrink, Ordering::Relaxed);
                    self.total_size.fetch_sub(shrink, Ordering::Relaxed);
                }
            }
        } else {
            self.size.fetch_add(data_len, Ordering::Relaxed);
            self.total_size.fetch_add(data_len, Ordering::Relaxed);
            self.unique_account_writes_size
                .fetch_add(data_len, Ordering::Relaxed);
        }
        item
    }

    pub fn get_all_pubkeys(&self) -> Vec<Pubkey> {
        self.cache.iter().map(|item| *item.key()).collect()
    }

    pub fn get_cloned(&self, pubkey: &Pubkey) -> Option<CachedAccount> {
        self.cache
            .get(pubkey)
            // 1) Maybe can eventually use a Cow to avoid a clone on every read
            // 2) Popping is only safe if it's guaranteed that only
            //    replay/banking threads are reading from the AccountsDb
            .map(|account_ref| account_ref.value().clone())
    }

}

#[derive(Debug, Default)]
pub struct AccountsCache {
    cache: DashMap<Slot, SlotCache>,
    // Queue of potentially unflushed roots. Random eviction + cache too large
    // could have triggered a flush of this slot already
    maybe_unflushed_roots: RwLock<BTreeSet<Slot>>,
    max_flushed_root: AtomicU64,
    total_size: Arc<AtomicU64>,
}

impl Drop for SlotCacheInner {
    fn drop(&mut self) {
        // broader cache no longer holds our size in memory
        self.total_size
            .fetch_sub(self.size.load(Ordering::Relaxed), Ordering::Relaxed);
    }
}

impl AccountsCache {
    pub fn num_slots(&self) -> usize {
        self.cache.len()
    }

    pub fn cached_frozen_slots(&self) -> Vec<Slot> {
        let mut slots: Vec<_> = self
            .cache
            .iter()
            .filter_map(|item| {
                let (slot, slot_cache) = item.pair();
                if slot_cache.is_frozen() {
                    Some(*slot)
                } else {
                    None
                }
            })
            .collect();
        slots.sort_unstable();
        slots
    }

    pub fn set_max_flush_root(&self, root: Slot) {
        self.max_flushed_root.fetch_max(root, Ordering::Relaxed);
    }

    pub fn remove_slot(&self, slot: Slot) -> Option<SlotCache> {
        self.cache.remove(&slot).map(|(_, slot_cache)| slot_cache)
    }

    #[allow(clippy::mem_replace_with_default)]
    pub fn clear_roots(&self, max_root: Option<Slot>) -> BTreeSet<Slot> {
        let mut w_maybe_unflushed_roots = self.maybe_unflushed_roots.write().unwrap();
        if let Some(max_root) = max_root {
            // `greater_than_max_root` contains all slots >= `max_root + 1`, or alternatively,
            // all slots > `max_root`. Meanwhile, `w_maybe_unflushed_roots` is left with all slots
            // <= `max_root`.
            let greater_than_max_root = w_maybe_unflushed_roots.split_off(&(max_root + 1));
            // After the replace, `w_maybe_unflushed_roots` contains slots > `max_root`, and
            // we return all slots <= `max_root`
            std::mem::replace(&mut w_maybe_unflushed_roots, greater_than_max_root)
        } else {
            std::mem::take(&mut *w_maybe_unflushed_roots)
        }
    }

    pub fn size(&self) -> u64 {
        self.total_size.load(Ordering::Relaxed)
    }

    pub fn new_inner(&self) -> SlotCache {
        Arc::new(SlotCacheInner {
            cache: DashMap::default(),
            same_account_writes: AtomicU64::default(),
            same_account_writes_size: AtomicU64::default(),
            unique_account_writes_size: AtomicU64::default(),
            size: AtomicU64::default(),
            total_size: Arc::clone(&self.total_size),
            is_frozen: AtomicBool::default(),
        })
    }

    pub fn store(
        &self,
        slot: Slot,
        pubkey: &Pubkey,
        account: AccountSharedData,
        hash: Option<impl Borrow<Hash>>,
    ) -> CachedAccount {
        let slot_cache = self.slot_cache(slot).unwrap_or_else(||
            // DashMap entry.or_insert() returns a RefMut, essentially a write lock,
            // which is dropped after this block ends, minimizing time held by the lock.
            // However, we still want to persist the reference to the `SlotStores` behind
            // the lock, hence we clone it out, (`SlotStores` is an Arc so is cheap to clone).
            self
                .cache
                .entry(slot)
                .or_insert(self.new_inner())
                .clone());

        slot_cache.insert(pubkey, account, hash, slot)
    }

    pub fn add_root(&self, root: Slot) {
        let max_flushed_root = self.fetch_max_flush_root();
        if root > max_flushed_root || (root == max_flushed_root && root == 0) {
            self.maybe_unflushed_roots.write().unwrap().insert(root);
        }
    }

    pub fn fetch_max_flush_root(&self) -> Slot {
        self.max_flushed_root.load(Ordering::Relaxed)
    }

    pub fn load(&self, slot: Slot, pubkey: &Pubkey) -> Option<CachedAccount> {
        self.slot_cache(slot)
            .and_then(|slot_cache| slot_cache.get_cloned(pubkey))
    }

    pub fn slot_cache(&self, slot: Slot) -> Option<SlotCache> {
        self.cache.get(&slot).map(|result| result.value().clone())
    }

}

impl Deref for SlotCacheInner {
    type Target = DashMap<Pubkey, CachedAccount>;
    fn deref(&self) -> &Self::Target {
        &self.cache
    }
}

impl CachedAccountInner {
    pub fn hash(&self) -> Hash {
        let hash = self.hash.read().unwrap();
        match *hash {
            Some(hash) => hash,
            None => {
                drop(hash);
                let hash = crate::accounts_db::AccountsDb::hash_account(
                    self.slot,
                    &self.account,
                    &self.pubkey,
                );
                *self.hash.write().unwrap() = Some(hash);
                hash
            }
        }
    }
    pub fn pubkey(&self) -> &Pubkey {
        &self.pubkey
    }
}