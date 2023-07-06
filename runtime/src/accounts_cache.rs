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
//test

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
#[derive(Debug, Default)]
pub struct AccountsCache {
    cache: DashMap<Slot, SlotCache>,
    // Queue of potentially unflushed roots. Random eviction + cache too large
    // could have triggered a flush of this slot already
    maybe_unflushed_roots: RwLock<BTreeSet<Slot>>,
    max_flushed_root: AtomicU64,
    total_size: Arc<AtomicU64>,
}

