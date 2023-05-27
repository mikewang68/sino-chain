use std::{
    cell::{RefCell, UnsafeCell},
    collections::HashMap,
    sync::RwLock,
};

use primitive_types::H256;

use crate::{CachedDatabaseHandle, Database};

// Single threaded cache implementation

#[derive(Default, Debug)]
pub struct CachedHandle<D, C> {
    pub db: D,
    cache: C,
}

impl<D: Clone, C: Default> Clone for CachedHandle<D, C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            cache: C::default(),
        }
    }
}

impl<D: CachedDatabaseHandle, C: Default> CachedHandle<D, C> {
    pub fn new(db: D) -> Self {
        Self {
            db,
            cache: C::default(),
        }
    }

    pub fn clear_cache(&mut self) {
        self.cache = C::default();
    }
}

pub trait Caching {
    fn insert(&self, key: H256, value: Vec<u8>) -> &[u8];

    fn get(&self, key: H256) -> Option<&[u8]>;

    fn contains_key(&self, key: H256) -> bool;
}

impl<D: CachedDatabaseHandle, C: Caching> Database for CachedHandle<D, C> {
    fn get(&self, key: H256) -> &[u8] {
        if !self.cache.contains_key(key) {
            self.cache.insert(key, self.db.get(key))
        } else {
            self.cache.get(key).unwrap()
        }
    }
}

#[derive(Default, Debug)]
pub struct Cache {
    cache: UnsafeCell<Vec<Vec<u8>>>,
    map: RefCell<HashMap<H256, usize>>,
}

impl Caching for Cache {
    fn insert(&self, key: H256, value: Vec<u8>) -> &[u8] {
        let cache = unsafe { &mut *self.cache.get() };
        let index = cache.len();
        self.map.borrow_mut().insert(key, index);
        cache.push(value);
        &cache[index]
    }

    fn get(&self, key: H256) -> Option<&[u8]> {
        let cache = unsafe { &mut *self.cache.get() };
        let map = self.map.borrow_mut();
        match map.get(&key) {
            Some(index) => Some(&cache[*index]),
            None => None,
        }
    }

    fn contains_key(&self, key: H256) -> bool {
        let map = self.map.borrow_mut();
        map.contains_key(&key)
    }
}

// Multithreaded cache implementation

#[derive(Default, Debug)]
pub struct SyncCache {
    cache: UnsafeCell<Vec<Vec<u8>>>,
    map: RwLock<HashMap<H256, usize>>,
}

unsafe impl Sync for SyncCache {}
unsafe impl Send for SyncCache {}

impl Caching for SyncCache {
    fn insert(&self, key: H256, value: Vec<u8>) -> &[u8] {
        let mut map = self.map.write().unwrap();
        let cache = unsafe { &mut *self.cache.get() };
        let index = cache.len();
        map.insert(key, index);
        cache.push(value);
        &cache[index]
    }

    fn get(&self, key: H256) -> Option<&[u8]> {
        let cache = unsafe { &mut *self.cache.get() };
        let map = self.map.read().unwrap();
        match map.get(&key) {
            Some(index) => Some(&cache[*index]),
            None => None,
        }
    }

    fn contains_key(&self, key: H256) -> bool {
        let map = self.map.read().unwrap();
        map.contains_key(&key)
    }
}
