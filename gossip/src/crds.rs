//! This module implements Cluster Replicated Data Store for
//! asynchronous updates in a distributed network.
//!
//! Data is stored in the CrdsValue type, each type has a specific
//! CrdsValueLabel.  Labels are semantically grouped into a single record
//! that is identified by a Pubkey.
//! * 1 Pubkey maps many CrdsValueLabels
//! * 1 CrdsValueLabel maps to 1 CrdsValue
//! The Label, the record Pubkey, and all the record labels can be derived
//! from a single CrdsValue.
//!
//! The actual data is stored in a single map of
//! `CrdsValueLabel(Pubkey) -> CrdsValue` This allows for partial record
//! updates to be propagated through the network.
//!
//! This means that full `Record` updates are not atomic.
//!
//! Additional labels can be added by appending them to the CrdsValueLabel,
//! CrdsValue enums.
//!
//! Merge strategy is implemented in:
//!     fn overrides(value: &CrdsValue, other: &VersionedCrdsValue) -> bool
//!
//! A value is updated to a new version if the labels match, and the value
//! wallclock is later, or the value hash is greater.

use {
    crate::{
        contact_info::ContactInfo,
        crds_entry::CrdsEntry,
        crds_shards::CrdsShards,
        crds_value::{CrdsData, CrdsValue, CrdsValueLabel},
    },
    bincode::serialize,
    indexmap::{
        map::{rayon::ParValues, Entry, IndexMap},
        set::IndexSet,
    },
    lru::LruCache,
    matches::debug_assert_matches,
    rayon::{prelude::*, ThreadPool},
    sdk::{
        clock::Slot,
        hash::{hash, Hash},
        pubkey::Pubkey,
    },
    std::{
        cmp::Ordering,
        collections::{hash_map, BTreeMap, HashMap, VecDeque},
        ops::{Bound, Index, IndexMut},
        sync::Mutex,
    },
};

const CRDS_SHARDS_BITS: u32 = 12;
// Number of vote slots to track in an lru-cache for metrics.
const VOTE_SLOTS_METRICS_CAP: usize = 100;

pub struct Crds {
    /// Stores the map of labels and values
    table: IndexMap<CrdsValueLabel, VersionedCrdsValue>,
    cursor: Cursor, // Next insert ordinal location.
    shards: CrdsShards,
    nodes: IndexSet<usize>, // Indices of nodes' ContactInfo.
    // Indices of Votes keyed by insert order.
    votes: BTreeMap<u64 /*insert order*/, usize /*index*/>,
    // Indices of EpochSlots keyed by insert order.
    epoch_slots: BTreeMap<u64 /*insert order*/, usize /*index*/>,
    // Indices of all crds values associated with a node.
    records: HashMap<Pubkey, IndexSet<usize>>,
    // Indices of all entries keyed by insert order.
    entries: BTreeMap<u64 /*insert order*/, usize /*index*/>,
    // Hash of recently purged values.
    purged: VecDeque<(Hash, u64 /*timestamp*/)>,
    // Mapping from nodes' pubkeys to their respective shred-version.
    shred_versions: HashMap<Pubkey, u16>,
    stats: Mutex<CrdsStats>,
}

#[derive(PartialEq, Debug)]
pub enum CrdsError {
    InsertFailed,
    UnknownStakes,
}

#[derive(Clone, Copy)]
pub enum GossipRoute {
    LocalMessage,
    PullRequest,
    PullResponse,
    PushMessage,
}

type CrdsCountsArray = [usize; 11];

pub(crate) struct CrdsDataStats {
    pub(crate) counts: CrdsCountsArray,
    pub(crate) fails: CrdsCountsArray,
    pub(crate) votes: LruCache<Slot, /*count:*/ usize>,
}

#[derive(Default)]
pub(crate) struct CrdsStats {
    pub(crate) pull: CrdsDataStats,
    pub(crate) push: CrdsDataStats,
}

/// This structure stores some local metadata associated with the CrdsValue
#[derive(PartialEq, Debug, Clone)]
pub struct VersionedCrdsValue {
    /// Ordinal index indicating insert order.
    ordinal: u64,
    pub value: CrdsValue,
    /// local time when updated
    pub(crate) local_timestamp: u64,
    /// value hash
    pub(crate) value_hash: Hash,
}

#[derive(Clone, Copy, Default)]
pub struct Cursor(u64);

impl Cursor {
    fn ordinal(&self) -> u64 {
        self.0
    }

    // Updates the cursor position given the ordinal index of value consumed.
    #[inline]
    fn consume(&mut self, ordinal: u64) {
        self.0 = self.0.max(ordinal + 1);
    }
}

impl VersionedCrdsValue {
    fn new(value: CrdsValue, cursor: Cursor, local_timestamp: u64) -> Self {
        let value_hash = hash(&serialize(&value).unwrap());
        VersionedCrdsValue {
            ordinal: cursor.ordinal(),
            value,
            local_timestamp,
            value_hash,
        }
    }
}

impl Default for Crds {
    fn default() -> Self {
        Crds {
            table: IndexMap::default(),
            cursor: Cursor::default(),
            shards: CrdsShards::new(CRDS_SHARDS_BITS),
            nodes: IndexSet::default(),
            votes: BTreeMap::default(),
            epoch_slots: BTreeMap::default(),
            records: HashMap::default(),
            entries: BTreeMap::default(),
            purged: VecDeque::default(),
            shred_versions: HashMap::default(),
            stats: Mutex::<CrdsStats>::default(),
        }
    }
}

// Returns true if the first value updates the 2nd one.
// Both values should have the same key/label.
fn overrides(value: &CrdsValue, other: &VersionedCrdsValue) -> bool {
    assert_eq!(value.label(), other.value.label(), "labels mismatch!");
    // Node instances are special cased so that if there are two running
    // instances of the same node, the more recent start is propagated through
    // gossip regardless of wallclocks.
    if let CrdsData::NodeInstance(value) = &value.data {
        if let Some(out) = value.overrides(&other.value) {
            return out;
        }
    }
    match value.wallclock().cmp(&other.value.wallclock()) {
        Ordering::Less => false,
        Ordering::Greater => true,
        // Ties should be broken in a deterministic way across the cluster.
        // For backward compatibility this is done by comparing hash of
        // serialized values.
        Ordering::Equal => {
            let value_hash = hash(&serialize(&value).unwrap());
            other.value_hash < value_hash
        }
    }
}

impl Crds {
    /// Returns true if the given value updates an existing one in the table.
    /// The value is outdated and fails to insert, if it already exists in the
    /// table with a more recent wallclock.
    pub(crate) fn upserts(&self, value: &CrdsValue) -> bool {
        match self.table.get(&value.label()) {
            Some(other) => overrides(value, other),
            None => true,
        }
    }

    pub fn insert(
        &mut self,
        value: CrdsValue,
        now: u64,
        route: GossipRoute,
    ) -> Result<(), CrdsError> {
        let label = value.label();
        let pubkey = value.pubkey();
        let value = VersionedCrdsValue::new(value, self.cursor, now);
        match self.table.entry(label) {
            Entry::Vacant(entry) => {
                self.stats.lock().unwrap().record_insert(&value, route);
                let entry_index = entry.index();
                self.shards.insert(entry_index, &value);
                match &value.value.data {
                    CrdsData::ContactInfo(node) => {
                        self.nodes.insert(entry_index);
                        self.shred_versions.insert(pubkey, node.shred_version);
                    }
                    CrdsData::Vote(_, _) => {
                        self.votes.insert(value.ordinal, entry_index);
                    }
                    CrdsData::EpochSlots(_, _) => {
                        self.epoch_slots.insert(value.ordinal, entry_index);
                    }
                    _ => (),
                };
                self.entries.insert(value.ordinal, entry_index);
                self.records.entry(pubkey).or_default().insert(entry_index);
                self.cursor.consume(value.ordinal);
                entry.insert(value);
                Ok(())
            }
            Entry::Occupied(mut entry) if overrides(&value.value, entry.get()) => {
                self.stats.lock().unwrap().record_insert(&value, route);
                let entry_index = entry.index();
                self.shards.remove(entry_index, entry.get());
                self.shards.insert(entry_index, &value);
                match &value.value.data {
                    CrdsData::ContactInfo(node) => {
                        self.shred_versions.insert(pubkey, node.shred_version);
                        // self.nodes does not need to be updated since the
                        // entry at this index was and stays contact-info.
                        debug_assert_matches!(entry.get().value.data, CrdsData::ContactInfo(_));
                    }
                    CrdsData::Vote(_, _) => {
                        self.votes.remove(&entry.get().ordinal);
                        self.votes.insert(value.ordinal, entry_index);
                    }
                    CrdsData::EpochSlots(_, _) => {
                        self.epoch_slots.remove(&entry.get().ordinal);
                        self.epoch_slots.insert(value.ordinal, entry_index);
                    }
                    _ => (),
                }
                self.entries.remove(&entry.get().ordinal);
                self.entries.insert(value.ordinal, entry_index);
                // As long as the pubkey does not change, self.records
                // does not need to be updated.
                debug_assert_eq!(entry.get().value.pubkey(), pubkey);
                self.cursor.consume(value.ordinal);
                self.purged.push_back((entry.get().value_hash, now));
                entry.insert(value);
                Ok(())
            }
            Entry::Occupied(entry) => {
                self.stats.lock().unwrap().record_fail(&value, route);
                trace!(
                    "INSERT FAILED data: {} new.wallclock: {}",
                    value.value.label(),
                    value.value.wallclock(),
                );
                if entry.get().value_hash != value.value_hash {
                    self.purged.push_back((value.value_hash, now));
                }
                Err(CrdsError::InsertFailed)
            }
        }
    }

    pub fn get<'a, 'b, V>(&'a self, key: V::Key) -> Option<V>
    where
        V: CrdsEntry<'a, 'b>,
    {
        V::get_entry(&self.table, key)
    }

    pub(crate) fn get_shred_version(&self, pubkey: &Pubkey) -> Option<u16> {
        self.shred_versions.get(pubkey).copied()
    }

    /// Returns all entries which are ContactInfo.
    pub(crate) fn get_nodes(&self) -> impl Iterator<Item = &VersionedCrdsValue> {
        self.nodes.iter().map(move |i| self.table.index(*i))
    }

    /// Returns ContactInfo of all known nodes.
    pub(crate) fn get_nodes_contact_info(&self) -> impl Iterator<Item = &ContactInfo> {
        self.get_nodes().map(|v| match &v.value.data {
            CrdsData::ContactInfo(info) => info,
            _ => panic!("this should not happen!"),
        })
    }

    /// Returns all vote entries inserted since the given cursor.
    /// Updates the cursor as the votes are consumed.
    pub(crate) fn get_votes<'a>(
        &'a self,
        cursor: &'a mut Cursor,
    ) -> impl Iterator<Item = &'a VersionedCrdsValue> {
        let range = (Bound::Included(cursor.ordinal()), Bound::Unbounded);
        self.votes.range(range).map(move |(ordinal, index)| {
            cursor.consume(*ordinal);
            self.table.index(*index)
        })
    }

    /// Returns epoch-slots inserted since the given cursor.
    /// Updates the cursor as the values are consumed.
    pub(crate) fn get_epoch_slots<'a>(
        &'a self,
        cursor: &'a mut Cursor,
    ) -> impl Iterator<Item = &'a VersionedCrdsValue> {
        let range = (Bound::Included(cursor.ordinal()), Bound::Unbounded);
        self.epoch_slots.range(range).map(move |(ordinal, index)| {
            cursor.consume(*ordinal);
            self.table.index(*index)
        })
    }

    /// Returns all entries inserted since the given cursor.
    pub(crate) fn get_entries<'a>(
        &'a self,
        cursor: &'a mut Cursor,
    ) -> impl Iterator<Item = &'a VersionedCrdsValue> {
        let range = (Bound::Included(cursor.ordinal()), Bound::Unbounded);
        self.entries.range(range).map(move |(ordinal, index)| {
            cursor.consume(*ordinal);
            self.table.index(*index)
        })
    }

    /// Returns all records associated with a pubkey.
    pub(crate) fn get_records(&self, pubkey: &Pubkey) -> impl Iterator<Item = &VersionedCrdsValue> {
        self.records
            .get(pubkey)
            .into_iter()
            .flat_map(|records| records.into_iter())
            .map(move |i| self.table.index(*i))
    }

    /// Returns number of known contact-infos (network size).
    pub(crate) fn num_nodes(&self) -> usize {
        self.nodes.len()
    }

    /// Returns number of unique pubkeys.
    pub(crate) fn num_pubkeys(&self) -> usize {
        self.records.len()
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn values(&self) -> impl Iterator<Item = &VersionedCrdsValue> {
        self.table.values()
    }

    pub(crate) fn par_values(&self) -> ParValues<'_, CrdsValueLabel, VersionedCrdsValue> {
        self.table.par_values()
    }

    pub(crate) fn num_purged(&self) -> usize {
        self.purged.len()
    }

    pub(crate) fn purged(&self) -> impl IndexedParallelIterator<Item = Hash> + '_ {
        self.purged.par_iter().map(|(hash, _)| *hash)
    }

    /// Drops purged value hashes with timestamp less than the given one.
    pub(crate) fn trim_purged(&mut self, timestamp: u64) {
        let count = self
            .purged
            .iter()
            .take_while(|(_, ts)| *ts < timestamp)
            .count();
        self.purged.drain(..count);
    }

    /// Returns all crds values which the first 'mask_bits'
    /// of their hash value is equal to 'mask'.
    pub(crate) fn filter_bitmask(
        &self,
        mask: u64,
        mask_bits: u32,
    ) -> impl Iterator<Item = &VersionedCrdsValue> {
        self.shards
            .find(mask, mask_bits)
            .map(move |i| self.table.index(i))
    }

    /// Update the timestamp's of all the labels that are associated with Pubkey
    pub(crate) fn update_record_timestamp(&mut self, pubkey: &Pubkey, now: u64) {
        // It suffices to only overwrite the origin's timestamp since that is
        // used when purging old values. If the origin does not exist in the
        // table, fallback to exhaustive update on all associated records.
        let origin = CrdsValueLabel::ContactInfo(*pubkey);
        if let Some(origin) = self.table.get_mut(&origin) {
            if origin.local_timestamp < now {
                origin.local_timestamp = now;
            }
        } else if let Some(indices) = self.records.get(pubkey) {
            for index in indices {
                let entry = self.table.index_mut(*index);
                if entry.local_timestamp < now {
                    entry.local_timestamp = now;
                }
            }
        }
    }

    /// Find all the keys that are older or equal to the timeout.
    /// * timeouts - Pubkey specific timeouts with Pubkey::default() as the default timeout.
    pub fn find_old_labels(
        &self,
        thread_pool: &ThreadPool,
        now: u64,
        timeouts: &HashMap<Pubkey, u64>,
    ) -> Vec<CrdsValueLabel> {
        let default_timeout = *timeouts
            .get(&Pubkey::default())
            .expect("must have default timeout");
        // Given an index of all crd values associated with a pubkey,
        // returns crds labels of old values to be evicted.
        let evict = |pubkey, index: &IndexSet<usize>| {
            let timeout = timeouts.get(pubkey).copied().unwrap_or(default_timeout);
            // If the origin's contact-info hasn't expired yet then preserve
            // all associated values.
            let origin = CrdsValueLabel::ContactInfo(*pubkey);
            if let Some(origin) = self.table.get(&origin) {
                if now < origin.local_timestamp.saturating_add(timeout) {
                    return vec![];
                }
            }
            // Otherwise check each value's timestamp individually.
            index
                .into_iter()
                .filter_map(|ix| {
                    let (label, value) = self.table.get_index(*ix).unwrap();
                    if value.local_timestamp.saturating_add(timeout) <= now {
                        Some(label.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        };
        thread_pool.install(|| {
            self.records
                .par_iter()
                .flat_map(|(pubkey, index)| evict(pubkey, index))
                .collect()
        })
    }

    pub fn remove(&mut self, key: &CrdsValueLabel, now: u64) {
        let (index, _ /*label*/, value) = match self.table.swap_remove_full(key) {
            Some(entry) => entry,
            None => return,
        };
        self.purged.push_back((value.value_hash, now));
        self.shards.remove(index, &value);
        match value.value.data {
            CrdsData::ContactInfo(_) => {
                self.nodes.swap_remove(&index);
            }
            CrdsData::Vote(_, _) => {
                self.votes.remove(&value.ordinal);
            }
            CrdsData::EpochSlots(_, _) => {
                self.epoch_slots.remove(&value.ordinal);
            }
            _ => (),
        }
        self.entries.remove(&value.ordinal);
        // Remove the index from records associated with the value's pubkey.
        let pubkey = value.value.pubkey();
        let mut records_entry = match self.records.entry(pubkey) {
            hash_map::Entry::Vacant(_) => panic!("this should not happen!"),
            hash_map::Entry::Occupied(entry) => entry,
        };
        records_entry.get_mut().swap_remove(&index);
        if records_entry.get().is_empty() {
            records_entry.remove();
            self.shred_versions.remove(&pubkey);
        }
        // If index == self.table.len(), then the removed entry was the last
        // entry in the table, in which case no other keys were modified.
        // Otherwise, the previously last element in the table is now moved to
        // the 'index' position; and so shards and nodes need to be updated
        // accordingly.
        let size = self.table.len();
        if index < size {
            let value = self.table.index(index);
            self.shards.remove(size, value);
            self.shards.insert(index, value);
            match value.value.data {
                CrdsData::ContactInfo(_) => {
                    self.nodes.swap_remove(&size);
                    self.nodes.insert(index);
                }
                CrdsData::Vote(_, _) => {
                    self.votes.insert(value.ordinal, index);
                }
                CrdsData::EpochSlots(_, _) => {
                    self.epoch_slots.insert(value.ordinal, index);
                }
                _ => (),
            };
            self.entries.insert(value.ordinal, index);
            let pubkey = value.value.pubkey();
            let records = self.records.get_mut(&pubkey).unwrap();
            records.swap_remove(&size);
            records.insert(index);
        }
    }

    /// Returns true if the number of unique pubkeys in the table exceeds the
    /// given capacity (plus some margin).
    /// Allows skipping unnecessary calls to trim without obtaining a write
    /// lock on gossip.
    pub(crate) fn should_trim(&self, cap: usize) -> bool {
        // Allow 10% overshoot so that the computation cost is amortized down.
        10 * self.records.len() > 11 * cap
    }

    /// Trims the table by dropping all values associated with the pubkeys with
    /// the lowest stake, so that the number of unique pubkeys are bounded.
    pub(crate) fn trim(
        &mut self,
        cap: usize, // Capacity hint for number of unique pubkeys.
        // Set of pubkeys to never drop.
        // e.g. known validators, self pubkey, ...
        keep: &[Pubkey],
        stakes: &HashMap<Pubkey, u64>,
        now: u64,
    ) -> Result</*num purged:*/ usize, CrdsError> {
        if self.should_trim(cap) {
            let size = self.records.len().saturating_sub(cap);
            self.drop(size, keep, stakes, now)
        } else {
            Ok(0)
        }
    }

    // Drops 'size' many pubkeys with the lowest stake.
    fn drop(
        &mut self,
        size: usize,
        keep: &[Pubkey],
        stakes: &HashMap<Pubkey, u64>,
        now: u64,
    ) -> Result</*num purged:*/ usize, CrdsError> {
        if stakes.values().all(|&stake| stake == 0) {
            return Err(CrdsError::UnknownStakes);
        }
        let mut keys: Vec<_> = self
            .records
            .keys()
            .map(|k| (stakes.get(k).copied().unwrap_or_default(), *k))
            .collect();
        if size < keys.len() {
            keys.select_nth_unstable(size);
        }
        let keys: Vec<_> = keys
            .into_iter()
            .take(size)
            .map(|(_, k)| k)
            .filter(|k| !keep.contains(k))
            .flat_map(|k| &self.records[&k])
            .map(|k| self.table.get_index(*k).unwrap().0.clone())
            .collect();
        for key in &keys {
            self.remove(key, now);
        }
        Ok(keys.len())
    }

    pub(crate) fn take_stats(&self) -> CrdsStats {
        std::mem::take(&mut self.stats.lock().unwrap())
    }

    // Only for tests and simulations.
    // pub(crate) fn mock_clone(&self) -> Self {
    //     Self {
    //         table: self.table.clone(),
    //         cursor: self.cursor,
    //         shards: self.shards.clone(),
    //         nodes: self.nodes.clone(),
    //         votes: self.votes.clone(),
    //         epoch_slots: self.epoch_slots.clone(),
    //         records: self.records.clone(),
    //         entries: self.entries.clone(),
    //         purged: self.purged.clone(),
    //         shred_versions: self.shred_versions.clone(),
    //         stats: Mutex::<CrdsStats>::default(),
    //     }
    // }
}

impl Default for CrdsDataStats {
    fn default() -> Self {
        Self {
            counts: CrdsCountsArray::default(),
            fails: CrdsCountsArray::default(),
            votes: LruCache::new(VOTE_SLOTS_METRICS_CAP),
        }
    }
}

impl CrdsDataStats {
    fn record_insert(&mut self, entry: &VersionedCrdsValue) {
        self.counts[Self::ordinal(entry)] += 1;
        if let CrdsData::Vote(_, vote) = &entry.value.data {
            if let Some(slot) = vote.slot() {
                let num_nodes = self.votes.get(&slot).copied().unwrap_or_default();
                self.votes.put(slot, num_nodes + 1);
            }
        }
    }

    fn record_fail(&mut self, entry: &VersionedCrdsValue) {
        self.fails[Self::ordinal(entry)] += 1;
    }

    fn ordinal(entry: &VersionedCrdsValue) -> usize {
        match &entry.value.data {
            CrdsData::ContactInfo(_) => 0,
            CrdsData::Vote(_, _) => 1,
            CrdsData::LowestSlot(_, _) => 2,
            CrdsData::SnapshotHashes(_) => 3,
            CrdsData::AccountsHashes(_) => 4,
            CrdsData::EpochSlots(_, _) => 5,
            CrdsData::LegacyVersion(_) => 6,
            CrdsData::Version(_) => 7,
            CrdsData::NodeInstance(_) => 8,
            CrdsData::DuplicateShred(_, _) => 9,
            CrdsData::IncrementalSnapshotHashes(_) => 10,
        }
    }
}

impl CrdsStats {
    fn record_insert(&mut self, entry: &VersionedCrdsValue, route: GossipRoute) {
        match route {
            GossipRoute::LocalMessage => (),
            GossipRoute::PullRequest => (),
            GossipRoute::PushMessage => self.push.record_insert(entry),
            GossipRoute::PullResponse => self.pull.record_insert(entry),
        }
    }

    fn record_fail(&mut self, entry: &VersionedCrdsValue, route: GossipRoute) {
        match route {
            GossipRoute::LocalMessage => (),
            GossipRoute::PullRequest => (),
            GossipRoute::PushMessage => self.push.record_fail(entry),
            GossipRoute::PullResponse => self.pull.record_fail(entry),
        }
    }
}