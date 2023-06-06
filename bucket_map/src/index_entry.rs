use {
    crate::{
        bucket::Bucket,
        bucket_storage::{
            BucketStorage, 
            Uid
        },
        RefCount,
    },
    sdk::{clock::Slot, pubkey::Pubkey},
    std::{
        collections::hash_map::DefaultHasher,
        fmt::Debug,
        hash::{Hash, Hasher},
    },
};

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
// one instance of this per item in the index
// stored in the index bucket
pub struct IndexEntry {
    pub key: Pubkey, // can this be smaller if we have reduced the keys into buckets already?
    pub ref_count: RefCount, // can this be smaller? Do we ever need more than 4B refcounts?
    pub storage_offset: u64, // smaller? since these are variably sized, this could get tricky. well, actually accountinfo is not variable sized...
    // if the bucket doubled, the index can be recomputed using create_bucket_capacity_pow2
    pub storage_capacity_when_created_pow2: u8, // see data_location
    pub num_slots: Slot, // can this be smaller? epoch size should ~ be the max len. this is the num elements in the slot list
}

impl IndexEntry {
    pub fn data_bucket_from_num_slots(num_slots: Slot) -> u64 {
        (num_slots as f64).log2().ceil() as u64 // use int log here?
    }

    // This function maps the original data location into an index in the current bucket storage.
    // This is coupled with how we resize bucket storages.
    pub fn data_loc(&self, storage: &BucketStorage) -> u64 {
        self.storage_offset << (storage.capacity_pow2 - self.storage_capacity_when_created_pow2)
    }

    pub fn data_bucket_ix(&self) -> u64 {
        Self::data_bucket_from_num_slots(self.num_slots)
    }

    pub fn key_uid(key: &Pubkey) -> Uid {
        let mut s = DefaultHasher::new();
        key.hash(&mut s);
        s.finish().max(1u64)
    }
}