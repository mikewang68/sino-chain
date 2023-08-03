use {
    crate::{crds::VersionedCrdsValue, crds_gossip_pull::CrdsFilter},
    indexmap::map::IndexMap,
    std::{
        cmp::Ordering,
        ops::{Index, IndexMut},
    },
};

#[derive(Clone)]
pub struct CrdsShards {
    // shards[k] includes crds values which the first shard_bits of their hash
    // value is equal to k. Each shard is a mapping from crds values indices to
    // their hash value.
    shards: Vec<IndexMap<usize, u64>>,
    shard_bits: u32,
}

impl CrdsShards {
    pub fn new(shard_bits: u32) -> Self {
        CrdsShards {
            shards: vec![IndexMap::new(); 1 << shard_bits],
            shard_bits,
        }
    }

    pub fn insert(&mut self, index: usize, value: &VersionedCrdsValue) -> bool {
        let hash = CrdsFilter::hash_as_u64(&value.value_hash);
        self.shard_mut(hash).insert(index, hash).is_none()
    }

    pub fn remove(&mut self, index: usize, value: &VersionedCrdsValue) -> bool {
        let hash = CrdsFilter::hash_as_u64(&value.value_hash);
        self.shard_mut(hash).swap_remove(&index).is_some()
    }

    /// Returns indices of all crds values which the first 'mask_bits' of their
    /// hash value is equal to 'mask'.
    pub fn find(&self, mask: u64, mask_bits: u32) -> impl Iterator<Item = usize> + '_ {
        let ones = (!0u64).checked_shr(mask_bits).unwrap_or(0);
        let mask = mask | ones;
        match self.shard_bits.cmp(&mask_bits) {
            Ordering::Less => {
                let pred = move |(&index, hash)| {
                    if hash | ones == mask {
                        Some(index)
                    } else {
                        None
                    }
                };
                Iter::Less(self.shard(mask).iter().filter_map(pred))
            }
            Ordering::Equal => Iter::Equal(self.shard(mask).keys().cloned()),
            Ordering::Greater => {
                let count = 1 << (self.shard_bits - mask_bits);
                let end = self.shard_index(mask) + 1;
                Iter::Greater(
                    self.shards[end - count..end]
                        .iter()
                        .flat_map(IndexMap::keys)
                        .cloned(),
                )
            }
        }
    }

    #[inline]
    fn shard_index(&self, hash: u64) -> usize {
        hash.checked_shr(64 - self.shard_bits).unwrap_or(0) as usize
    }

    #[inline]
    fn shard(&self, hash: u64) -> &IndexMap<usize, u64> {
        let shard_index = self.shard_index(hash);
        self.shards.index(shard_index)
    }

    #[inline]
    fn shard_mut(&mut self, hash: u64) -> &mut IndexMap<usize, u64> {
        let shard_index = self.shard_index(hash);
        self.shards.index_mut(shard_index)
    }

    // Checks invariants in the shards tables against the crds table.
    #[cfg(test)]
    pub fn check(&self, crds: &[VersionedCrdsValue]) {
        let mut indices: Vec<_> = self
            .shards
            .iter()
            .flat_map(IndexMap::keys)
            .cloned()
            .collect();
        indices.sort_unstable();
        assert_eq!(indices, (0..crds.len()).collect::<Vec<_>>());
        for (shard_index, shard) in self.shards.iter().enumerate() {
            for (&index, &hash) in shard {
                assert_eq!(hash, CrdsFilter::hash_as_u64(&crds[index].value_hash));
                assert_eq!(
                    shard_index as u64,
                    hash.checked_shr(64 - self.shard_bits).unwrap_or(0)
                );
            }
        }
    }
}

// Wrapper for 3 types of iterators we get when comparing shard_bits and
// mask_bits in find method. This is to avoid Box<dyn Iterator<Item =...>>
// which involves dynamic dispatch and is relatively slow.
enum Iter<R, S, T> {
    Less(R),
    Equal(S),
    Greater(T),
}

impl<R, S, T> Iterator for Iter<R, S, T>
where
    R: Iterator<Item = usize>,
    S: Iterator<Item = usize>,
    T: Iterator<Item = usize>,
{
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Greater(iter) => iter.next(),
            Self::Less(iter) => iter.next(),
            Self::Equal(iter) => iter.next(),
        }
    }
}