use {
    itertools::Itertools,
    rand::distributions::{Distribution, WeightedIndex},
    rand_chacha::{rand_core::SeedableRng, ChaChaRng},
    sdk::pubkey::Pubkey,
    std::{collections::HashMap, convert::identity, ops::Index, sync::Arc},
};

// Used for testing
#[derive(Clone, Debug)]
pub struct FixedSchedule {
    pub leader_schedule: Arc<LeaderSchedule>,
    pub start_epoch: u64,
}

/// Stake-weighted leader schedule for one epoch.
#[derive(Debug, Default, PartialEq)]
pub struct LeaderSchedule {
    slot_leaders: Vec<Pubkey>,
    // Inverted index from pubkeys to indices where they are the leader.
    index: HashMap<Pubkey, Arc<Vec<usize>>>,
}

impl LeaderSchedule {
    // Note: passing in zero stakers will cause a panic.
    #[allow(clippy::branches_sharing_code)]
    pub fn new(ids_and_stakes: &[(Pubkey, u64)], seed: [u8; 32], len: u64, repeat: u64) -> Self {
        let (ids, stakes): (Vec<_>, Vec<_>) = ids_and_stakes.iter().cloned().unzip();
        let rng = &mut ChaChaRng::from_seed(seed);
        let weighted_index = WeightedIndex::new(stakes).unwrap();
        let mut current_node = Pubkey::default();
        let slot_leaders = (0..len)
            .map(|i| {
                if i % repeat == 0 {
                    current_node = ids[weighted_index.sample(rng)];
                }
                current_node
            })
            .collect();
        Self::new_from_schedule(slot_leaders)
    }

    pub fn new_from_schedule(slot_leaders: Vec<Pubkey>) -> Self {
        let index = slot_leaders
            .iter()
            .enumerate()
            .map(|(i, pk)| (*pk, i))
            .into_group_map()
            .into_iter()
            .map(|(k, v)| (k, Arc::new(v)))
            .collect();
        Self {
            slot_leaders,
            index,
        }
    }

//     pub fn get_slot_leaders(&self) -> &[Pubkey] {
//         &self.slot_leaders
//     }

//     pub fn num_slots(&self) -> usize {
//         self.slot_leaders.len()
//     }

    /// 'offset' is an index into the leader schedule. The function returns an
    /// iterator of indices i >= offset where the given pubkey is the leader.
    pub(crate) fn get_indices(
        &self,
        pubkey: &Pubkey,
        offset: usize, // Starting index.
    ) -> impl Iterator<Item = usize> {
        let index = self.index.get(pubkey).cloned().unwrap_or_default();
        let num_slots = self.slot_leaders.len();
        let size = index.len();
        #[allow(clippy::reversed_empty_ranges)]
        let range = if index.is_empty() {
            1..=0 // Intentionally empty range of type RangeInclusive.
        } else {
            let offset = index
                .binary_search(&(offset % num_slots))
                .unwrap_or_else(identity)
                + offset / num_slots * size;
            offset..=usize::MAX
        };
        // The modular arithmetic here and above replicate Index implementation
        // for LeaderSchedule, where the schedule keeps repeating endlessly.
        // The '%' returns where in a cycle we are and the '/' returns how many
        // times the schedule is repeated.
        range.map(move |k| index[k % size] + k / size * num_slots)
    }
}

impl Index<u64> for LeaderSchedule {
    type Output = Pubkey;
    fn index(&self, index: u64) -> &Pubkey {
        let index = index as usize;
        &self.slot_leaders[index % self.slot_leaders.len()]
    }
}
