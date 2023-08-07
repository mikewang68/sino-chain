use {
    crate::leader_schedule::LeaderSchedule,
    runtime::bank::Bank,
    sdk::{
        clock::{Epoch, Slot, NUM_CONSECUTIVE_LEADER_SLOTS},
        pubkey::Pubkey,
    },
    std::collections::HashMap,
};


pub use vote_program::{
    MIN_STAKERS_TO_BE_MAJORITY, NUM_MAJOR_STAKERS_FOR_FILTERING,
};

/// Return the leader schedule for the given epoch.
pub fn leader_schedule(epoch: Epoch, bank: &Bank) -> Option<LeaderSchedule> {
    bank.epoch_staked_nodes(epoch).map(|stakes| {
        let mut seed = [0u8; 32];
        seed[0..8].copy_from_slice(&epoch.to_le_bytes());
        let stakes = retain_sort_stakers(&stakes);
        LeaderSchedule::new(
            &stakes,
            seed,
            bank.get_slots_in_epoch(epoch),
            NUM_CONSECUTIVE_LEADER_SLOTS,
        )
    })
}

fn retain_sort_stakers(stakes: &HashMap<Pubkey, u64>) -> Vec<(Pubkey, u64)> {
    let mut stakes: Vec<_> = stakes.iter().map(|(k, v)| (*k, *v)).collect();
    sort_stakes(&mut stakes);
    if num_major_stakers(&stakes) >= NUM_MAJOR_STAKERS_FOR_FILTERING {
        retain_major_stakers(&mut stakes)
    }
    stakes
}

fn sort_stakes(stakes: &mut Vec<(Pubkey, u64)>) {
    // Sort first by stake. If stakes are the same, sort by pubkey to ensure a
    // deterministic result.
    // Note: Use unstable sort, because we dedup right after to remove the equal elements.
    stakes.sort_unstable_by(|(l_pubkey, l_stake), (r_pubkey, r_stake)| {
        if r_stake == l_stake {
            r_pubkey.cmp(l_pubkey)
        } else {
            r_stake.cmp(l_stake)
        }
    });

    // Now that it's sorted, we can do an O(n) dedup.
    stakes.dedup();
}

/// Map of leader base58 identity pubkeys to the slot indices relative to the first epoch slot
pub type LeaderScheduleByIdentity = HashMap<String, Vec<usize>>;

pub fn leader_schedule_by_identity<'a>(
    upcoming_leaders: impl Iterator<Item = (usize, &'a Pubkey)>,
) -> LeaderScheduleByIdentity {
    let mut leader_schedule_by_identity = HashMap::new();

    for (slot_index, identity_pubkey) in upcoming_leaders {
        leader_schedule_by_identity
            .entry(identity_pubkey)
            .or_insert_with(Vec::new)
            .push(slot_index);
    }

    leader_schedule_by_identity
        .into_iter()
        .map(|(identity_pubkey, slot_indices)| (identity_pubkey.to_string(), slot_indices))
        .collect()
}

fn num_major_stakers(stakes: &[(Pubkey, u64)]) -> usize {
    stakes
        .iter()
        .filter(|s| s.1 >= MIN_STAKERS_TO_BE_MAJORITY)
        .count()
}

fn retain_major_stakers(stakes: &mut Vec<(Pubkey, u64)>) {
    stakes.retain(|s| s.1 >= MIN_STAKERS_TO_BE_MAJORITY);
}
