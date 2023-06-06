use {
    crate::{
        blockstore::Blockstore,
        leader_schedule::{FixedSchedule, LeaderSchedule},
        leader_schedule_utils,
    },
    // log::*,
    runtime::bank::Bank,
    sdk::{
        clock::{Epoch, Slot},
        epoch_schedule::EpochSchedule,
        pubkey::Pubkey,
    },
    std::{
        collections::{hash_map::Entry, HashMap, VecDeque},
        sync::{Arc, RwLock},
    },
};

type CachedSchedules = (HashMap<Epoch, Arc<LeaderSchedule>>, VecDeque<u64>);
const MAX_SCHEDULES: usize = 10;

struct CacheCapacity(usize);
impl Default for CacheCapacity {
    fn default() -> Self {
        CacheCapacity(MAX_SCHEDULES)
    }
}

#[derive(Default)]
pub struct LeaderScheduleCache {
    // Map from an epoch to a leader schedule for that epoch
    pub cached_schedules: RwLock<CachedSchedules>,
    epoch_schedule: EpochSchedule,
    max_epoch: RwLock<Epoch>,
    max_schedules: CacheCapacity,
    fixed_schedule: Option<Arc<FixedSchedule>>,
}

impl LeaderScheduleCache {
//     pub fn new_from_bank(bank: &Bank) -> Self {
//         Self::new(*bank.epoch_schedule(), bank)
//     }

//     pub fn new(epoch_schedule: EpochSchedule, root_bank: &Bank) -> Self {
//         let cache = Self {
//             cached_schedules: RwLock::new((HashMap::new(), VecDeque::new())),
//             epoch_schedule,
//             max_epoch: RwLock::new(0),
//             max_schedules: CacheCapacity::default(),
//             fixed_schedule: None,
//         };

//         // This sets the root and calculates the schedule at leader_schedule_epoch(root)
//         cache.set_root(root_bank);

//         // Calculate the schedule for all epochs between 0 and leader_schedule_epoch(root)
//         let leader_schedule_epoch = epoch_schedule.get_leader_schedule_epoch(root_bank.slot());
//         for epoch in 0..leader_schedule_epoch {
//             let first_slot_in_epoch = epoch_schedule.get_first_slot_in_epoch(epoch);
//             cache.slot_leader_at(first_slot_in_epoch, Some(root_bank));
//         }
//         cache
//     }

//     pub fn set_max_schedules(&mut self, max_schedules: usize) {
//         if max_schedules > 0 {
//             self.max_schedules = CacheCapacity(max_schedules);
//         }
//     }

    pub fn max_schedules(&self) -> usize {
        self.max_schedules.0
    }

//     pub fn set_root(&self, root_bank: &Bank) {
//         let new_max_epoch = self
//             .epoch_schedule
//             .get_leader_schedule_epoch(root_bank.slot());
//         let old_max_epoch = {
//             let mut max_epoch = self.max_epoch.write().unwrap();
//             let old_max_epoch = *max_epoch;
//             *max_epoch = new_max_epoch;
//             assert!(new_max_epoch >= old_max_epoch);
//             old_max_epoch
//         };

//         // Calculate the epoch as soon as it's rooted
//         if new_max_epoch > old_max_epoch {
//             self.compute_epoch_schedule(new_max_epoch, root_bank);
//         }
//     }

    pub fn slot_leader_at(&self, slot: Slot, bank: Option<&Bank>) -> Option<Pubkey> {
        if let Some(bank) = bank {
            self.slot_leader_at_else_compute(slot, bank)
        } else if self.epoch_schedule.slots_per_epoch == 0 {
            None
        } else {
            self.slot_leader_at_no_compute(slot)
        }
    }

//     /// Returns the (next slot, last slot) consecutive range of slots after
//     /// the given current_slot that the given node will be leader.
//     pub fn next_leader_slot(
//         &self,
//         pubkey: &Pubkey,
//         current_slot: Slot,
//         bank: &Bank,
//         blockstore: Option<&Blockstore>,
//         max_slot_range: u64,
//     ) -> Option<(Slot, Slot)> {
//         let (epoch, start_index) = bank.get_epoch_and_slot_index(current_slot + 1);
//         let max_epoch = *self.max_epoch.read().unwrap();
//         if epoch > max_epoch {
//             debug!(
//                 "Requested next leader in slot: {} of unconfirmed epoch: {}",
//                 current_slot + 1,
//                 epoch
//             );
//             return None;
//         }
//         // Slots after current_slot where pubkey is the leader.
//         let mut schedule = (epoch..=max_epoch)
//             .map(|epoch| self.get_epoch_schedule_else_compute(epoch, bank))
//             .while_some()
//             .zip(epoch..)
//             .flat_map(|(leader_schedule, k)| {
//                 let offset = if k == epoch { start_index as usize } else { 0 };
//                 let num_slots = bank.get_slots_in_epoch(k) as usize;
//                 let first_slot = bank.epoch_schedule().get_first_slot_in_epoch(k);
//                 leader_schedule
//                     .get_indices(pubkey, offset)
//                     .take_while(move |i| *i < num_slots)
//                     .map(move |i| i as Slot + first_slot)
//             })
//             .skip_while(|slot| {
//                 match blockstore {
//                     None => false,
//                     // Skip slots we have already sent a shred for.
//                     Some(blockstore) => match blockstore.meta(*slot).unwrap() {
//                         Some(meta) => meta.received > 0,
//                         None => false,
//                     },
//                 }
//             });
//         let first_slot = schedule.next()?;
//         let max_slot = first_slot.saturating_add(max_slot_range);
//         let last_slot = schedule
//             .take_while(|slot| *slot < max_slot)
//             .zip(first_slot + 1..)
//             .take_while(|(a, b)| a == b)
//             .map(|(s, _)| s)
//             .last()
//             .unwrap_or(first_slot);
//         Some((first_slot, last_slot))
//     }

//     pub fn set_fixed_leader_schedule(&mut self, fixed_schedule: Option<FixedSchedule>) {
//         self.fixed_schedule = fixed_schedule.map(Arc::new);
//     }

    fn slot_leader_at_no_compute(&self, slot: Slot) -> Option<Pubkey> {
        let (epoch, slot_index) = self.epoch_schedule.get_epoch_and_slot_index(slot);
        if let Some(ref fixed_schedule) = self.fixed_schedule {
            if epoch >= fixed_schedule.start_epoch {
                return Some(fixed_schedule.leader_schedule[slot_index]);
            }
        }
        self.cached_schedules
            .read()
            .unwrap()
            .0
            .get(&epoch)
            .map(|schedule| schedule[slot_index])
    }

    fn slot_leader_at_else_compute(&self, slot: Slot, bank: &Bank) -> Option<Pubkey> {
        let cache_result = self.slot_leader_at_no_compute(slot);
        // Forbid asking for slots in an unconfirmed epoch
        let bank_epoch = self.epoch_schedule.get_epoch_and_slot_index(slot).0;
        if bank_epoch > *self.max_epoch.read().unwrap() {
            debug!(
                "Requested leader in slot: {} of unconfirmed epoch: {}",
                slot, bank_epoch
            );
            return None;
        }
        if cache_result.is_some() {
            cache_result
        } else {
            let (epoch, slot_index) = bank.get_epoch_and_slot_index(slot);
            self.compute_epoch_schedule(epoch, bank)
                .map(|epoch_schedule| epoch_schedule[slot_index])
        }
    }

//     pub fn get_epoch_leader_schedule(&self, epoch: Epoch) -> Option<Arc<LeaderSchedule>> {
//         self.cached_schedules.read().unwrap().0.get(&epoch).cloned()
//     }

//     fn get_epoch_schedule_else_compute(
//         &self,
//         epoch: Epoch,
//         bank: &Bank,
//     ) -> Option<Arc<LeaderSchedule>> {
//         if let Some(ref fixed_schedule) = self.fixed_schedule {
//             if epoch >= fixed_schedule.start_epoch {
//                 return Some(fixed_schedule.leader_schedule.clone());
//             }
//         }
//         let epoch_schedule = self.get_epoch_leader_schedule(epoch);
//         if epoch_schedule.is_some() {
//             epoch_schedule
//         } else {
//             self.compute_epoch_schedule(epoch, bank)
//         }
//     }

    fn compute_epoch_schedule(&self, epoch: Epoch, bank: &Bank) -> Option<Arc<LeaderSchedule>> {
        let leader_schedule = leader_schedule_utils::leader_schedule(epoch, bank);
        leader_schedule.map(|leader_schedule| {
            let leader_schedule = Arc::new(leader_schedule);
            let (ref mut cached_schedules, ref mut order) = *self.cached_schedules.write().unwrap();
            // Check to see if schedule exists in case somebody already inserted in the time we were
            // waiting for the lock
            let entry = cached_schedules.entry(epoch);
            if let Entry::Vacant(v) = entry {
                v.insert(leader_schedule.clone());
                order.push_back(epoch);
                Self::retain_latest(cached_schedules, order, self.max_schedules());
            }
            leader_schedule
        })
    }

    fn retain_latest(
        schedules: &mut HashMap<Epoch, Arc<LeaderSchedule>>,
        order: &mut VecDeque<u64>,
        max_schedules: usize,
    ) {
        while schedules.len() > max_schedules {
            let first = order.pop_front().unwrap();
            schedules.remove(&first);
        }
    }
}
