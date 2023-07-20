use {
    crate::accounts_db::SnapshotStorage, log::*, measure::measure::Measure,
    sdk::clock::Slot, std::ops::Range,
};

pub struct SortedStorages<'a> {
    range: Range<Slot>,
    storages: Vec<Option<&'a SnapshotStorage>>,
    slot_count: usize,
    storage_count: usize,
}

impl<'a> SortedStorages<'a> {
    pub fn get(&self, slot: Slot) -> Option<&SnapshotStorage> {
        if !self.range.contains(&slot) {
            None
        } else {
            let index = (slot - self.range.start) as usize;
            self.storages[index]
        }
    }

    pub fn range_width(&self) -> Slot {
        self.range.end - self.range.start
    }

    pub fn range(&self) -> &Range<Slot> {
        &self.range
    }

    pub fn slot_count(&self) -> usize {
        self.slot_count
    }

    pub fn storage_count(&self) -> usize {
        self.storage_count
    }

    // assumptions:
    // 1. each SnapshotStorage.!is_empty()
    // 2. SnapshotStorage.first().unwrap().get_slot() is unique from all other SnapshotStorage items.
    pub fn new(source: &'a [SnapshotStorage]) -> Self {
        let slots = source
            .iter()
            .map(|storages| {
                let first = storages.first();
                assert!(first.is_some(), "SnapshotStorage.is_empty()");
                let storage = first.unwrap();
                storage.slot() // this must be unique. Will be enforced in new_with_slots
            })
            .collect::<Vec<_>>();
        Self::new_with_slots(source.iter().zip(slots.iter()), None, None)
    }

    // source[i] is in slot slots[i]
    // assumptions:
    // 1. slots vector contains unique slot #s.
    // 2. slots and source are the same len
    pub fn new_with_slots<'b>(
        source: impl Iterator<Item = (&'a SnapshotStorage, &'b Slot)> + Clone,
        // A slot used as a lower bound, but potentially smaller than the smallest slot in the given 'source' iterator
        min_slot: Option<Slot>,
        // highest valid slot. Only matters if source array does not contain a slot >= max_slot_inclusive.
        // An example is a slot that has accounts in the write cache at slots <= 'max_slot_inclusive' but no storages at those slots.
        // None => self.range.end = source.1.max() + 1
        // Some(slot) => self.range.end = std::cmp::max(slot, source.1.max())
        max_slot_inclusive: Option<Slot>,
    ) -> Self {
        let mut min = Slot::MAX;
        let mut max = Slot::MIN;
        let mut adjust_min_max = |slot| {
            min = std::cmp::min(slot, min);
            max = std::cmp::max(slot + 1, max);
        };
        // none, either, or both of min/max could be specified
        if let Some(slot) = min_slot {
            adjust_min_max(slot);
        }
        if let Some(slot) = max_slot_inclusive {
            adjust_min_max(slot);
        }

        let mut slot_count = 0;
        let mut time = Measure::start("get slot");
        let source_ = source.clone();
        let mut storage_count = 0;
        source_.for_each(|(storages, slot)| {
            storage_count += storages.len();
            slot_count += 1;
            adjust_min_max(*slot);
        });
        time.stop();
        let mut time2 = Measure::start("sort");
        let range;
        let mut storages;
        if min > max {
            range = Range::default();
            storages = vec![];
        } else {
            range = Range {
                start: min,
                end: max,
            };
            let len = max - min;
            storages = vec![None; len as usize];
            source.for_each(|(original_storages, slot)| {
                let index = (slot - min) as usize;
                assert!(storages[index].is_none(), "slots are not unique"); // we should not encounter the same slot twice
                storages[index] = Some(original_storages);
            });
        }
        time2.stop();
        debug!("SortedStorages, times: {}, {}", time.as_us(), time2.as_us());
        Self {
            range,
            storages,
            slot_count,
            storage_count,
        }
    }
}