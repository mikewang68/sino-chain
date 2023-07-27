use {crate::accounts_index::RollingBitField, sdk::clock::Slot, std::collections::HashMap};

pub type AncestorsForSerialization = HashMap<Slot, usize>;

#[derive(Debug, Clone, PartialEq, AbiExample)]
pub struct Ancestors {
    ancestors: RollingBitField,
}

// some tests produce ancestors ranges that are too large such
// that we prefer to implement them in a sparse HashMap
const ANCESTORS_HASH_MAP_SIZE: u64 = 8192;

impl Default for Ancestors {
    fn default() -> Self {
        Self {
            ancestors: RollingBitField::new(ANCESTORS_HASH_MAP_SIZE),
        }
    }
}

impl From<Vec<Slot>> for Ancestors {
    fn from(mut source: Vec<Slot>) -> Ancestors {
        // bitfield performs optimally when we insert the minimum value first so that it knows the correct start/end values
        source.sort_unstable();
        let mut result = Ancestors::default();
        source.into_iter().for_each(|slot| {
            result.ancestors.insert(slot);
        });

        result
    }
}

impl From<&HashMap<Slot, usize>> for Ancestors {
    fn from(source: &HashMap<Slot, usize>) -> Ancestors {
        let vec = source.iter().map(|(slot, _)| *slot).collect::<Vec<_>>();
        Ancestors::from(vec)
    }
}

impl From<&Ancestors> for HashMap<Slot, usize> {
    fn from(source: &Ancestors) -> HashMap<Slot, usize> {
        let mut result = HashMap::with_capacity(source.len());
        source.keys().iter().for_each(|slot| {
            result.insert(*slot, 0);
        });
        result
    }
}

impl Ancestors {
    pub fn keys(&self) -> Vec<Slot> {
        self.ancestors.get_all()
    }

    pub fn get(&self, slot: &Slot) -> bool {
        self.ancestors.contains(slot)
    }

    pub fn remove(&mut self, slot: &Slot) {
        self.ancestors.remove(slot);
    }

    pub fn contains_key(&self, slot: &Slot) -> bool {
        self.ancestors.contains(slot)
    }

    pub fn len(&self) -> usize {
        self.ancestors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn max_slot(&self) -> Slot {
        self.ancestors.max() - 1
    }
}
#[cfg(test)]
pub mod tests {
    use {
        super::*, crate::contains::Contains, log::*, measure::measure::Measure,
        std::collections::HashSet,
    };

    impl std::iter::FromIterator<(Slot, usize)> for Ancestors {
        fn from_iter<I>(iter: I) -> Self
        where
            I: IntoIterator<Item = (Slot, usize)>,
        {
            let mut data = Vec::new();
            for i in iter {
                data.push(i);
            }
            Ancestors::from(data)
        }
    }

    impl From<Vec<(Slot, usize)>> for Ancestors {
        fn from(source: Vec<(Slot, usize)>) -> Ancestors {
            Ancestors::from(source.into_iter().map(|(slot, _)| slot).collect::<Vec<_>>())
        }
    }
    impl Ancestors {
        pub fn insert(&mut self, slot: Slot, _size: usize) {
            self.ancestors.insert(slot);
        }
    }

    #[test]
    fn test_ancestors_permutations() {
        sino_logger::setup();
        let mut ancestors = Ancestors::default();
        let mut hash = HashMap::new();

        let min = 101_000;
        let width = 400_000;
        let dead = 19;

        let mut slot = min;
        while hash.len() < width {
            slot += 1;
            if slot % dead == 0 {
                continue;
            }
            hash.insert(slot, 0);
            ancestors.insert(slot, 0);
        }
        compare_ancestors(&hash, &ancestors);

        let max = slot + 1;

        let mut time = Measure::start("");
        let mut count = 0;
        for slot in (min - 10)..max + 100 {
            if hash.contains(&slot) {
                count += 1;
            }
        }
        time.stop();

        let mut time2 = Measure::start("");
        let mut count2 = 0;
        for slot in (min - 10)..max + 100 {
            if ancestors.contains_key(&slot) {
                count2 += 1;
            }
        }
        time2.stop();
        info!(
            "{}ms, {}ms, {} ratio",
            time.as_ms(),
            time2.as_ms(),
            time.as_ns() / time2.as_ns()
        );
        assert_eq!(count, count2);
    }

    fn compare_ancestors(hashset: &HashMap<u64, usize>, ancestors: &Ancestors) {
        assert_eq!(hashset.len(), ancestors.len());
        assert_eq!(hashset.is_empty(), ancestors.is_empty());
        let mut min = u64::MAX;
        let mut max = 0;
        for item in hashset.iter() {
            let key = item.0;
            min = std::cmp::min(min, *key);
            max = std::cmp::max(max, *key);
            assert!(ancestors.get(key));
        }
        for slot in min - 1..max + 2 {
            assert_eq!(ancestors.get(&slot), hashset.contains(&slot));
        }
    }

    #[test]
    fn test_ancestors_smaller() {
        sino_logger::setup();

        for width in 0..34 {
            let mut hash = HashSet::new();

            let min = 1_010_000;
            let dead = 19;

            let mut slot = min;
            let mut slots = Vec::new();
            while hash.len() < width {
                slot += 1;
                if slot % dead == 0 {
                    continue;
                }
                hash.insert(slot);
                slots.push((slot, 0));
            }
            let ancestors = Ancestors::from(slots);

            let max = slot + 1;
            let passes = 1;
            let mut time = Measure::start("");
            let mut count = 0;
            for _pass in 0..passes {
                for slot in (min - 10)..max + 100 {
                    if hash.contains(&slot) {
                        count += 1;
                    }
                }
            }
            time.stop();

            let mut time2 = Measure::start("");
            let mut count2 = 0;
            for _pass in 0..passes {
                for slot in (min - 10)..max + 100 {
                    if ancestors.contains_key(&slot) {
                        count2 += 1;
                    }
                }
            }
            time2.stop();
            info!(
                "{}, {}, {}",
                time.as_ms(),
                time2.as_ms(),
                time.as_ns() / time2.as_ns()
            );
            assert_eq!(count, count2);
        }
    }
}
