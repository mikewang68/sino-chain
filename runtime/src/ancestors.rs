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
