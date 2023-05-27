use primitive_types::H256;
use serde::{Deserialize, Serialize};

use crate::cache::Caching;
use crate::gc::{MapWithCounterCachedParam, RootGuard, TrieCollection};
use crate::TrieMut;

#[derive(Eq, PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DataWithRoot {
    pub root: H256,
}

impl DataWithRoot {
    pub fn get_childs(data: &[u8]) -> Vec<H256> {
        bincode::deserialize::<Self>(data)
            .ok()
            .into_iter()
            .map(|e| e.root)
            .collect()
    }
}
impl Default for DataWithRoot {
    fn default() -> Self {
        Self {
            root: crate::empty_trie_hash!(),
        }
    }
}
pub fn insert_element<'a, F, C: Caching>(
    collection: &'a TrieCollection<MapWithCounterCachedParam<C>>,
    account_key: &[u8],
    data_key: &[u8],
    data: &[u8],
    input_root: H256,
    child_extractor: F,
) -> RootGuard<'a, MapWithCounterCachedParam<C>, F>
where
    F: FnMut(&[u8]) -> Vec<H256> + Clone,
{
    // Insert to first db
    let mut account_trie = collection.trie_for(input_root);
    let mut account: DataWithRoot = TrieMut::get(&account_trie, account_key)
        .map(|d| bincode::deserialize(&d).unwrap())
        .unwrap_or_default();
    let mut storage_trie = collection.trie_for(account.root);
    storage_trie.insert(data_key, data);
    let storage_patch = storage_trie.into_patch();
    log::trace!(
        "1 Update account root: old {}, new {}",
        account.root,
        storage_patch.root
    );
    account.root = storage_patch.root;
    account_trie.insert(account_key, &bincode::serialize(&account).unwrap());
    let mut account_patch = account_trie.into_patch();
    account_patch.change.merge_child(&storage_patch.change);

    collection.apply_increase(account_patch, child_extractor)
}
