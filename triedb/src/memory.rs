use std::collections::HashMap;

use primitive_types::H256;

use crate::{
    build, delete, empty_trie_hash, get, insert, AnySecureTrieMut, AnyTrieMut, Change,
    FixedSecureTrieMut, FixedTrieMut, SecureTrieMut, TrieMut,
};

/// A memory-backed trie.
#[derive(Clone, Debug)]
pub struct MemoryTrieMut {
    database: HashMap<H256, Vec<u8>>,
    root: H256,
}

/// A memory-backed trie where the value is operated on a fixed RLP
/// value type.
pub type FixedMemoryTrieMut<K, V> = FixedTrieMut<MemoryTrieMut, K, V>;
/// A memory-backed trie where the key is hashed and the value is
/// operated on a fixed RLP value type.
pub type FixedSecureMemoryTrieMut<K, V> = FixedSecureTrieMut<MemoryTrieMut, K, V>;
/// A memory-backed trie where the key is hashed.
pub type SecureMemoryTrieMut = SecureTrieMut<MemoryTrieMut>;
/// A memory-backed trie where the value is operated on any RLP
/// values.
pub type AnyMemoryTrieMut = AnyTrieMut<MemoryTrieMut>;
/// A memory-backed trie where the key is hashed and the value is
/// operated on any RLP values.
pub type AnySecureMemoryTrieMut = AnySecureTrieMut<MemoryTrieMut>;

impl Default for MemoryTrieMut {
    fn default() -> Self {
        Self {
            database: HashMap::new(),
            root: empty_trie_hash!(),
        }
    }
}

impl From<MemoryTrieMut> for HashMap<H256, Vec<u8>> {
    fn from(trie: MemoryTrieMut) -> HashMap<H256, Vec<u8>> {
        trie.database
    }
}

impl TrieMut for MemoryTrieMut {
    fn root(&self) -> H256 {
        self.root
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) {
        let (new_root, change) = insert(self.root, &self.database, key, value);

        self.apply_change(change);
        self.root = new_root;
    }

    fn delete(&mut self, key: &[u8]) {
        let (new_root, change) = delete(self.root, &self.database, key);

        self.apply_change(change);
        self.root = new_root;
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        get(self.root, &self.database, key).map(|v| v.into())
    }
}

impl MemoryTrieMut {
    fn apply_change(&mut self, change: Change) {
        for (key, v) in &change.changes {
            if let Some(v) = v {
                self.database.insert(*key, v.clone().into());
            } else {
                self.database.remove(key);
            }
        }
    }

    /// Build a memory trie from a map.
    pub fn build(map: &HashMap<Vec<u8>, Vec<u8>>) -> Self {
        let (new_root, change) = build(map);

        let mut ret = Self::default();
        ret.apply_change(change);
        ret.root = new_root;

        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use std::str::FromStr;

    #[test]
    fn trie_middle_leaf() {
        let mut map = HashMap::new();
        map.insert(
            "key1aa".as_bytes().into(),
            "0123456789012345678901234567890123456789xxx"
                .as_bytes()
                .into(),
        );
        map.insert(
            "key1".as_bytes().into(),
            "0123456789012345678901234567890123456789Very_Long"
                .as_bytes()
                .into(),
        );
        map.insert("key2bb".as_bytes().into(), "aval3".as_bytes().into());
        map.insert("key2".as_bytes().into(), "short".as_bytes().into());
        map.insert("key3cc".as_bytes().into(), "aval3".as_bytes().into());
        map.insert(
            "key3".as_bytes().into(),
            "1234567890123456789012345678901".as_bytes().into(),
        );

        let btrie = MemoryTrieMut::build(&map);

        assert_eq!(
            btrie.root(),
            H256::from_str("cb65032e2f76c48b82b5c24b3db8f670ce73982869d38cd39a624f23d62a9e89")
                .unwrap()
        );
        assert_eq!(
            btrie.get("key2bb".as_bytes()),
            Some("aval3".as_bytes().into())
        );
        assert_eq!(btrie.get("key2bbb".as_bytes()), None);

        let mut mtrie = MemoryTrieMut::default();
        for (key, value) in &map {
            mtrie.insert(key, value);
        }

        assert_eq!(btrie.database, mtrie.database);

        mtrie.insert("key2bbb".as_bytes(), "aval4".as_bytes());
        mtrie.delete("key2bbb".as_bytes());

        assert_eq!(btrie.database, mtrie.database);

        for key in map.keys() {
            mtrie.delete(key);
        }

        assert!(mtrie.database.is_empty());
        assert!(mtrie.root == empty_trie_hash!());
    }

    #[test]
    fn trie_two_keys() {
        let mut mtrie = MemoryTrieMut::default();
        mtrie.insert("key1".as_bytes(), "aval1".as_bytes());
        mtrie.insert("key2bb".as_bytes(), "aval3".as_bytes());
        let db1 = mtrie.database.clone();

        mtrie.insert("key2bbb".as_bytes(), "aval4".as_bytes());
        mtrie.delete("key2bbb".as_bytes());

        assert_eq!(db1, mtrie.database);
    }

    #[test]
    fn trie_multiple_prefixed_keys() {
        let key1 = &hex!("af");
        let key2 = &hex!("a2");
        let key3 = &hex!("b3");
        let keyc = &hex!("bf");
        let val = &hex!("bb");
        let mut mtrie = MemoryTrieMut::default();
        mtrie.insert(key1, val);
        mtrie.insert(key2, val);
        mtrie.insert(key3, val);
        mtrie.insert(keyc, val);
        mtrie.delete(keyc);

        assert_eq!(mtrie.get(key1).unwrap(), val);
        assert_eq!(mtrie.get(key2).unwrap(), val);
        assert_eq!(mtrie.get(key3).unwrap(), val);
    }
}
