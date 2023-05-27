use std::borrow::Borrow;

use crate::{
    merkle::{nibble::Entry, Branch, Extension, Leaf, MerkleNode, MerkleValue},
    Database,
};
use primitive_types::H256;
use rlp::Rlp;

use crate::merkle::nibble::NibbleVec;
use anyhow::Result;
use log::*;

use inspector::{TrieDataInsectorRaw, TrieInspector};

pub mod inspector;

pub struct Walker<DB, TI, DI> {
    db: DB,
    pub trie_inspector: TI,
    pub data_inspector: DI,
}

impl<DB, TI, DI> Walker<DB, TI, DI> {
    pub fn new_raw(db: DB, trie_inspector: TI, data_inspector: DI) -> Self {
        Self {
            db,
            trie_inspector,
            data_inspector,
        }
    }
}

impl<DB, TI, DI> Walker<DB, TI, DI>
where
    DB: Database + Sync + Send,
    TI: TrieInspector + Sync + Send,
    DI: TrieDataInsectorRaw + Sync + Send,
{
    pub fn traverse(&self, hash: H256) -> Result<()> {
        self.traverse_inner(Default::default(), hash)
    }
    pub fn traverse_inner(&self, nibble: NibbleVec, hash: H256) -> Result<()> {
        debug!("traversing {:?} ...", hash);
        if hash != crate::empty_trie_hash() {
            let db = self.db.borrow();
            let bytes = db.get(hash);
            trace!("raw bytes: {:?}", bytes);

            let rlp = Rlp::new(bytes);
            trace!("rlp: {:?}", rlp);
            let node = MerkleNode::decode(&rlp)?;
            debug!("node: {:?}", node);

            self.process_node(Entry::new(nibble, &node))?;

            // process node after inspection, to copy root later than it's data, to make sure that all roots are correct links
            self.trie_inspector.inspect_node(hash, bytes)?;
        } else {
            debug!("skip empty trie");
        }

        Ok(())
    }

    // fn process_node(&self, mut nibble: NibbleVec, node: &MerkleNode) -> Result<()> {
    fn process_node(&self, mut entry: Entry<&MerkleNode>) -> Result<()> {
        match entry.value {
            MerkleNode::Leaf(Leaf { nibbles, data }) => {
                entry.nibble.extend_from_slice(nibbles);
                let key = crate::merkle::nibble::into_key(&entry.nibble);
                self.data_inspector.inspect_data_raw(key, data)
            }
            MerkleNode::Extension(Extension { nibbles, value }) => {
                entry.nibble.extend_from_slice(nibbles);
                self.process_value(Entry::new(entry.nibble, value))
            }
            MerkleNode::Branch(Branch {
                childs: values,
                data: maybe_data,
            }) => {
                // lack of copy on result, forces setting array manually
                let mut values_result = [
                    None, None, None, None, None, None, None, None, None, None, None, None, None,
                    None, None, None,
                ];
                let result = rayon::scope(|s| {
                    for (index, (value, result)) in
                        values.iter().zip(&mut values_result).enumerate()
                    {
                        let mut key = entry.nibble.clone();
                        s.spawn(move |_| {
                            key.push(index.into());
                            *result = Some(self.process_value(Entry::new(key, value)))
                        });
                    }
                    if let Some(data) = maybe_data {
                        let key: Vec<u8> = crate::merkle::nibble::into_key(&entry.nibble);
                        self.data_inspector.inspect_data_raw(key, data)
                    } else {
                        Ok(())
                    }
                });
                for result in values_result {
                    result.unwrap()?
                }
                result
            }
        }
    }

    fn process_value(&self, entry: Entry<&MerkleValue>) -> Result<()> {
        match entry.value {
            MerkleValue::Empty => Ok(()),
            MerkleValue::Full(node) => self.process_node(Entry::new(entry.nibble, node)),
            MerkleValue::Hash(hash) => self.traverse_inner(entry.nibble, *hash),
        }
    }
}
