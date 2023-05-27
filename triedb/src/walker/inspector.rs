use std::sync::Arc;

use anyhow::{ensure, Result};
use log::*;
use primitive_types::H256;

pub trait TrieInspector {
    fn inspect_node<Data: AsRef<[u8]>>(&self, trie_key: H256, node: Data) -> Result<bool>;
}
pub trait DataInspector<K, V> {
    fn inspect_data(&self, key: K, value: V) -> Result<()>;
}

pub trait TrieDataInsectorRaw {
    fn inspect_data_raw<Data: AsRef<[u8]>>(&self, key: Vec<u8>, value: Data) -> Result<()>;
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct NoopInspector;

// secure-triedb specific encoding.
// key - H256, data is rlp decodable
pub mod encoding {
    use super::*;
    use std::marker::PhantomData;

    #[derive(Default, Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
    pub struct SecTrie<T, K, V> {
        pub inner: T,
        _pd: PhantomData<(K, V)>,
    }

    impl<T, K, V> TrieDataInsectorRaw for SecTrie<T, K, V>
    where
        T: DataInspector<K, V>,
        K: TryFromSlice,
        V: rlp::Decodable,
    {
        fn inspect_data_raw<Data: AsRef<[u8]>>(&self, key: Vec<u8>, value: Data) -> Result<()> {
            let key = TryFromSlice::try_from_slice(&key)?;
            let value = data_from_bytes(value)?;
            self.inner.inspect_data(key, value)
        }
    }

    impl<K, V, T: DataInspector<K, V>> DataInspector<K, V> for SecTrie<T, K, V> {
        fn inspect_data(&self, key: K, value: V) -> Result<()> {
            self.inner.inspect_data(key, value)
        }
    }

    impl<K, V, T: TrieInspector> TrieInspector for SecTrie<T, K, V> {
        fn inspect_node<Data: AsRef<[u8]>>(&self, trie_key: H256, node: Data) -> Result<bool> {
            self.inner.inspect_node(trie_key, node)
        }
    }

    pub trait TryFromSlice {
        fn try_from_slice(slice: &[u8]) -> Result<Self>
        where
            Self: Sized;
    }

    impl TryFromSlice for H256 {
        fn try_from_slice(slice: &[u8]) -> Result<Self>
        where
            Self: Sized,
        {
            ensure!(
                slice.len() == 32,
                "Cannot get H256 from slice len:{}",
                slice.len()
            );

            Ok(H256::from_slice(slice))
        }
    }

    fn data_from_bytes<Data: AsRef<[u8]>, Value>(data: Data) -> Result<Value>
    where
        Value: rlp::Decodable,
    {
        let rlp = rlp::Rlp::new(data.as_ref());
        trace!("rlp: {:?}", rlp);
        let t = Value::decode(&rlp)?;
        Ok(t)
    }
}

impl<K, V> DataInspector<K, V> for NoopInspector {
    fn inspect_data(&self, _key: K, _value: V) -> Result<()> {
        Ok(())
    }
}

impl TrieInspector for NoopInspector {
    fn inspect_node<Data: AsRef<[u8]>>(&self, _trie_key: H256, _node: Data) -> Result<bool> {
        Ok(false)
    }
}

impl TrieDataInsectorRaw for NoopInspector {
    fn inspect_data_raw<Data: AsRef<[u8]>>(&self, _key: Vec<u8>, _value: Data) -> Result<()> {
        Ok(())
    }
}

impl<K, V, T: DataInspector<K, V>> DataInspector<K, V> for Arc<T> {
    fn inspect_data(&self, key: K, value: V) -> Result<()> {
        self.as_ref().inspect_data(key, value)
    }
}

impl<T: TrieInspector> TrieInspector for Arc<T> {
    fn inspect_node<Data: AsRef<[u8]>>(&self, trie_key: H256, node: Data) -> Result<bool> {
        self.as_ref().inspect_node(trie_key, node)
    }
}

impl<T: TrieDataInsectorRaw> TrieDataInsectorRaw for Arc<T> {
    fn inspect_data_raw<Data: AsRef<[u8]>>(&self, key: Vec<u8>, value: Data) -> Result<()> {
        self.as_ref().inspect_data_raw(key, value)
    }
}
