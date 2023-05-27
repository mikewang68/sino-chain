use std::collections::HashMap;
use std::fmt;

use serde::de::{Deserialize, SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserializer, Serialize, Serializer};

#[derive(Clone, Default, Eq, PartialEq, Hash)]
pub struct EntriesHex {
    pub data: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

impl EntriesHex {
    pub fn new(data: Vec<(Vec<u8>, Option<Vec<u8>>)>) -> Self {
        // log::info!("{}", serde_json::to_string_pretty(&res).unwrap());
        Self { data }
    }

    pub fn join(&self, other: &Self) -> Self {
        let mut join_map: HashMap<Vec<u8>, Option<Vec<u8>>> = HashMap::new();

        for (key, val) in &self.data {
            join_map.insert(key.clone(), val.clone());
        }
        for (key, val) in &other.data {
            join_map.insert(key.clone(), val.clone());
        }

        let mut join_entries = vec![];
        for (key, val) in join_map.into_iter() {
            join_entries.push((key, val));
        }
        Self::new(join_entries)
    }
}

#[derive(Clone)]
pub struct InnerEntriesHex {
    pub data: Vec<(Vec<u8>, EntriesHex)>,
}

impl InnerEntriesHex {
    pub fn new(data: Vec<(Vec<u8>, EntriesHex)>) -> Self {
        let res = Self { data };
        log::info!("{}", serde_json::to_string_pretty(&res).unwrap());
        res
    }

    pub fn join(&self, other: &Self) -> Self {
        let mut join_map: HashMap<Vec<u8>, EntriesHex> = HashMap::new();

        for (key, val) in &self.data {
            join_map.insert(key.clone(), val.clone());
        }
        for (key, val) in &other.data {
            let entry = join_map.entry(key.clone()).or_default();
            *entry = entry.join(val);
        }

        let mut join_entries = vec![];
        for (key, val) in join_map.into_iter() {
            join_entries.push((key, val));
        }
        Self::new(join_entries)
    }
}

impl Serialize for EntriesHex {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.data.len()))?;
        for (key, value) in &self.data {
            let tuple: (String, Option<String>) = (
                hexutil::to_hex(key),
                value.as_ref().map(|value| hexutil::to_hex(value)),
            );
            seq.serialize_element(&tuple)?;
        }
        seq.end()
    }
}
struct TestInputHexVisitor;

impl<'de> Visitor<'de> for TestInputHexVisitor {
    type Value = EntriesHex;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("struct TestInputHex")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let mut out: Vec<(Vec<u8>, Option<Vec<u8>>)> = vec![];
        let mut element: Option<(String, Option<String>)> = seq.next_element()?;
        while let Some((key, value)) = element {
            let key_vec: Vec<u8> = hexutil::read_hex(&key).map_err(|err| {
                serde::de::Error::invalid_value(
                    serde::de::Unexpected::Str(&format!("{:?}", err)),
                    &self,
                )
            })?;
            let value_vec: Option<Vec<u8>> = match value {
                Some(value) => Some(hexutil::read_hex(&value).map_err(|err| {
                    serde::de::Error::invalid_value(
                        serde::de::Unexpected::Str(&format!("{:?}", err)),
                        &self,
                    )
                })?),
                None => None,
            };
            out.push((key_vec, value_vec));
            element = seq.next_element()?;
        }
        Ok(EntriesHex::new(out))
    }
}

impl<'de> Deserialize<'de> for EntriesHex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Instantiate our Visitor and ask the Deserializer to drive
        // it over the input data, resulting in an instance of MyMap.
        deserializer.deserialize_seq(TestInputHexVisitor)
    }
}

impl Serialize for InnerEntriesHex {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.data.len()))?;
        for (key, value) in &self.data {
            let tuple: (String, &EntriesHex) = (hexutil::to_hex(key), value);
            seq.serialize_element(&tuple)?;
        }
        seq.end()
    }
}
struct TestInputHexVisitorInner;

impl<'de> Visitor<'de> for TestInputHexVisitorInner {
    type Value = InnerEntriesHex;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("struct TestInputHex")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let mut out = vec![];
        let mut element: Option<(String, EntriesHex)> = seq.next_element()?;
        while let Some((key, value)) = element {
            let key_vec: Vec<u8> = hexutil::read_hex(&key).map_err(|err| {
                serde::de::Error::invalid_value(
                    serde::de::Unexpected::Str(&format!("{:?}", err)),
                    &self,
                )
            })?;
            out.push((key_vec, value));
            element = seq.next_element()?;
        }
        Ok(InnerEntriesHex::new(out))
    }
}

impl<'de> Deserialize<'de> for InnerEntriesHex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Instantiate our Visitor and ask the Deserializer to drive
        // it over the input data, resulting in an instance of MyMap.
        deserializer.deserialize_seq(TestInputHexVisitorInner)
    }
}
