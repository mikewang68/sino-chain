use std::fmt::{self, LowerHex};
use std::marker::PhantomData;
use std::str::FromStr;

use super::error::*;

use derive_more::Deref;
use primitive_types::{H160, H256, H512, U128, U256, U512};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use snafu::ResultExt;

#[derive(Debug, Default, Hash, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deref)]
pub struct Hex<T>(pub T);

#[derive(Debug, Clone)]
pub struct Bytes(pub Vec<u8>);

fn format_hex_trimmed<T: LowerHex>(val: &T) -> String {
    let hex_str = format!("{:x}", val);
    format!("0x{}", hex_str.trim_start_matches('0'))
}

impl<T: FormatHex> Hex<T> {
    pub fn from_hex(data: &str) -> Result<Self, Error> {
        if data.len() < 2 || &data[0..2] != "0x" {
            return InvalidHexPrefix {
                input_data: data.to_string(),
            }
            .fail();
        }
        let result = if data.len() == 2 {
            T::from_hex("0")?
        } else {
            T::from_hex(&data[2..])?
        };
        Ok(Hex(result))
    }
}

impl<T: FormatHex> std::str::FromStr for Hex<T> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        Self::from_hex(s)
    }
}

impl std::str::FromStr for Bytes {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() < 2 || &s[..2] != "0x" {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        if s.len() == 2 {
            return Ok(Bytes(vec![]));
        }

        match hex::decode(&s[2..]) {
            Ok(d) => Ok(Bytes(d)),
            Err(e) => Err(e),
        }
    }
}

impl<T: FormatHex> std::fmt::Display for Hex<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.format_hex())
    }
}

impl std::fmt::Display for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", &hex::encode(&self.0))
    }
}

pub trait FormatHex {
    fn format_hex(&self) -> String;
    fn from_hex(data: &str) -> Result<Self, Error>
    where
        Self: Sized;
}

impl FormatHex for usize {
    fn format_hex(&self) -> String {
        format_hex_trimmed(self)
    }

    fn from_hex(data: &str) -> Result<Self, Error> {
        Self::from_str_radix(data, 16).with_context(|_| IntError {
            input_data: data.to_string(),
        })
    }
}

impl FormatHex for u8 {
    fn format_hex(&self) -> String {
        format_hex_trimmed(self)
    }
    fn from_hex(data: &str) -> Result<Self, Error> {
        Self::from_str_radix(data, 16).with_context(|_| IntError {
            input_data: data.to_string(),
        })
    }
}

impl FormatHex for u16 {
    fn format_hex(&self) -> String {
        format_hex_trimmed(self)
    }
    fn from_hex(data: &str) -> Result<Self, Error> {
        Self::from_str_radix(data, 16).with_context(|_| IntError {
            input_data: data.to_string(),
        })
    }
}
impl FormatHex for u32 {
    fn format_hex(&self) -> String {
        format_hex_trimmed(self)
    }
    fn from_hex(data: &str) -> Result<Self, Error> {
        Self::from_str_radix(data, 16).with_context(|_| IntError {
            input_data: data.to_string(),
        })
    }
}

impl FormatHex for u64 {
    fn format_hex(&self) -> String {
        format_hex_trimmed(self)
    }
    fn from_hex(data: &str) -> Result<Self, Error> {
        Self::from_str_radix(data, 16).with_context(|_| IntError {
            input_data: data.to_string(),
        })
    }
}

impl FormatHex for U128 {
    fn format_hex(&self) -> String {
        format_hex_trimmed(self)
    }
    fn from_hex(s: &str) -> Result<Self, Error> {
        FromStr::from_str(s).with_context(|_| BigIntError {
            input_data: s.to_string(),
        })
    }
}

impl FormatHex for U256 {
    fn format_hex(&self) -> String {
        format_hex_trimmed(self)
    }
    fn from_hex(s: &str) -> Result<Self, Error> {
        FromStr::from_str(s).with_context(|_| BigIntError {
            input_data: s.to_string(),
        })
    }
}

impl FormatHex for U512 {
    fn format_hex(&self) -> String {
        format_hex_trimmed(self)
    }
    fn from_hex(s: &str) -> Result<Self, Error> {
        FromStr::from_str(s).with_context(|_| BigIntError {
            input_data: s.to_string(),
        })
    }
}

impl FormatHex for H512 {
    fn format_hex(&self) -> String {
        format!("0x{:x}", self)
    }
    fn from_hex(s: &str) -> Result<Self, Error> {
        FromStr::from_str(s).with_context(|_| HexError {
            input_data: s.to_string(),
        })
    }
}

impl FormatHex for H256 {
    fn format_hex(&self) -> String {
        format!("0x{:x}", self)
    }
    fn from_hex(s: &str) -> Result<Self, Error> {
        FromStr::from_str(s).with_context(|_| HexError {
            input_data: s.to_string(),
        })
    }
}

impl FormatHex for H160 {
    fn format_hex(&self) -> String {
        format!("0x{:x}", self)
    }
    fn from_hex(s: &str) -> Result<Self, Error> {
        FromStr::from_str(s).with_context(|_| HexError {
            input_data: s.to_string(),
        })
    }
}

impl<T: FormatHex> Serialize for Hex<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = self.0.format_hex();
        if &value == "0x" {
            serializer.serialize_str("0x0")
        } else {
            serializer.serialize_str(&value)
        }
    }
}

impl Serialize for Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

struct HexVisitor<T> {
    _marker: PhantomData<T>,
}

impl<'de, T: FormatHex> de::Visitor<'de> for HexVisitor<T> {
    type Value = Hex<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Must be a valid hex string")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if s.len() < 3 || &s[..2] != "0x" {
            return Err(de::Error::invalid_value(de::Unexpected::Str(s), &self));
        }
        match T::from_hex(&s[2..]) {
            Ok(d) if &s[..2] == "0x" => Ok(Hex(d)),
            _ => Err(de::Error::invalid_value(de::Unexpected::Str(s), &self)),
        }
    }
}

struct BytesVisitor;

impl<'de> de::Visitor<'de> for BytesVisitor {
    type Value = Bytes;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Must be a valid hex string")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Bytes::from_str(s).map_err(|_| de::Error::invalid_value(de::Unexpected::Str(s), &self))
    }
}

impl<'de, T: FormatHex> Deserialize<'de> for Hex<T> {
    fn deserialize<D>(deserializer: D) -> Result<Hex<T>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(HexVisitor {
            _marker: PhantomData,
        })
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(BytesVisitor)
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(b: Vec<u8>) -> Self {
        Bytes(b)
    }
}
impl<T: FormatHex + FromStr> From<T> for Hex<T> {
    fn from(b: T) -> Self {
        Hex(b)
    }
}

// The starting of removing Hex type in favour of #[serde(with)] atribute
// Currently used only for nonce, because its u64, but should be serialized as HASH
pub mod hex_serde {
    use super::FormatHex;
    use serde::de;
    use serde::{de::Deserializer, ser::Serializer};
    use std::fmt;
    use std::marker::PhantomData;

    struct HexVisitor<T> {
        _marker: PhantomData<T>,
    }

    impl<'de, T: FormatHex> de::Visitor<'de> for HexVisitor<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("Must be a valid hex string")
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if s.len() < 3 || &s[..2] != "0x" {
                return Err(de::Error::invalid_value(de::Unexpected::Str(s), &self));
            }

            match T::from_hex(&s[2..]) {
                Ok(d) if &s[..2] == "0x" => Ok(d),
                _ => Err(de::Error::invalid_value(de::Unexpected::Str(s), &self)),
            }
        }
    }
    pub mod padded {

        use super::*;

        pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&format!("{:#018x}", value))
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_str(HexVisitor {
                _marker: PhantomData,
            })
        }
    }
}

