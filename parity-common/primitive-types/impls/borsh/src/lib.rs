//! Borsh serialization support for uint and fixed hash.

#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[doc(hidden)]
pub use borsh;

pub const ERROR_UNEXPECTED_LENGTH_OF_INPUT: &str = "Unexpected length of input";

/// Add Borsh serialization support to an integer created by `construct_uint!`.
#[macro_export]
macro_rules! impl_uint_borsh {
	($name: ident, $len: expr) => {
		impl $crate::borsh::BorshSerialize for $name {
			#[inline]
			fn serialize<W: $crate::borsh::maybestd::io::Write>(
				&self,
				writer: &mut W,
			) -> $crate::borsh::maybestd::io::Result<()> {
				let mut bytes = [0u8; $len * 8];
				self.to_little_endian(&mut bytes);
				writer.write_all(&bytes)?;
				Ok(())
			}
		}

		impl $crate::borsh::BorshDeserialize for $name {
			#[inline]
			fn deserialize(buf: &mut &[u8]) -> $crate::borsh::maybestd::io::Result<Self> {
				if buf.len() < ($len * 8) {
					return Err($crate::borsh::maybestd::io::Error::new(
						$crate::borsh::maybestd::io::ErrorKind::InvalidInput,
						$crate::ERROR_UNEXPECTED_LENGTH_OF_INPUT,
					))
				}
				let res = Self::from_little_endian(&buf[..($len * 8)]);
				*buf = &buf[($len * 8)..];
				Ok(res)
			}
		}

		impl $crate::borsh::BorshSchema for $name {
			fn add_definitions_recursively(
				definitions: &mut $crate::borsh::maybestd::collections::HashMap<
					$crate::borsh::schema::Declaration,
					$crate::borsh::schema::Definition,
				>,
			) {
				let definition =
					$crate::borsh::schema::Definition::Array { length: $len, elements: u64::declaration() };
				Self::add_definition(Self::declaration(), definition, definitions);
			}
			fn declaration() -> $crate::borsh::schema::Declaration {
				stringify!($name).to_string()
			}
		}
	};
}

/// Add Borsh serialization support to a fixed-sized hash type created by `construct_fixed_hash!`.
#[macro_export]
macro_rules! impl_fixed_hash_borsh {
	($name: ident, $len: expr) => {
		impl $crate::borsh::BorshSerialize for $name {
			#[inline]
			fn serialize<W: $crate::borsh::maybestd::io::Write>(
				&self,
				writer: &mut W,
			) -> $crate::borsh::maybestd::io::Result<()> {
				writer.write_all(self.as_bytes())?;
				Ok(())
			}
		}

		impl $crate::borsh::BorshDeserialize for $name {
			#[inline]
			fn deserialize(buf: &mut &[u8]) -> $crate::borsh::maybestd::io::Result<Self> {
				if buf.len() < $len {
					return Err($crate::borsh::maybestd::io::Error::new(
						$crate::borsh::maybestd::io::ErrorKind::InvalidInput,
						$crate::ERROR_UNEXPECTED_LENGTH_OF_INPUT,
					))
				}
				let res = Self::from_slice(&buf[..$len]);
				*buf = &buf[$len..];
				Ok(res)
			}
		}

		impl $crate::borsh::BorshSchema for $name {
			fn add_definitions_recursively(
				definitions: &mut $crate::borsh::maybestd::collections::HashMap<
					$crate::borsh::schema::Declaration,
					$crate::borsh::schema::Definition,
				>,
			) {
				let definition = $crate::borsh::schema::Definition::Array { length: $len, elements: u8::declaration() };
				Self::add_definition(Self::declaration(), definition, definitions);
			}
			fn declaration() -> $crate::borsh::schema::Declaration {
				stringify!($name).to_string()
			}
		}
	};
}
