use std::ops::DerefMut;
use std::{fmt, ops::Deref};
mod draw;

#[cfg(test)]
mod hex_input;

pub mod child_extractor;

pub use draw::{draw, Child, DebugPrintExt};

#[cfg(test)]
pub use hex_input::{EntriesHex, InnerEntriesHex};

use primitive_types::H256;

pub fn no_childs(_: &[u8]) -> Vec<H256> {
    vec![]
}

/// The type used to implement custom debug logic
/// Should be compatible with Vec<u8> impl.
#[derive(Clone, Eq, PartialEq, PartialOrd, Default)]
pub struct OwnedData(pub Vec<u8>);

impl fmt::Debug for OwnedData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("").field(&hexutil::to_hex(&self.0)).finish()
    }
}
impl AsRef<[u8]> for OwnedData {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Deref for OwnedData {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for OwnedData {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<&[u8]> for OwnedData {
    fn from(value: &[u8]) -> Self {
        OwnedData(value.to_vec())
    }
}

impl From<Vec<u8>> for OwnedData {
    fn from(value: Vec<u8>) -> Self {
        OwnedData(value)
    }
}
impl From<OwnedData> for Vec<u8> {
    fn from(value: OwnedData) -> Self {
        value.0
    }
}

#[cfg(test)]
pub mod tests {
    #[cfg(feature = "tracing-enable")]
    pub fn tracing_sub_init() {
        use tracing::metadata::LevelFilter;
        use tracing_subscriber::fmt::format::FmtSpan;
        let _ = tracing_subscriber::fmt()
            .with_span_events(FmtSpan::ENTER)
            .with_max_level(LevelFilter::TRACE)
            .compact()
            .try_init();
    }
    #[cfg(not(feature = "tracing-enable"))]
    pub fn tracing_sub_init() {
        let _ = env_logger::Builder::new().parse_filters("info").try_init();
    }
}
