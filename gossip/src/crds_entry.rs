use {
    crate::{
        contact_info::ContactInfo,
        crds::VersionedCrdsValue,
        crds_value::{
            CrdsData, CrdsValue, CrdsValueLabel, IncrementalSnapshotHashes, LegacyVersion,
            LowestSlot, SnapshotHashes, Version,
        },
    },
    indexmap::IndexMap,
    sdk::pubkey::Pubkey,
};

type CrdsTable = IndexMap<CrdsValueLabel, VersionedCrdsValue>;

/// Represents types which can be looked up from crds table given a key. e.g.
///   CrdsValueLabel -> VersionedCrdsValue, CrdsValue, CrdsData
///   Pubkey -> ContactInfo, LowestSlot, SnapshotHashes, ...
pub trait CrdsEntry<'a, 'b>: Sized {
    type Key; // Lookup key.
    fn get_entry(table: &'a CrdsTable, key: Self::Key) -> Option<Self>;
}

macro_rules! impl_crds_entry (
    // Lookup by CrdsValueLabel.
    ($name:ident, |$entry:ident| $body:expr) => (
        impl<'a, 'b> CrdsEntry<'a, 'b> for &'a $name {
            type Key = &'b CrdsValueLabel;
            fn get_entry(table:&'a CrdsTable, key: Self::Key) -> Option<Self> {
                let $entry = table.get(key);
                $body
            }
        }
    );
    // Lookup by Pubkey.
    ($name:ident, $pat:pat, $expr:expr) => (
        impl<'a, 'b> CrdsEntry<'a, 'b> for &'a $name {
            type Key = Pubkey;
            fn get_entry(table:&'a CrdsTable, key: Self::Key) -> Option<Self> {
                let key = CrdsValueLabel::$name(key);
                match &table.get(&key)?.value.data {
                    $pat => Some($expr),
                    _ => None,
                }
            }
        }
    );
);

// Lookup by CrdsValueLabel.
impl_crds_entry!(CrdsData, |entry| Some(&entry?.value.data));
impl_crds_entry!(CrdsValue, |entry| Some(&entry?.value));
impl_crds_entry!(VersionedCrdsValue, |entry| entry);

// Lookup by Pubkey.
impl_crds_entry!(ContactInfo, CrdsData::ContactInfo(node), node);
impl_crds_entry!(LegacyVersion, CrdsData::LegacyVersion(version), version);
impl_crds_entry!(LowestSlot, CrdsData::LowestSlot(_, slot), slot);
impl_crds_entry!(Version, CrdsData::Version(version), version);
impl_crds_entry!(
    IncrementalSnapshotHashes,
    CrdsData::IncrementalSnapshotHashes(incremental_snapshot_hashes),
    incremental_snapshot_hashes
);

impl<'a, 'b> CrdsEntry<'a, 'b> for &'a SnapshotHashes {
    type Key = Pubkey;
    fn get_entry(table: &'a CrdsTable, key: Self::Key) -> Option<Self> {
        let key = CrdsValueLabel::SnapshotHashes(key);
        match &table.get(&key)?.value.data {
            CrdsData::SnapshotHashes(snapshot_hash) => Some(snapshot_hash),
            _ => None,
        }
    }
}