//! Helper types and functions for handling and dealing with snapshot hashes.
use sdk::{clock::Slot, hash::Hash};

/// At startup, when loading from snapshots, the starting snapshot hashes need to be passed to
/// SnapshotPackagerService, which is in charge of pushing the hashes to CRDS.  This struct wraps
/// up those values make it easier to pass from bank_forks_utils, through validator, to
/// SnapshotPackagerService.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StartingSnapshotHashes {
    pub full: FullSnapshotHash,
    pub incremental: Option<IncrementalSnapshotHash>,
}

/// Used by SnapshotPackagerService and SnapshotGossipManager, this struct adds type safety to
/// ensure a full snapshot hash is pushed to the right CRDS.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FullSnapshotHash {
    pub hash: (Slot, Hash),
}

/// Used by SnapshotPackagerService and SnapshotGossipManager, this struct adds type safety to
/// ensure an incremental snapshot hash is pushed to the right CRDS.  `base` is the (full) snapshot
/// this incremental snapshot (`hash`) is based on.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalSnapshotHash {
    pub base: (Slot, Hash),
    pub hash: (Slot, Hash),
}

/// FullSnapshotHashes is used by SnapshotPackagerService to collect the snapshot hashes from full
/// snapshots and then push those hashes to CRDS.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FullSnapshotHashes {
    pub hashes: Vec<(Slot, Hash)>,
}

/// IncrementalSnapshotHashes is used by SnapshotPackagerService to collect the snapshot hashes
/// from incremental snapshots and then push those hashes to CRDS.  `base` is the (full) snapshot
/// all the incremental snapshots (`hashes`) are based on.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IncrementalSnapshotHashes {
    pub base: (Slot, Hash),
    pub hashes: Vec<(Slot, Hash)>,
}
