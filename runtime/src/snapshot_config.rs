use {
    crate::snapshot_utils::{self, ArchiveFormat, SnapshotVersion},
    sdk::clock::Slot,
    std::path::PathBuf,
};

/// Snapshot configuration and runtime information
#[derive(Clone, Debug)]
pub struct SnapshotConfig {
    /// Generate a new full snapshot archive every this many slots
    pub full_snapshot_archive_interval_slots: Slot,

    /// Generate a new incremental snapshot archive every this many slots
    pub incremental_snapshot_archive_interval_slots: Slot,

    /// Path to the directory where snapshot archives are stored
    pub snapshot_archives_dir: PathBuf,

    /// Path to the directory where bank snapshots are stored
    pub bank_snapshots_dir: PathBuf,

    /// The archive format to use for snapshots
    pub archive_format: ArchiveFormat,

    /// Snapshot version to generate
    pub snapshot_version: SnapshotVersion,

    /// Maximum number of full snapshot archives to retain
    pub maximum_full_snapshot_archives_to_retain: usize,

    /// Maximum number of incremental snapshot archives to retain
    /// NOTE: Incremental snapshots will only be kept for the latest full snapshot
    pub maximum_incremental_snapshot_archives_to_retain: usize,

    /// This is the `use_index` parameter to use when calling `update_accounts_hash()`
    pub accounts_hash_use_index: bool,

    /// This is the `debug_verify` parameter to use when calling `update_accounts_hash()`
    pub accounts_hash_debug_verify: bool,

    // Thread niceness adjustment for snapshot packager service
    pub packager_thread_niceness_adj: i8,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            full_snapshot_archive_interval_slots:
                snapshot_utils::DEFAULT_FULL_SNAPSHOT_ARCHIVE_INTERVAL_SLOTS,
            incremental_snapshot_archive_interval_slots:
                snapshot_utils::DEFAULT_INCREMENTAL_SNAPSHOT_ARCHIVE_INTERVAL_SLOTS,
            snapshot_archives_dir: PathBuf::default(),
            bank_snapshots_dir: PathBuf::default(),
            archive_format: ArchiveFormat::TarBzip2,
            snapshot_version: SnapshotVersion::default(),
            maximum_full_snapshot_archives_to_retain:
                snapshot_utils::DEFAULT_MAX_FULL_SNAPSHOT_ARCHIVES_TO_RETAIN,
            maximum_incremental_snapshot_archives_to_retain:
                snapshot_utils::DEFAULT_MAX_INCREMENTAL_SNAPSHOT_ARCHIVES_TO_RETAIN,
            accounts_hash_use_index: false,
            accounts_hash_debug_verify: false,
            packager_thread_niceness_adj: 0,
        }
    }
}
