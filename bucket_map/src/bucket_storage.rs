use {
    crate::{bucket_stats::BucketStats, MaxSearch},
    memmap2::MmapMut,
    rand::{thread_rng, Rng},
    measure::measure::Measure,
    std::{
        fs::{remove_file, OpenOptions},
        io::{Seek, SeekFrom, Write},
        path::PathBuf,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
    },
};

pub struct BucketStorage {
    path: PathBuf,
    mmap: MmapMut,
    pub cell_size: u64,
    pub capacity_pow2: u8,
    pub used: AtomicU64,
    pub stats: Arc<BucketStats>,
    pub max_search: MaxSearch,
}