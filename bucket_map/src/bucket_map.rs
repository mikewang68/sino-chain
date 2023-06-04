use {
    crate::{bucket_api::BucketApi, bucket_stats::BucketMapStats, MaxSearch, RefCount},
    sdk::pubkey::Pubkey,
    std::{convert::TryInto, fmt::Debug, fs, path::PathBuf, sync::Arc},
    tempfile::TempDir,
};

pub struct BucketMap<T: Clone + Copy + Debug> {
    buckets: Vec<Arc<BucketApi<T>>>,
    drives: Arc<Vec<PathBuf>>,
    max_buckets_pow2: u8,
    pub stats: Arc<BucketMapStats>,
    pub temp_dir: Option<TempDir>,
}
impl<T: Clone + Copy + Debug> BucketMap<T> {
    pub fn get_bucket_from_index(&self, ix: usize) -> &Arc<BucketApi<T>> {
        &self.buckets[ix]
    }
}

#[derive(Debug, Default, Clone)]
pub struct BucketMapConfig {
    pub max_buckets: usize,
    pub drives: Option<Vec<PathBuf>>,
    pub max_search: Option<MaxSearch>,
}

impl BucketMapConfig {
    /// Create a new BucketMapConfig
    /// NOTE: BucketMap requires that max_buckets is a power of two
    pub fn new(max_buckets: usize) -> BucketMapConfig {
        BucketMapConfig {
            max_buckets,
            ..BucketMapConfig::default()
        }
    }
}