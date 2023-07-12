use {
    crate::{bucket_api::BucketApi, bucket_stats::BucketMapStats, MaxSearch, /*RefCount*/},
    /*sdk::pubkey::Pubkey,*/
    std::{/*convert::TryInto,*/ fmt::Debug, fs, path::PathBuf, sync::Arc},
    tempfile::TempDir,
};


#[derive(Debug)]
pub enum BucketMapError {
    /// (bucket_index, current_capacity_pow2)
    DataNoSpace((u64, u8)),
    /// current_capacity_pow2
    IndexNoSpace(u8),
}

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

    pub fn new(config: BucketMapConfig) -> Self {
        assert_ne!(
            config.max_buckets, 0,
            "Max number of buckets must be non-zero"
        );
        assert!(
            config.max_buckets.is_power_of_two(),
            "Max number of buckets must be a power of two"
        );
        // this should be <= 1 << DEFAULT_CAPACITY or we end up searching the same items over and over - probably not a big deal since it is so small anyway
        const MAX_SEARCH: MaxSearch = 32;
        let max_search = config.max_search.unwrap_or(MAX_SEARCH);

        if let Some(drives) = config.drives.as_ref() {
            Self::erase_previous_drives(drives);
        }
        let mut temp_dir = None;
        let drives = config.drives.unwrap_or_else(|| {
            temp_dir = Some(TempDir::new().unwrap());
            vec![temp_dir.as_ref().unwrap().path().to_path_buf()]
        });
        let drives = Arc::new(drives);

        let mut per_bucket_count = Vec::with_capacity(config.max_buckets);
        per_bucket_count.resize_with(config.max_buckets, Arc::default);
        let stats = Arc::new(BucketMapStats {
            per_bucket_count,
            ..BucketMapStats::default()
        });
        let buckets = stats
            .per_bucket_count
            .iter()
            .map(|per_bucket_count| {
                Arc::new(BucketApi::new(
                    Arc::clone(&drives),
                    max_search,
                    Arc::clone(&stats),
                    Arc::clone(per_bucket_count),
                ))
            })
            .collect();

        // A simple log2 function that is correct if x is a power of two
        let log2 = |x: usize| usize::BITS - x.leading_zeros() - 1;

        Self {
            buckets,
            drives,
            max_buckets_pow2: log2(config.max_buckets) as u8,
            stats,
            temp_dir,
        }
    }

    fn erase_previous_drives(drives: &[PathBuf]) {
        drives.iter().for_each(|folder| {
            let _ = fs::remove_dir_all(folder);
            let _ = fs::create_dir_all(folder);
        })
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