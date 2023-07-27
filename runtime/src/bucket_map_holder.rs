use {
    crate::{
        accounts_index::{AccountsIndexConfig, IndexValue},
        bucket_map_holder_stats::BucketMapHolderStats,
        in_mem_accounts_index::{InMemAccountsIndex, SlotT},
        waitable_condvar::WaitableCondvar,
    },
    bucket_map::bucket_map::{BucketMap, BucketMapConfig},
    measure::measure::Measure,
    sdk::{clock::SLOT_MS, timing::AtomicInterval},
    std::{
        fmt::Debug,
        sync::{
            atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
            Arc, Mutex,
        },
        time::Duration,
    },
};
pub type Age = u8;

const AGE_MS: u64 = SLOT_MS; // match one age per slot time

pub struct BucketMapHolder<T: IndexValue> {
    pub disk: Option<BucketMap<SlotT<T>>>,

    pub count_ages_flushed: AtomicUsize,
    pub age: AtomicU8,
    pub stats: BucketMapHolderStats,

    age_timer: AtomicInterval,

    // used by bg processing to know when any bucket has become dirty
    pub wait_dirty_or_aged: Arc<WaitableCondvar>,
    next_bucket_to_flush: Mutex<usize>,
    bins: usize,

    pub threads: usize,

    // how much mb are we allowed to keep in the in-mem index?
    // Rest goes to disk.
    pub mem_budget_mb: Option<usize>,
    ages_to_stay_in_cache: Age,

    /// startup is a special time for flush to focus on moving everything to disk as fast and efficiently as possible
    /// with less thread count limitations. LRU and access patterns are not important. Freeing memory
    /// and writing to disk in parallel are.
    /// Note startup is an optimization and is not required for correctness.
    startup: AtomicBool,
}

impl<T: IndexValue> Debug for BucketMapHolder<T> {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}

#[allow(clippy::mutex_atomic)]
impl<T: IndexValue> BucketMapHolder<T> {
    pub fn increment_age(&self) {
        // since we are about to change age, there are now 0 buckets that have been flushed at this age
        // this should happen before the age.fetch_add
        let previous = self.count_ages_flushed.swap(0, Ordering::Acquire);
        // fetch_add is defined to wrap.
        // That's what we want. 0..255, then back to 0.
        self.age.fetch_add(1, Ordering::Release);
        assert!(previous >= self.bins); // we should not have increased age before previous age was fully flushed
        self.wait_dirty_or_aged.notify_all(); // notify all because we can age scan in parallel
    }

    pub fn future_age_to_flush(&self) -> Age {
        self.current_age().wrapping_add(self.ages_to_stay_in_cache)
    }

    fn has_age_interval_elapsed(&self) -> bool {
        // note that when this returns true, state of age_timer is modified
        self.age_timer.should_update(self.age_interval_ms())
    }

    /// used by bg processes to determine # active threads and how aggressively to flush
    pub fn get_startup(&self) -> bool {
        self.startup.load(Ordering::Relaxed)
    }

    /// startup=true causes:
    ///      in mem to act in a way that flushes to disk asap
    /// startup=false is 'normal' operation
    pub fn set_startup(&self, value: bool) {
        if !value {
            self.wait_for_idle();
        }
        self.startup.store(value, Ordering::Relaxed)
    }

    /// return when the bg threads have reached an 'idle' state
    pub(crate) fn wait_for_idle(&self) {
        assert!(self.get_startup());
        if self.disk.is_none() {
            return;
        }

        // when age has incremented twice, we know that we have made it through scanning all bins since we started waiting,
        //  so we are then 'idle'
        let end_age = self.current_age().wrapping_add(2);
        loop {
            self.wait_dirty_or_aged
                .wait_timeout(Duration::from_millis(self.age_interval_ms()));
            if end_age == self.current_age() {
                break;
            }
        }
    }

    pub fn current_age(&self) -> Age {
        self.age.load(Ordering::Acquire)
    }

    pub fn bucket_flushed_at_current_age(&self) {
        self.count_ages_flushed.fetch_add(1, Ordering::Release);
        self.maybe_advance_age();
    }

    /// have all buckets been flushed at the current age?
    pub fn all_buckets_flushed_at_current_age(&self) -> bool {
        self.count_ages_flushed() >= self.bins
    }

    pub fn count_ages_flushed(&self) -> usize {
        self.count_ages_flushed.load(Ordering::Acquire)
    }

    pub fn maybe_advance_age(&self) -> bool {
        // check has_age_interval_elapsed last as calling it modifies state on success
        if self.all_buckets_flushed_at_current_age() && self.has_age_interval_elapsed() {
            self.increment_age();
            true
        } else {
            false
        }
    }

    pub fn new(bins: usize, config: &Option<AccountsIndexConfig>, threads: usize) -> Self {
        const DEFAULT_AGE_TO_STAY_IN_CACHE: Age = 5;
        let ages_to_stay_in_cache = config
            .as_ref()
            .and_then(|config| config.ages_to_stay_in_cache)
            .unwrap_or(DEFAULT_AGE_TO_STAY_IN_CACHE);

        let mut bucket_config = BucketMapConfig::new(bins);
        bucket_config.drives = config.as_ref().and_then(|config| config.drives.clone());
        let mem_budget_mb = config.as_ref().and_then(|config| config.index_limit_mb);
        // only allocate if mem_budget_mb is Some
        let disk = mem_budget_mb.map(|_| BucketMap::new(bucket_config));
        Self {
            disk,
            ages_to_stay_in_cache,
            count_ages_flushed: AtomicUsize::default(),
            age: AtomicU8::default(),
            stats: BucketMapHolderStats::new(bins),
            wait_dirty_or_aged: Arc::default(),
            next_bucket_to_flush: Mutex::new(0),
            age_timer: AtomicInterval::default(),
            bins,
            startup: AtomicBool::default(),
            mem_budget_mb,
            threads,
        }
    }

    // get the next bucket to flush, with the idea that the previous bucket
    // is perhaps being flushed by another thread already.
    pub fn next_bucket_to_flush(&self) -> usize {
        // could be lock-free as an optimization
        // wrapping is tricky
        let mut lock = self.next_bucket_to_flush.lock().unwrap();
        let result = *lock;
        *lock = (result + 1) % self.bins;
        result
    }

    /// prepare for this to be dynamic if necessary
    /// For example, maybe startup has a shorter age interval.
    fn age_interval_ms(&self) -> u64 {
        AGE_MS
    }

    /// return an amount of ms to sleep
    fn throttling_wait_ms_internal(
        &self,
        interval_ms: u64,
        elapsed_ms: u64,
        bins_flushed: u64,
    ) -> Option<u64> {
        let target_percent = 90; // aim to finish in 90% of the allocated time
        let remaining_ms = (interval_ms * target_percent / 100).saturating_sub(elapsed_ms);
        let remaining_bins = (self.bins as u64).saturating_sub(bins_flushed);
        if remaining_bins == 0 || remaining_ms == 0 || elapsed_ms == 0 || bins_flushed == 0 {
            // any of these conditions result in 'do not wait due to progress'
            return None;
        }
        let ms_per_s = 1_000;
        let rate_bins_per_s = bins_flushed * ms_per_s / elapsed_ms;
        let expected_bins_processed_in_remaining_time = rate_bins_per_s * remaining_ms / ms_per_s;
        if expected_bins_processed_in_remaining_time > remaining_bins {
            // wait because we predict will finish prior to target
            Some(1)
        } else {
            // do not wait because we predict will finish after target
            None
        }
    }

    /// Check progress this age.
    /// Return ms to wait to get closer to the wait target and spread out work over the entire age interval.
    /// Goal is to avoid cpu spikes at beginning of age interval.
    fn throttling_wait_ms(&self) -> Option<u64> {
        let interval_ms = self.age_interval_ms();
        let elapsed_ms = self.age_timer.elapsed_ms();
        let bins_flushed = self.count_ages_flushed() as u64;
        self.throttling_wait_ms_internal(interval_ms, elapsed_ms, bins_flushed)
    }

    /// true if this thread can sleep
    fn should_thread_sleep(&self) -> bool {
        let bins_flushed = self.count_ages_flushed();
        if bins_flushed >= self.bins {
            // all bins flushed, so this thread can sleep
            true
        } else {
            // at least 1 thread running for each bin that still needs to be flushed, so this thread can sleep
            let active = self.stats.active_threads.load(Ordering::Relaxed);
            bins_flushed.saturating_add(active as usize) >= self.bins
        }
    }

    // intended to execute in a bg thread
    pub fn background(&self, exit: Arc<AtomicBool>, in_mem: Vec<Arc<InMemAccountsIndex<T>>>) {
        let bins = in_mem.len();
        let flush = self.disk.is_some();
        let mut throttling_wait_ms = None;
        loop {
            if !flush {
                self.wait_dirty_or_aged.wait_timeout(Duration::from_millis(
                    self.stats.remaining_until_next_interval(),
                ));
            } else if self.should_thread_sleep() || throttling_wait_ms.is_some() {
                let mut wait = std::cmp::min(
                    self.age_timer
                        .remaining_until_next_interval(self.age_interval_ms()),
                    self.stats.remaining_until_next_interval(),
                );
                if let Some(throttling_wait_ms) = throttling_wait_ms {
                    self.stats
                        .bg_throttling_wait_us
                        .fetch_add(throttling_wait_ms * 1000, Ordering::Relaxed);
                    wait = std::cmp::min(throttling_wait_ms, wait);
                }

                let mut m = Measure::start("wait");
                self.wait_dirty_or_aged
                    .wait_timeout(Duration::from_millis(wait));
                m.stop();
                self.stats
                    .bg_waiting_us
                    .fetch_add(m.as_us(), Ordering::Relaxed);
                // likely some time has elapsed. May have been waiting for age time interval to elapse.
                self.maybe_advance_age();
            }
            throttling_wait_ms = None;

            if exit.load(Ordering::Relaxed) {
                break;
            }

            self.stats.active_threads.fetch_add(1, Ordering::Relaxed);
            for _ in 0..bins {
                if flush {
                    let index = self.next_bucket_to_flush();
                    in_mem[index].flush();
                }
                self.stats.report_stats(self);
                if self.all_buckets_flushed_at_current_age() {
                    break;
                }
                throttling_wait_ms = self.throttling_wait_ms();
                if throttling_wait_ms.is_some() {
                    break;
                }
            }
            self.stats.active_threads.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
pub mod tests {
    use {
        super::*,
        rayon::prelude::*,
        std::{
            sync::atomic::{AtomicUsize, Ordering},
            time::Instant,
        },
    };

    #[test]
    fn test_next_bucket_to_flush() {
        sino_logger::setup();
        let bins = 4;
        let test = BucketMapHolder::<u64>::new(bins, &Some(AccountsIndexConfig::default()), 1);
        let visited = (0..bins)
            .into_iter()
            .map(|_| AtomicUsize::default())
            .collect::<Vec<_>>();
        let iterations = bins * 30;
        let threads = bins * 4;
        let expected = threads * iterations / bins;

        (0..threads).into_par_iter().for_each(|_| {
            (0..iterations).into_iter().for_each(|_| {
                let bin = test.next_bucket_to_flush();
                visited[bin].fetch_add(1, Ordering::Relaxed);
            });
        });
        visited.iter().enumerate().for_each(|(bin, visited)| {
            assert_eq!(visited.load(Ordering::Relaxed), expected, "bin: {}", bin)
        });
    }

    #[test]
    fn test_age_increment() {
        sino_logger::setup();
        let bins = 4;
        let test = BucketMapHolder::<u64>::new(bins, &Some(AccountsIndexConfig::default()), 1);
        for age in 0..513 {
            assert_eq!(test.current_age(), (age % 256) as Age);

            // inc all
            for _ in 0..bins {
                assert!(!test.all_buckets_flushed_at_current_age());
                // cannot call this because based on timing, it may fire: test.bucket_flushed_at_current_age();
            }

            // this would normally happen once time went off and all buckets had been flushed at the previous age
            test.count_ages_flushed.fetch_add(bins, Ordering::Release);
            test.increment_age();
        }
    }

    #[test]
    fn test_throttle() {
        sino_logger::setup();
        let bins = 100;
        let test = BucketMapHolder::<u64>::new(bins, &Some(AccountsIndexConfig::default()), 1);
        let bins = test.bins as u64;
        let interval_ms = test.age_interval_ms();
        // 90% of time elapsed, all but 1 bins flushed, should not wait since we'll end up right on time
        let elapsed_ms = interval_ms * 89 / 100;
        let bins_flushed = bins - 1;
        let result = test.throttling_wait_ms_internal(interval_ms, elapsed_ms, bins_flushed);
        assert_eq!(result, None);
        // 10% of time, all bins but 1, should wait
        let elapsed_ms = interval_ms / 10;
        let bins_flushed = bins - 1;
        let result = test.throttling_wait_ms_internal(interval_ms, elapsed_ms, bins_flushed);
        assert_eq!(result, Some(1));
        // 5% of time, 8% of bins, should wait. target is 90%. These #s roughly work
        let elapsed_ms = interval_ms * 5 / 100;
        let bins_flushed = bins * 8 / 100;
        let result = test.throttling_wait_ms_internal(interval_ms, elapsed_ms, bins_flushed);
        assert_eq!(result, Some(1));
        // 11% of time, 12% of bins, should NOT wait. target is 90%. These #s roughly work
        let elapsed_ms = interval_ms * 11 / 100;
        let bins_flushed = bins * 12 / 100;
        let result = test.throttling_wait_ms_internal(interval_ms, elapsed_ms, bins_flushed);
        assert_eq!(result, None);
    }

    #[test]
    fn test_age_time() {
        sino_logger::setup();
        let bins = 1;
        let test = BucketMapHolder::<u64>::new(bins, &Some(AccountsIndexConfig::default()), 1);
        let threads = 2;
        let time = AGE_MS * 5 / 2;
        let expected = (time / AGE_MS) as Age;
        let now = Instant::now();
        test.bucket_flushed_at_current_age(); // done with age 0
        (0..threads).into_par_iter().for_each(|_| {
            while now.elapsed().as_millis() < (time as u128) {
                if test.maybe_advance_age() {
                    test.bucket_flushed_at_current_age();
                }
            }
        });
        assert_eq!(test.current_age(), expected);
    }

    #[test]
    fn test_age_broad() {
        sino_logger::setup();
        let bins = 4;
        let test = BucketMapHolder::<u64>::new(bins, &Some(AccountsIndexConfig::default()), 1);
        assert_eq!(test.current_age(), 0);
        for _ in 0..bins {
            assert!(!test.all_buckets_flushed_at_current_age());
            test.bucket_flushed_at_current_age();
        }
        std::thread::sleep(std::time::Duration::from_millis(AGE_MS * 2));
        test.maybe_advance_age();
        assert_eq!(test.current_age(), 1);
        assert!(!test.all_buckets_flushed_at_current_age());
    }
}
