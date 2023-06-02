use {
    log::*,
    sdk::hash::{hash, hashv, Hash},
    std::time::{Duration, Instant},
};

pub struct Poh {
    pub hash: Hash,
    num_hashes: u64,
    hashes_per_tick: u64,
    remaining_hashes: u64,
    ticks_per_slot: u64,
    tick_number: u64,
    slot_start_time: Instant,
}

#[derive(Debug)]
pub struct PohEntry {
    pub num_hashes: u64,
    pub hash: Hash,
}

impl Poh {
    pub fn new(hash: Hash, hashes_per_tick: Option<u64>) -> Self {
        Self::new_with_slot_info(hash, hashes_per_tick, 0, 0)
    }

    pub fn new_with_slot_info(
        hash: Hash,
        hashes_per_tick: Option<u64>,
        ticks_per_slot: u64,
        tick_number: u64,
    ) -> Self {
        let hashes_per_tick = hashes_per_tick.unwrap_or(std::u64::MAX);
        assert!(hashes_per_tick > 1);
        let now = Instant::now();
        Poh {
            hash,
            num_hashes: 0,
            hashes_per_tick,
            remaining_hashes: hashes_per_tick,
            ticks_per_slot,
            tick_number,
            slot_start_time: now,
        }
    }

    pub fn hash(&mut self, max_num_hashes: u64) -> bool {
        let num_hashes = std::cmp::min(self.remaining_hashes - 1, max_num_hashes);

        for _ in 0..num_hashes {
            self.hash = hash(self.hash.as_ref());
        }
        self.num_hashes += num_hashes;
        self.remaining_hashes -= num_hashes;

        assert!(self.remaining_hashes > 0);
        self.remaining_hashes == 1 // Return `true` if caller needs to `tick()` next
    }

    pub fn record(&mut self, mixin: Hash) -> Option<PohEntry> {
        if self.remaining_hashes == 1 {
            return None; // Caller needs to `tick()` first
        }

        self.hash = hashv(&[self.hash.as_ref(), mixin.as_ref()]);
        let num_hashes = self.num_hashes + 1;
        self.num_hashes = 0;
        self.remaining_hashes -= 1;

        Some(PohEntry {
            num_hashes,
            hash: self.hash,
        })
    }

    pub fn tick(&mut self) -> Option<PohEntry> {
        self.hash = hash(self.hash.as_ref());
        self.num_hashes += 1;
        self.remaining_hashes -= 1;

        // If the hashes_per_tick is variable (std::u64::MAX) then always generate a tick.
        // Otherwise only tick if there are no remaining hashes
        if self.hashes_per_tick < std::u64::MAX && self.remaining_hashes != 0 {
            return None;
        }

        let num_hashes = self.num_hashes;
        self.remaining_hashes = self.hashes_per_tick;
        self.num_hashes = 0;
        self.tick_number += 1;
        Some(PohEntry {
            num_hashes,
            hash: self.hash,
        })
    }
}

//生产指定数量Hash所需要的秒数
pub fn compute_hash_time_ns(hashes_sample_size: u64) -> u64 {
    info!("Running {} hashes...", hashes_sample_size);
    let mut v = Hash::default();
    let start = Instant::now();
    for _ in 0..hashes_sample_size {
        v = hash(v.as_ref());
    }
    start.elapsed().as_nanos() as u64
}
//计算每个tick要生产的Hash数
pub fn compute_hashes_per_tick(duration: Duration, hashes_sample_size: u64) -> u64 {
    let elapsed = compute_hash_time_ns(hashes_sample_size) / (1000 * 1000);
    duration.as_millis() as u64 * hashes_sample_size / elapsed
}