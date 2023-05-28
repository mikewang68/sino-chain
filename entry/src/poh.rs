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