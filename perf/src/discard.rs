use {
    crate::packet::PacketBatch,
    rand::{thread_rng, Rng},
};

pub fn discard_batches_randomly(
    batches: &mut Vec<PacketBatch>,
    max_packets: usize,
    mut total_packets: usize,
) -> usize {
    while total_packets > max_packets {
        let index = thread_rng().gen_range(0, batches.len());
        let removed = batches.swap_remove(index);
        total_packets = total_packets.saturating_sub(removed.packets.len());
    }
    total_packets
}
