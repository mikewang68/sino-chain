//! The `rpc` module implements the Sino RPC interface.
    

pub const MAX_REQUEST_PAYLOAD_SIZE: usize = 200 * (1 << 10); // 200kB perviously: 50 * (1 << 10); // 50kB
pub const PERFORMANCE_SAMPLES_LIMIT: usize = 720;

// Limit the length of the `epoch_credits` array for each validator in a `get_vote_accounts`
// response
const MAX_RPC_EPOCH_CREDITS_HISTORY: usize = 5;

pub type BatchId = u64;

#[derive(Clone, Debug, Default)]
pub struct BatchState {
    pub duration: Duration,
}

#[derive(Clone, Debug, Default)]
pub struct BatchStateMap(DashMap<BatchId, BatchState>);
