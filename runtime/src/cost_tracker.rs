//! `cost_tracker` keeps tracking transaction cost per chained accounts as well as for entire block
//! The main functions are:
//! - would_fit(&tx_cost), immutable function to test if tx with tx_cost would fit into current block
//! - add_transaction_cost(&tx_cost), mutable function to accumulate tx_cost to tracker.
//!
use {
    crate::{block_cost_limits::*/* , cost_model::TransactionCost*/},
    sdk::{pubkey::Pubkey},
    std::{collections::HashMap},
};

const WRITABLE_ACCOUNTS_PER_BLOCK: usize = 512;

#[derive(AbiExample, Debug)]
pub struct CostTracker {
    account_cost_limit: u64,
    block_cost_limit: u64,
    vote_cost_limit: u64,
    cost_by_writable_accounts: HashMap<Pubkey, u64>,
    block_cost: u64,
    vote_cost: u64,
    transaction_count: u64,
}

impl Default for CostTracker {
    fn default() -> Self {
        // Clippy doesn't like asserts in const contexts, so need to explicitly allow them.  For
        // more info, see this issue: https://github.com/rust-lang/rust-clippy/issues/8159
        #![allow(clippy::assertions_on_constants)]
        const _: () = assert!(MAX_WRITABLE_ACCOUNT_UNITS <= MAX_BLOCK_UNITS);
        const _: () = assert!(MAX_VOTE_UNITS <= MAX_BLOCK_UNITS);

        Self {
            account_cost_limit: MAX_WRITABLE_ACCOUNT_UNITS,
            block_cost_limit: MAX_BLOCK_UNITS,
            vote_cost_limit: MAX_VOTE_UNITS,
            cost_by_writable_accounts: HashMap::with_capacity(WRITABLE_ACCOUNTS_PER_BLOCK),
            block_cost: 0,
            vote_cost: 0,
            transaction_count: 0,
        }
    }
}