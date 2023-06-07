//! The `faucet` module provides an object for launching a Solana Faucet,
//! which is the custodian of any remaining lamports in a mint.
//! The Solana Faucet builds and sends airdrop transactions,
//! checking requests against a single-request cap and a per-IP limit
//! for a given time time_slice.

use {
    log::*,
    thiserror::Error,
};

#[derive(Error, Debug)]
pub enum FaucetError {
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialize(#[from] bincode::Error),

    #[error("transaction_length from faucet exceeds limit: {0}")]
    TransactionDataTooLarge(usize),

    #[error("transaction_length from faucet: 0")]
    NoDataReceived,

    #[error("request too large; req: ◎{0}, cap: ◎{1}")]
    PerRequestCapExceeded(f64, f64),

    #[error("limit reached; req: ◎{0}, to: {1}, current: ◎{2}, cap: ◎{3}")]
    PerTimeCapExceeded(f64, String, f64, f64),
}