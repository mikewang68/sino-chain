#![allow(clippy::integer_arithmetic)]
// pub mod address_generator;
// pub mod solana_genesis_accounts;
// pub mod stakes;
// pub mod unlocks;

use serde::{Deserialize, Serialize};

/// An account where the data is encoded as a Base64 string.
#[derive(Serialize, Deserialize, Debug)]
pub struct Base64Account {
    pub balance: u64,
    pub owner: String,
    pub data: String,
    pub executable: bool,
}