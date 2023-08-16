#![cfg_attr(RUSTC_WITH_SPECIALIZATION, feature(min_specialization))]
#![allow(clippy::integer_arithmetic)]

pub mod authorized_voters;
pub mod vote_instruction;
pub mod vote_state;
pub mod vote_transaction;

#[macro_use]
extern crate metrics;

#[macro_use]
extern crate frozen_abi_macro;

pub use sdk::vote::program::{check_id, id};


/// Amount of stake to be in majority = 1M
pub const MIN_STAKERS_TO_BE_MAJORITY: u64 = 1_000_000 * sdk::native_token::WENS_PER_SOR;

/// Number of stakers with wens more than 1M, to start filtering = 19
pub const NUM_MAJOR_STAKERS_FOR_FILTERING: usize = 19;