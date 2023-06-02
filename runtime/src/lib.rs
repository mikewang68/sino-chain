#![cfg_attr(RUSTC_WITH_SPECIALIZATION, feature(min_specialization))]
#![allow(clippy::integer_arithmetic)]

pub mod hardened_unpack;
pub mod genesis_utils;
pub mod bank;
pub mod accounts;
pub mod accounts_db;
pub mod ancestors;
pub mod accounts_index;
pub mod blockhash_queue;
pub mod status_cache;
pub mod rent_collector;
pub mod epoch_stakes;
pub mod stakes;
pub mod stake_delegations;
pub mod stake_history;
pub mod vote_account;
pub mod builtins;
pub mod cost_tracker;

#[macro_use]
extern crate metrics;
#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate frozen_abi_macro;