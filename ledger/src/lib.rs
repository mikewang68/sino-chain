#![cfg_attr(RUSTC_WITH_SPECIALIZATION, feature(min_specialization))]
#![allow(clippy::integer_arithmetic)]
// #[macro_use]
// extern crate solana_bpf_loader_program;

#[macro_use]
pub mod blockstore;
pub mod blockstore_db;
pub mod blockstore_meta;
pub mod shred;
pub mod ancestor_iterator;
pub mod erasure;
pub mod leader_schedule_cache;
pub mod leader_schedule;
pub mod leader_schedule_utils;
pub mod genesis_utils;
pub mod blockstore_processor;

#[macro_use]
extern crate metrics;

#[macro_use]
extern crate log;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate frozen_abi_macro;