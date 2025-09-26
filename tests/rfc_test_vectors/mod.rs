//! RFC test vector suite.

#![cfg(test)]
#![expect(clippy::cargo_common_metadata, unreachable_pub, reason = "tests")]

mod basic;
mod batch;
mod parse;

use hex_literal::hex;

/// Seed `info` used in every test vector.
const KEY_INFO: &[u8] = b"test key";
/// Seed used in every test vector.
const SEED: [u8; 32] = hex!("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");
