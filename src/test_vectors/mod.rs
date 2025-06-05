//! Test vector suite.

#![expect(clippy::indexing_slicing, reason = "tests should panic")]

mod cycle_rng;
mod oprf;
mod parse;
mod poprf;
mod voprf;

use hex_literal::hex;

/// Seed `info` used in every test vector.
const KEY_INFO: &[u8] = b"test key";
/// Seed used in every test vector.
const SEED: [u8; 32] = hex!("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");
/// `info` used in every test vector.
const INFO: &[u8] = b"test info";
