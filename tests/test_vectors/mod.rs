//! Test vector suite.

#![cfg(test)]
#![expect(clippy::cargo_common_metadata, unreachable_pub, reason = "tests")]

mod basic;
mod batch;
#[cfg(feature = "serde")]
mod generate;
mod parse;
