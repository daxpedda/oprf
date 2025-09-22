//! TODO
//!
//! # Features

#![no_std]
#![expect(clippy::cargo_common_metadata, reason = "todo")]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod cipher_suite;
pub mod common;
pub mod error;
pub mod group;
mod internal;
pub mod key;
pub mod oprf;
pub mod poprf;
#[cfg(feature = "serde")]
mod serde;
mod util;
pub mod voprf;

pub use common::{BlindedElement, EvaluationElement, Proof};
#[cfg(feature = "decaf448")]
pub use ed448_goldilocks::Decaf448;
pub use error::{Error, Result};
pub use oprf::{OprfClient, OprfServer};
#[cfg(feature = "p256-ciphersuite")]
pub use p256::NistP256;
#[cfg(feature = "p384-ciphersuite")]
pub use p384::NistP384;
#[cfg(feature = "p521-ciphersuite")]
pub use p521::NistP521;
pub use poprf::{PoprfClient, PoprfServer};
pub use voprf::{VoprfClient, VoprfServer};

#[cfg(feature = "ristretto255-ciphersuite")]
pub use self::group::ristretto255::Ristretto255;
