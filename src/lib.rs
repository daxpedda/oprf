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

pub use cipher_suite::CipherSuite;
pub use common::{BlindedElement, EvaluationElement, Proof};
pub use error::{Error, Result};
pub use oprf::{OprfClient, OprfServer};
pub use poprf::{PoprfClient, PoprfServer};
pub use voprf::{VoprfClient, VoprfServer};
