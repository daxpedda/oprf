//! TODO

#![no_std]
#![expect(
	clippy::cargo_common_metadata,
	clippy::missing_errors_doc,
	missing_docs,
	reason = "todo"
)]
#![cfg_attr(
	not(test),
	expect(clippy::missing_docs_in_private_items, reason = "todo")
)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod ciphersuite;
pub mod common;
mod error;
pub mod group;
mod internal;
pub mod key;
pub mod oprf;
pub mod poprf;
#[cfg(feature = "serde")]
mod serde;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod test_vectors;
mod util;
pub mod voprf;

pub use ciphersuite::CipherSuite;
pub use common::{BlindedElement, EvaluationElement, Proof};
pub use error::{Error, Result};
pub use oprf::{OprfClient, OprfServer};
pub use poprf::{PoprfClient, PoprfServer};
pub use voprf::{VoprfClient, VoprfServer};
