//! Tests for traits on exported types.

#![cfg(test)]
#![expect(
	clippy::arbitrary_source_item_ordering,
	clippy::cargo_common_metadata,
	reason = "tests"
)]

use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::{error, io};

use oprf::Error;
use oprf::cipher_suite::{CipherSuite, Id};
#[cfg(feature = "alloc")]
use oprf::common::BatchAllocBlindEvaluateResult;
use oprf::common::{
	BatchBlindEvaluateResult, BlindEvaluateResult, BlindedElement, EvaluationElement, Mode, Proof,
};
use oprf::group::decaf448::Decaf448;
use oprf::group::ristretto255::Ristretto255;
use oprf::key::{KeyPair, PublicKey, SecretKey};
#[cfg(feature = "alloc")]
use oprf::oprf::OprfBatchAllocBlindResult;
use oprf::oprf::{OprfBatchBlindResult, OprfBlindResult, OprfClient, OprfServer};
#[cfg(feature = "alloc")]
use oprf::poprf::PoprfBatchAllocBlindResult;
use oprf::poprf::{PoprfBatchBlindResult, PoprfBlindResult, PoprfClient, PoprfServer};
#[cfg(feature = "alloc")]
use oprf::voprf::VoprfBatchAllocBlindResult;
use oprf::voprf::{VoprfBatchBlindResult, VoprfBlindResult, VoprfClient, VoprfServer};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use paste::paste;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use static_assertions::assert_impl_all;
use zeroize::ZeroizeOnDrop;

/// Asserts that public types implement expected traits with different
/// [`CipherSuite`]s.
#[macro_export]
macro_rules! test_ciphersuite {
	($cs:ident, $prefix:ident) => {
		paste! {
			#[test]
			fn [<test $prefix>]() {
				api!(BlindedElement<$cs>);
				api!(EvaluationElement<$cs>);
				api!(Proof<$cs>);
				result!(BlindEvaluateResult<$cs>);
				result!(BatchBlindEvaluateResult<$cs, 1>);
				#[cfg(feature = "alloc")]
				result!(BatchAllocBlindEvaluateResult<$cs>);

				api!(KeyPair<<$cs as CipherSuite>::Group>);
				api!(SecretKey<<$cs as CipherSuite>::Group>);
				api!(PublicKey<<$cs as CipherSuite>::Group>);

				api!(OprfClient<$cs>);
				api!(OprfServer<$cs>);
				result!(OprfBlindResult<$cs>);
				result!(OprfBatchBlindResult<$cs, 1>);
				#[cfg(feature = "alloc")]
				result!(OprfBatchAllocBlindResult<$cs>);

				api!(VoprfClient<$cs>);
				api!(VoprfServer<$cs>);
				result!(VoprfBlindResult<$cs>);
				result!(VoprfBatchBlindResult<$cs, 1>);
				#[cfg(feature = "alloc")]
				result!(VoprfBatchAllocBlindResult<$cs>);

				api!(PoprfClient<$cs>);
				api!(PoprfServer<$cs>);
				result!(PoprfBlindResult<$cs>);
				result!(PoprfBatchBlindResult<$cs, 1>);
				#[cfg(feature = "alloc")]
				result!(PoprfBatchAllocBlindResult<$cs>);
			}
		}
	};
}

test_ciphersuite!(NistP256, p256);
test_ciphersuite!(NistP384, p384);
test_ciphersuite!(NistP521, p521);
test_ciphersuite!(Ristretto255, ristretto255);
test_ciphersuite!(Decaf448, decaf448);

common!(Mode);
assert_impl_all!(Mode: Copy, Hash);

common!(Error);
assert_impl_all!(Error: Copy, Display, error::Error, Hash);

common!(Error<()>);
assert_impl_all!(Error<()>: Copy, Hash);

assert_impl_all!(Error<io::Error>: Display, error::Error);

common!(Id);
assert_impl_all!(Mode: Copy, Hash);

/// Check for all common traits.
#[macro_export]
macro_rules! common {
	($type:ty) => {
		assert_impl_all!($type: Clone, Debug, Eq, PartialEq, Send, Sync, Unpin, RefUnwindSafe, UnwindSafe);
	};
}

/// Check for all basic API types.
#[macro_export]
macro_rules! api {
	($type:ty) => {
		common!($type);
		assert_impl_all!($type: ZeroizeOnDrop);
		#[cfg(feature = "serde")]
		assert_impl_all!($type: Deserialize<'static>, Serialize);
	};
}

/// Check for all result types.
#[macro_export]
macro_rules! result {
	($type:ty) => {
		assert_impl_all!($type: Debug, ZeroizeOnDrop);
	};
}
