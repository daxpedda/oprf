//! Serde testing utilities.

use std::iter;

use oprf::cipher_suite::CipherSuite;
use oprf::common::{BlindedElement, EvaluationElement, Proof};
use oprf::group::Group;
use oprf::group::decaf448::Decaf448;
use oprf::group::ristretto255::Ristretto255;
use oprf::key::{KeyPair, PublicKey, SecretKey};
use oprf::oprf::{OprfClient, OprfServer};
use oprf::poprf::{PoprfClient, PoprfServer};
use oprf::voprf::{VoprfClient, VoprfServer};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use serde_test::Token;

/// Defines how certain cipher suites differ in their serialization format of
/// scalars. By default this assumes [`Token::Bytes`] is used.
pub trait ScalarRepr {
	/// The [`Token`] expected for the given field index of this type.
	#[must_use]
	fn scalar_repr(bytes: &'static [u8]) -> impl Iterator<Item = Token> {
		iter::once(Token::Bytes(bytes))
	}
}

impl ScalarRepr for NistP256 {}

impl ScalarRepr for NistP384 {}

impl ScalarRepr for NistP521 {}

impl ScalarRepr for Ristretto255 {
	fn scalar_repr(bytes: &'static [u8]) -> impl Iterator<Item = Token> {
		iter::once(Token::Tuple { len: bytes.len() })
			.chain(bytes.iter().copied().map(Token::U8))
			.chain(iter::once(Token::TupleEnd))
	}
}

impl ScalarRepr for Decaf448 {}

/// Defines how types differ in their serialization format of
/// byte strings. By default this assumes [`Token::Bytes`] is used.
pub trait TypeRepr {
	/// The [`Token`] expected for the given field index of this type.
	#[must_use]
	fn repr(_index: usize, bytes: &'static [u8]) -> impl Iterator<Item = Token> {
		iter::once(Token::Bytes(bytes))
	}
}

impl<CS: CipherSuite> TypeRepr for BlindedElement<CS> {}

impl<CS: CipherSuite> TypeRepr for EvaluationElement<CS> {}

impl<CS: CipherSuite + ScalarRepr> TypeRepr for Proof<CS> {
	fn repr(_: usize, bytes: &'static [u8]) -> impl Iterator<Item = Token> {
		CS::scalar_repr(bytes)
	}
}

impl<G: Group + ScalarRepr> TypeRepr for KeyPair<G> {
	fn repr(_: usize, bytes: &'static [u8]) -> impl Iterator<Item = Token> {
		G::scalar_repr(bytes)
	}
}

impl<G: Group + ScalarRepr> TypeRepr for SecretKey<G> {
	fn repr(_: usize, bytes: &'static [u8]) -> impl Iterator<Item = Token> {
		G::scalar_repr(bytes)
	}
}

impl<G: Group + ScalarRepr> TypeRepr for PublicKey<G> {}

impl<CS: CipherSuite + ScalarRepr> TypeRepr for OprfClient<CS> {
	fn repr(_: usize, bytes: &'static [u8]) -> impl Iterator<Item = Token> {
		CS::scalar_repr(bytes)
	}
}

impl<CS: CipherSuite + ScalarRepr> TypeRepr for OprfServer<CS> {
	fn repr(_: usize, bytes: &'static [u8]) -> impl Iterator<Item = Token> {
		CS::scalar_repr(bytes)
	}
}

impl<CS: CipherSuite + ScalarRepr> TypeRepr for VoprfClient<CS> {
	fn repr(index: usize, bytes: &'static [u8]) -> impl Iterator<Item = Token> {
		#[expect(
			clippy::iter_on_empty_collections,
			clippy::iter_on_single_items,
			reason = "required to produce type compatible output"
		)]
		match index {
			0 => Some(CS::scalar_repr(bytes))
				.into_iter()
				.flatten()
				.chain(None),
			1 => None.into_iter().flatten().chain(Some(Token::Bytes(bytes))),
			_ => unreachable!(),
		}
	}
}

impl<CS: CipherSuite + ScalarRepr> TypeRepr for VoprfServer<CS> {
	fn repr(_: usize, bytes: &'static [u8]) -> impl Iterator<Item = Token> {
		CS::scalar_repr(bytes)
	}
}

impl<CS: CipherSuite + ScalarRepr> TypeRepr for PoprfClient<CS> {
	fn repr(index: usize, bytes: &'static [u8]) -> impl Iterator<Item = Token> {
		VoprfClient::<CS>::repr(index, bytes)
	}
}

impl<CS: CipherSuite + ScalarRepr> TypeRepr for PoprfServer<CS> {
	fn repr(_: usize, bytes: &'static [u8]) -> impl Iterator<Item = Token> {
		CS::scalar_repr(bytes)
	}
}
