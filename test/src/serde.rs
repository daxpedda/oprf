//! Serde testing utilities.

use std::iter;

use ed448_goldilocks::Decaf448;
use oprf::cipher_suite::CipherSuite;
use oprf::common::{BlindedElement, EvaluationElement, Proof};
use oprf::group::Group;
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
	/// The [`Token`] expected for the provided field index of this type.
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
	/// The [`Token`] expected for the provided field index of this type.
	#[must_use]
	fn repr(_index: usize, bytes: &'static [u8]) -> impl Iterator<Item = Token> {
		iter::once(Token::Bytes(bytes))
	}
}

impl<Cs: CipherSuite> TypeRepr for BlindedElement<Cs> {}

impl<Cs: CipherSuite> TypeRepr for EvaluationElement<Cs> {}

impl<Cs: CipherSuite + ScalarRepr> TypeRepr for Proof<Cs> {
	fn repr(_: usize, bytes: &'static [u8]) -> impl Iterator<Item = Token> {
		Cs::scalar_repr(bytes)
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

impl<Cs: CipherSuite + ScalarRepr> TypeRepr for OprfClient<Cs> {
	fn repr(_: usize, bytes: &'static [u8]) -> impl Iterator<Item = Token> {
		Cs::scalar_repr(bytes)
	}
}

impl<Cs: CipherSuite + ScalarRepr> TypeRepr for OprfServer<Cs> {
	fn repr(_: usize, bytes: &'static [u8]) -> impl Iterator<Item = Token> {
		Cs::scalar_repr(bytes)
	}
}

impl<Cs: CipherSuite + ScalarRepr> TypeRepr for VoprfClient<Cs> {
	fn repr(index: usize, bytes: &'static [u8]) -> impl Iterator<Item = Token> {
		#[expect(
			clippy::iter_on_empty_collections,
			clippy::iter_on_single_items,
			reason = "required to produce type compatible output"
		)]
		match index {
			0 => Some(Cs::scalar_repr(bytes))
				.into_iter()
				.flatten()
				.chain(None),
			1 => None.into_iter().flatten().chain(Some(Token::Bytes(bytes))),
			_ => unreachable!(),
		}
	}
}

impl<Cs: CipherSuite + ScalarRepr> TypeRepr for VoprfServer<Cs> {
	fn repr(_: usize, bytes: &'static [u8]) -> impl Iterator<Item = Token> {
		Cs::scalar_repr(bytes)
	}
}

impl<Cs: CipherSuite + ScalarRepr> TypeRepr for PoprfClient<Cs> {
	fn repr(index: usize, bytes: &'static [u8]) -> impl Iterator<Item = Token> {
		VoprfClient::<Cs>::repr(index, bytes)
	}
}

impl<Cs: CipherSuite + ScalarRepr> TypeRepr for PoprfServer<Cs> {
	fn repr(_: usize, bytes: &'static [u8]) -> impl Iterator<Item = Token> {
		Cs::scalar_repr(bytes)
	}
}
