//! Tests for [`Error::FromRepr`] cases.

#![cfg(test)]
#![expect(
	clippy::cargo_common_metadata,
	clippy::indexing_slicing,
	reason = "tests"
)]

mod util;

use hybrid_array::Array;
use oprf::Error;
use oprf::ciphersuite::CipherSuite;
use oprf::common::{BlindedElement, EvaluationElement, Proof};
use oprf::group::Group;
use oprf::key::PublicKey;

test_ciphersuites!(blinded_element);

fn blinded_element<CS: CipherSuite>() {
	let mut bytes = Array::<u8, <CS::Group as Group>::ElementLength>::default();
	bytes[0] = 1;

	// Failure on identity element.
	let result = BlindedElement::<CS>::from_repr(&bytes);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = BlindedElement::<CS>::from_repr(&[]);
	assert_eq!(result.unwrap_err(), Error::FromRepr);
}

test_ciphersuites!(evaluation_element);

fn evaluation_element<CS: CipherSuite>() {
	let mut bytes = Array::<u8, <CS::Group as Group>::ElementLength>::default();
	bytes[0] = 1;

	// Failure on identity element.
	let result = EvaluationElement::<CS>::from_repr(&bytes);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = EvaluationElement::<CS>::from_repr(&[]);
	assert_eq!(result.unwrap_err(), Error::FromRepr);
}

test_ciphersuites!(proof);

fn proof<CS: CipherSuite>() {
	let right = Array::<u8, <CS::Group as Group>::ScalarLength>::from_fn(|_| 0xFF);
	let wrong = Array::<u8, <CS::Group as Group>::ScalarLength>::default();

	// Failure on non-reduced scalar `c`.
	let result = Proof::<CS>::from_repr(&right.clone().concat(wrong.clone()));
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on non-reduced scalar `s`.
	let result = Proof::<CS>::from_repr(&wrong.concat(right));
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = Proof::<CS>::from_repr(&[]);
	assert_eq!(result.unwrap_err(), Error::FromRepr);
}

test_ciphersuites!(public_key);

fn public_key<CS: CipherSuite>() {
	let mut bytes = Array::<u8, <CS::Group as Group>::ElementLength>::default();
	bytes[0] = 1;

	// Failure on identity element.
	let result = PublicKey::<CS::Group>::from_repr(&bytes);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = PublicKey::<CS::Group>::from_repr(&[]);
	assert_eq!(result.unwrap_err(), Error::FromRepr);
}
