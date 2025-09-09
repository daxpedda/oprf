//! Tests for [`Error::FromRepr`] cases.

#![cfg(test)]
#![expect(clippy::cargo_common_metadata, reason = "tests")]

use oprf::Error;
use oprf::cipher_suite::CipherSuite;
use oprf::common::{BlindedElement, EvaluationElement, Proof};
use oprf::key::{KeyPair, PublicKey, SecretKey};
use oprf_test::test_ciphersuites;

test_ciphersuites!(blinded_element);

fn blinded_element<Cs: CipherSuite>() {
	// Failure on non-reduced element.
	let result = BlindedElement::<Cs>::from_repr(&oprf_test::invalid_element::<Cs>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on identity element.
	let result = BlindedElement::<Cs>::from_repr(&oprf_test::identity_element::<Cs>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = BlindedElement::<Cs>::from_repr(&[]);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Success.
	BlindedElement::<Cs>::from_repr(&oprf_test::element::<Cs>()).unwrap();
}

test_ciphersuites!(evaluation_element);

fn evaluation_element<Cs: CipherSuite>() {
	// Failure on non-reduced element.
	let result = EvaluationElement::<Cs>::from_repr(&oprf_test::invalid_element::<Cs>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on identity element.
	let result = EvaluationElement::<Cs>::from_repr(&oprf_test::identity_element::<Cs>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = EvaluationElement::<Cs>::from_repr(&[]);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Success.
	EvaluationElement::<Cs>::from_repr(&oprf_test::element::<Cs>()).unwrap();
}

test_ciphersuites!(proof);

fn proof<Cs: CipherSuite>() {
	// Failure on non-reduced scalar `c`.
	let result = Proof::<Cs>::from_repr(
		&oprf_test::invalid_scalar::<Cs>().concat(oprf_test::scalar::<Cs>()),
	);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on non-reduced scalar `s`.
	let result = Proof::<Cs>::from_repr(
		&oprf_test::scalar::<Cs>().concat(oprf_test::invalid_scalar::<Cs>()),
	);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = Proof::<Cs>::from_repr(&oprf_test::scalar::<Cs>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Success on non-zero scalars.
	Proof::<Cs>::from_repr(&oprf_test::zero_scalar::<Cs>().concat(oprf_test::zero_scalar::<Cs>()))
		.unwrap();

	// Success.
	Proof::<Cs>::from_repr(&oprf_test::scalar::<Cs>().concat(oprf_test::scalar::<Cs>())).unwrap();
}

test_ciphersuites!(key_pair);

fn key_pair<Cs: CipherSuite>() {
	// Failure on non-reduced scalar.
	let result = KeyPair::<Cs::Group>::from_repr(&oprf_test::invalid_scalar::<Cs>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on zero-scalar.
	let result = KeyPair::<Cs::Group>::from_repr(&oprf_test::zero_scalar::<Cs>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = KeyPair::<Cs::Group>::from_repr(&[]);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Success.
	KeyPair::<Cs::Group>::from_repr(&oprf_test::scalar::<Cs>()).unwrap();
}

test_ciphersuites!(secret_key);

fn secret_key<Cs: CipherSuite>() {
	// Failure on non-reduced scalar.
	let result = SecretKey::<Cs::Group>::from_repr(&oprf_test::invalid_scalar::<Cs>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on zero-scalar.
	let result = SecretKey::<Cs::Group>::from_repr(&oprf_test::zero_scalar::<Cs>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = SecretKey::<Cs::Group>::from_repr(&[]);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Success.
	SecretKey::<Cs::Group>::from_repr(&oprf_test::scalar::<Cs>()).unwrap();
}

test_ciphersuites!(public_key);

fn public_key<Cs: CipherSuite>() {
	// Failure on non-reduced element.
	let result = PublicKey::<Cs::Group>::from_repr(&oprf_test::invalid_element::<Cs>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on identity element.
	let result = PublicKey::<Cs::Group>::from_repr(&oprf_test::identity_element::<Cs>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = PublicKey::<Cs::Group>::from_repr(&[]);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Success.
	PublicKey::<Cs::Group>::from_repr(&oprf_test::element::<Cs>()).unwrap();
}
