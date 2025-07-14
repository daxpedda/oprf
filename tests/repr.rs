//! Tests for [`Error::FromRepr`] cases.

#![cfg(test)]
#![expect(clippy::cargo_common_metadata, reason = "tests")]

use oprf::Error;
use oprf::cipher_suite::CipherSuite;
use oprf::common::{BlindedElement, EvaluationElement, Proof};
use oprf::key::{KeyPair, PublicKey, SecretKey};
use oprf_test::test_ciphersuites;

test_ciphersuites!(blinded_element);

fn blinded_element<CS: CipherSuite>() {
	// Failure on non-reduced element.
	let result = BlindedElement::<CS>::from_repr(&oprf_test::invalid_element::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on identity element.
	let result = BlindedElement::<CS>::from_repr(&oprf_test::identity_element::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = BlindedElement::<CS>::from_repr(&[]);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Success.
	BlindedElement::<CS>::from_repr(&oprf_test::element::<CS>()).unwrap();
}

test_ciphersuites!(evaluation_element);

fn evaluation_element<CS: CipherSuite>() {
	// Failure on non-reduced element.
	let result = EvaluationElement::<CS>::from_repr(&oprf_test::invalid_element::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on identity element.
	let result = EvaluationElement::<CS>::from_repr(&oprf_test::identity_element::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = EvaluationElement::<CS>::from_repr(&[]);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Success.
	EvaluationElement::<CS>::from_repr(&oprf_test::element::<CS>()).unwrap();
}

test_ciphersuites!(proof);

fn proof<CS: CipherSuite>() {
	// Failure on non-reduced scalar `c`.
	let result = Proof::<CS>::from_repr(
		&oprf_test::invalid_scalar::<CS>().concat(oprf_test::scalar::<CS>()),
	);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on non-reduced scalar `s`.
	let result = Proof::<CS>::from_repr(
		&oprf_test::scalar::<CS>().concat(oprf_test::invalid_scalar::<CS>()),
	);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = Proof::<CS>::from_repr(&oprf_test::scalar::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Success on non-zero scalars.
	Proof::<CS>::from_repr(&oprf_test::zero_scalar::<CS>().concat(oprf_test::zero_scalar::<CS>()))
		.unwrap();

	// Success.
	Proof::<CS>::from_repr(&oprf_test::scalar::<CS>().concat(oprf_test::scalar::<CS>())).unwrap();
}

test_ciphersuites!(key_pair);

fn key_pair<CS: CipherSuite>() {
	// Failure on non-reduced scalar.
	let result = KeyPair::<CS::Group>::from_repr(&oprf_test::invalid_scalar::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on zero-scalar.
	let result = KeyPair::<CS::Group>::from_repr(&oprf_test::zero_scalar::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = KeyPair::<CS::Group>::from_repr(&[]);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Success.
	KeyPair::<CS::Group>::from_repr(&oprf_test::scalar::<CS>()).unwrap();
}

test_ciphersuites!(secret_key);

fn secret_key<CS: CipherSuite>() {
	// Failure on non-reduced scalar.
	let result = SecretKey::<CS::Group>::from_repr(&oprf_test::invalid_scalar::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on zero-scalar.
	let result = SecretKey::<CS::Group>::from_repr(&oprf_test::zero_scalar::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = SecretKey::<CS::Group>::from_repr(&[]);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Success.
	SecretKey::<CS::Group>::from_repr(&oprf_test::scalar::<CS>()).unwrap();
}

test_ciphersuites!(public_key);

fn public_key<CS: CipherSuite>() {
	// Failure on non-reduced element.
	let result = PublicKey::<CS::Group>::from_repr(&oprf_test::invalid_element::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on identity element.
	let result = PublicKey::<CS::Group>::from_repr(&oprf_test::identity_element::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = PublicKey::<CS::Group>::from_repr(&[]);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Success.
	PublicKey::<CS::Group>::from_repr(&oprf_test::element::<CS>()).unwrap();
}
