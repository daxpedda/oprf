//! Tests for [`Error::FromRepr`] cases.

#![cfg(test)]
#![expect(clippy::cargo_common_metadata, reason = "tests")]

use hybrid_array::Array;
use oprf::Error;
use oprf::cipher_suite::CipherSuite;
use oprf::common::{BlindedElement, EvaluationElement, Proof};
use oprf::group::Group;
use oprf::key::{KeyPair, PublicKey, SecretKey};
use oprf_test::test_ciphersuites;
use rand_core::OsRng;

test_ciphersuites!(blinded_element);

fn blinded_element<CS: CipherSuite>() {
	// Failure on non-reduced element.
	let result = BlindedElement::<CS>::from_repr(&invalid_element::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on identity element.
	let result = BlindedElement::<CS>::from_repr(&identity_element::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = BlindedElement::<CS>::from_repr(&[]);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Success.
	BlindedElement::<CS>::from_repr(&element::<CS>()).unwrap();
}

test_ciphersuites!(evaluation_element);

fn evaluation_element<CS: CipherSuite>() {
	// Failure on non-reduced element.
	let result = EvaluationElement::<CS>::from_repr(&invalid_element::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on identity element.
	let result = EvaluationElement::<CS>::from_repr(&identity_element::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = EvaluationElement::<CS>::from_repr(&[]);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Success.
	EvaluationElement::<CS>::from_repr(&element::<CS>()).unwrap();
}

test_ciphersuites!(proof);

fn proof<CS: CipherSuite>() {
	// Failure on non-reduced scalar `c`.
	let result = Proof::<CS>::from_repr(&invalid_scalar::<CS>().concat(scalar::<CS>()));
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on non-reduced scalar `s`.
	let result = Proof::<CS>::from_repr(&scalar::<CS>().concat(invalid_scalar::<CS>()));
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = Proof::<CS>::from_repr(&scalar::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Success on non-zero scalars.
	Proof::<CS>::from_repr(&zero_scalar::<CS>().concat(zero_scalar::<CS>())).unwrap();

	// Success.
	Proof::<CS>::from_repr(&scalar::<CS>().concat(scalar::<CS>())).unwrap();
}

test_ciphersuites!(key_pair);

fn key_pair<CS: CipherSuite>() {
	// Failure on non-reduced scalar.
	let result = KeyPair::<CS::Group>::from_repr(&invalid_scalar::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on zero-scalar.
	let result = KeyPair::<CS::Group>::from_repr(&zero_scalar::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = KeyPair::<CS::Group>::from_repr(&[]);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Success.
	KeyPair::<CS::Group>::from_repr(&scalar::<CS>()).unwrap();
}

test_ciphersuites!(secret_key);

fn secret_key<CS: CipherSuite>() {
	// Failure on non-reduced scalar.
	let result = SecretKey::<CS::Group>::from_repr(&invalid_scalar::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on zero-scalar.
	let result = SecretKey::<CS::Group>::from_repr(&zero_scalar::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = SecretKey::<CS::Group>::from_repr(&[]);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Success.
	SecretKey::<CS::Group>::from_repr(&scalar::<CS>()).unwrap();
}

test_ciphersuites!(public_key);

fn public_key<CS: CipherSuite>() {
	// Failure on non-reduced element.
	let result = PublicKey::<CS::Group>::from_repr(&invalid_element::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on identity element.
	let result = PublicKey::<CS::Group>::from_repr(&identity_element::<CS>());
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Failure on not enough bytes.
	let result = PublicKey::<CS::Group>::from_repr(&[]);
	assert_eq!(result.unwrap_err(), Error::FromRepr);

	// Success.
	PublicKey::<CS::Group>::from_repr(&element::<CS>()).unwrap();
}

fn scalar<CS: CipherSuite>() -> Array<u8, <CS::Group as Group>::ScalarLength> {
	let scalar = CS::Group::scalar_random(&mut OsRng).unwrap();
	CS::Group::scalar_to_repr(&scalar)
}

fn invalid_scalar<CS: CipherSuite>() -> Array<u8, <CS::Group as Group>::ScalarLength> {
	Array::from_fn(|_| u8::MAX)
}

fn zero_scalar<CS: CipherSuite>() -> Array<u8, <CS::Group as Group>::ScalarLength> {
	Array::default()
}

fn element<CS: CipherSuite>() -> Array<u8, <CS::Group as Group>::ElementLength> {
	let scalar = CS::Group::scalar_random(&mut OsRng).unwrap();
	let element = CS::Group::scalar_mul_by_generator(&scalar);
	let [bytes] = CS::Group::element_batch_to_repr(&[element]);
	bytes
}

fn invalid_element<CS: CipherSuite>() -> Array<u8, <CS::Group as Group>::ElementLength> {
	Array::from_fn(|_| u8::MAX)
}

fn identity_element<CS: CipherSuite>() -> Array<u8, <CS::Group as Group>::ElementLength> {
	let element = CS::Group::element_identity();
	let [bytes] = CS::Group::element_batch_to_repr(&[element]);
	bytes
}
