//! Functions to generate various forms of scalars and points.

#![expect(clippy::missing_panics_doc, reason = "tests")]

use hybrid_array::Array;
use oprf::cipher_suite::CipherSuite;
use oprf::group::Group;

/// Generates a valid non-zero scalar.
#[must_use]
pub fn scalar<Cs: CipherSuite>() -> Array<u8, <Cs::Group as Group>::ScalarLength> {
	let scalar = Cs::Group::scalar_random(&mut rand::rng()).unwrap();
	Cs::Group::scalar_to_repr(&scalar)
}

/// Returns a non-reduced scalar.
#[must_use]
pub fn invalid_scalar<Cs: CipherSuite>() -> Array<u8, <Cs::Group as Group>::ScalarLength> {
	Array::from_fn(|_| u8::MAX)
}

/// Returns a zero-scalar.
#[must_use]
pub fn zero_scalar<Cs: CipherSuite>() -> Array<u8, <Cs::Group as Group>::ScalarLength> {
	Array::default()
}

/// Generates a valid non-identity element.
#[must_use]
pub fn element<Cs: CipherSuite>() -> Array<u8, <Cs::Group as Group>::ElementLength> {
	let scalar = Cs::Group::scalar_random(&mut rand::rng()).unwrap();
	let element = Cs::Group::scalar_mul_by_generator(&scalar);
	Cs::Group::element_to_repr(&element)
}

/// Returns a non-reduced element.
#[must_use]
pub fn invalid_element<Cs: CipherSuite>() -> Array<u8, <Cs::Group as Group>::ElementLength> {
	Array::from_fn(|_| u8::MAX)
}

/// Returns a non-identity element.
#[must_use]
pub fn identity_element<Cs: CipherSuite>() -> Array<u8, <Cs::Group as Group>::ElementLength> {
	let element = Cs::Group::element_identity();
	Cs::Group::element_to_repr(&element)
}
