//! Functions to generate various forms of scalars and points.

#![expect(clippy::missing_panics_doc, reason = "tests")]

use hybrid_array::Array;
use oprf::CipherSuite;
use oprf::group::Group;
use rand_core::OsRng;

/// Generates a valid non-zero scalar.
#[must_use]
pub fn scalar<CS: CipherSuite>() -> Array<u8, <CS::Group as Group>::ScalarLength> {
	let scalar = CS::Group::scalar_random(&mut OsRng).unwrap();
	CS::Group::scalar_to_repr(&scalar)
}

/// Returns a non-reduced scalar.
#[must_use]
pub fn invalid_scalar<CS: CipherSuite>() -> Array<u8, <CS::Group as Group>::ScalarLength> {
	Array::from_fn(|_| u8::MAX)
}

/// Returns a zero-scalar.
#[must_use]
pub fn zero_scalar<CS: CipherSuite>() -> Array<u8, <CS::Group as Group>::ScalarLength> {
	Array::default()
}

/// Generates a valid non-identity element.
#[must_use]
pub fn element<CS: CipherSuite>() -> Array<u8, <CS::Group as Group>::ElementLength> {
	let scalar = CS::Group::scalar_random(&mut OsRng).unwrap();
	let element = CS::Group::scalar_mul_by_generator(&scalar);
	CS::Group::element_to_repr(&element)
}

/// Returns a non-reduced element.
#[must_use]
pub fn invalid_element<CS: CipherSuite>() -> Array<u8, <CS::Group as Group>::ElementLength> {
	Array::from_fn(|_| u8::MAX)
}

/// Returns a non-identity element.
#[must_use]
pub fn identity_element<CS: CipherSuite>() -> Array<u8, <CS::Group as Group>::ElementLength> {
	let element = CS::Group::element_identity();
	CS::Group::element_to_repr(&element)
}
