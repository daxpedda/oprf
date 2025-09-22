//! [`Edwards448`] implementation.

use digest::XofFixedWrapper;
use ed448_goldilocks::elliptic_curve::group::GroupEncoding;
use ed448_goldilocks::elliptic_curve::ops::{BatchInvert, Invert, LinearCombination};
use ed448_goldilocks::elliptic_curve::point::NonIdentity;
use ed448_goldilocks::elliptic_curve::{Group as _, PrimeField};
use ed448_goldilocks::sha3::Shake256;
use ed448_goldilocks::{Ed448, Ed448NonZeroScalar, EdwardsPoint, EdwardsScalar};
use hash2curve::{ExpandMsg, GroupDigest, MapToCurve};
use hybrid_array::Array;
use hybrid_array::typenum::{U57, U64, U84};
use oprf::cipher_suite::{CipherSuite, Id};
use oprf::error::InternalError;
use oprf::group::Group;
use rand_core::TryCryptoRng;

/// OPRF implementation for Edwards25519.
#[derive(Clone, Copy, Debug)]
pub struct Edwards448;

impl CipherSuite for Edwards448 {
	const ID: Id = Id::new(b"edwards448-SHAKE256").unwrap();

	type Group = Self;
	type Hash = XofFixedWrapper<Shake256, U64>;
	type ExpandMsg = <Ed448 as GroupDigest>::ExpandMsg;
}

impl Group for Edwards448 {
	type SecurityLevel = <Ed448 as MapToCurve>::SecurityLevel;

	type NonZeroScalar = Ed448NonZeroScalar;
	type Scalar = EdwardsScalar;
	type ScalarLength = U57;

	type NonIdentityElement = NonIdentity<EdwardsPoint>;
	type Element = EdwardsPoint;
	type ElementLength = U57;

	fn scalar_random<R>(rng: &mut R) -> Result<Self::NonZeroScalar, R::Error>
	where
		R: ?Sized + TryCryptoRng,
	{
		let mut bytes = Array::default();

		loop {
			rng.try_fill_bytes(&mut bytes)?;

			if let Some(result) = Ed448NonZeroScalar::from_repr(bytes).into() {
				break Ok(result);
			}
		}
	}

	fn hash_to_scalar<E>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Scalar, InternalError>
	where
		E: ExpandMsg<Self::SecurityLevel>,
	{
		hash2curve::hash_to_scalar::<Ed448, E, U84>(input, dst).map_err(|_| InternalError)
	}

	fn non_zero_scalar_mul_by_generator(scalar: &Self::NonZeroScalar) -> Self::NonIdentityElement {
		NonIdentity::mul_by_generator(scalar)
	}

	fn scalar_mul_by_generator(scalar: &Self::Scalar) -> Self::Element {
		EdwardsPoint::mul_by_generator(scalar)
	}

	fn scalar_invert(scalar: &Self::NonZeroScalar) -> Self::NonZeroScalar {
		scalar.invert()
	}

	fn scalar_batch_invert<const N: usize>(
		scalars: [Self::NonZeroScalar; N],
	) -> [Self::NonZeroScalar; N] {
		Ed448NonZeroScalar::batch_invert(scalars)
	}

	#[cfg(feature = "alloc")]
	fn scalar_batch_alloc_invert(scalars: Vec<Self::NonZeroScalar>) -> Vec<Self::NonZeroScalar> {
		Ed448NonZeroScalar::batch_invert(scalars)
	}

	fn scalar_to_repr(scalar: &Self::Scalar) -> Array<u8, Self::ScalarLength> {
		scalar.to_repr()
	}

	fn non_zero_scalar_from_repr(
		repr: Array<u8, Self::ScalarLength>,
	) -> Result<Self::NonZeroScalar, InternalError> {
		Ed448NonZeroScalar::from_repr(repr)
			.into_option()
			.ok_or(InternalError)
	}

	fn scalar_from_repr(
		repr: &Array<u8, Self::ScalarLength>,
	) -> Result<Self::Scalar, InternalError> {
		EdwardsScalar::from_repr(*repr)
			.into_option()
			.ok_or(InternalError)
	}

	fn element_identity() -> Self::Element {
		EdwardsPoint::IDENTITY
	}

	fn element_generator() -> Self::Element {
		EdwardsPoint::GENERATOR
	}

	fn hash_to_curve<E>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Element, InternalError>
	where
		E: ExpandMsg<Self::SecurityLevel>,
	{
		hash2curve::hash_from_bytes::<Ed448, E>(input, dst).map_err(|_| InternalError)
	}

	fn element_to_repr(element: &Self::Element) -> Array<u8, Self::ElementLength> {
		element.to_bytes()
	}

	fn non_identity_element_from_repr(
		repr: &Array<u8, Self::ElementLength>,
	) -> Result<Self::NonIdentityElement, InternalError> {
		NonIdentity::from_repr(repr)
			.into_option()
			.ok_or(InternalError)
	}

	fn lincomb<const N: usize>(
		elements_and_scalars: &[(Self::Element, Self::Scalar); N],
	) -> Self::Element {
		EdwardsPoint::lincomb(elements_and_scalars)
	}

	#[cfg(feature = "alloc")]
	fn alloc_lincomb(elements_and_scalars: &[(Self::Element, Self::Scalar)]) -> Self::Element {
		EdwardsPoint::lincomb(elements_and_scalars)
	}
}
