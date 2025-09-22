//! NIST curves implementation.

use elliptic_curve::ops::{BatchInvert, Invert, LinearCombination};
use elliptic_curve::point::NonIdentity;
use elliptic_curve::sec1::CompressedPointSize;
use elliptic_curve::{BatchNormalize, FieldBytesSize, Group as _, PrimeField};
use group::GroupEncoding;
use hash2curve::{ExpandMsg, GroupDigest, MapToCurve};
use hybrid_array::Array;
use k256::{NonZeroScalar, ProjectivePoint, Scalar};
use oprf::cipher_suite::{CipherSuite, Id};
use oprf::error::InternalError;
use oprf::group::Group;
use rand_core::TryCryptoRng;
use sha2::Sha256;

/// OPRF implementation for secp256k1.
#[derive(Clone, Copy, Debug)]
pub struct Secp256k1;

impl CipherSuite for Secp256k1 {
	const ID: Id = Id::new(b"secp256k1-SHA256").unwrap();

	type Group = Self;
	type Hash = Sha256;
	type ExpandMsg = <k256::Secp256k1 as GroupDigest>::ExpandMsg;
}

impl Group for Secp256k1 {
	type SecurityLevel = <k256::Secp256k1 as MapToCurve>::SecurityLevel;

	type NonZeroScalar = NonZeroScalar;
	type Scalar = Scalar;
	type ScalarLength = FieldBytesSize<k256::Secp256k1>;

	type NonIdentityElement = NonIdentity<ProjectivePoint>;
	type Element = ProjectivePoint;
	type ElementLength = CompressedPointSize<k256::Secp256k1>;

	fn scalar_random<R>(rng: &mut R) -> Result<Self::NonZeroScalar, R::Error>
	where
		R: ?Sized + TryCryptoRng,
	{
		let mut bytes = Array::default();

		loop {
			rng.try_fill_bytes(&mut bytes)?;

			if let Some(result) = NonZeroScalar::from_repr(bytes).into() {
				break Ok(result);
			}
		}
	}

	fn hash_to_scalar<E>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Scalar, InternalError>
	where
		E: ExpandMsg<Self::SecurityLevel>,
	{
		hash2curve::hash_to_scalar::<k256::Secp256k1, E, <k256::Secp256k1 as MapToCurve>::Length>(
			input, dst,
		)
		.map_err(|_| InternalError)
	}

	fn non_zero_scalar_mul_by_generator(scalar: &Self::NonZeroScalar) -> Self::NonIdentityElement {
		NonIdentity::mul_by_generator(scalar)
	}

	fn scalar_mul_by_generator(scalar: &Self::Scalar) -> Self::Element {
		ProjectivePoint::mul_by_generator(scalar)
	}

	fn scalar_invert(scalar: &Self::NonZeroScalar) -> Self::NonZeroScalar {
		scalar.invert()
	}

	fn scalar_batch_invert<const N: usize>(
		scalars: [Self::NonZeroScalar; N],
	) -> [Self::NonZeroScalar; N] {
		NonZeroScalar::batch_invert(scalars)
	}

	#[cfg(feature = "alloc")]
	fn scalar_batch_alloc_invert(scalars: Vec<Self::NonZeroScalar>) -> Vec<Self::NonZeroScalar> {
		NonZeroScalar::batch_invert(scalars)
	}

	fn scalar_to_repr(scalar: &Self::Scalar) -> Array<u8, Self::ScalarLength> {
		scalar.to_repr()
	}

	fn non_zero_scalar_from_repr(
		repr: Array<u8, Self::ScalarLength>,
	) -> Result<Self::NonZeroScalar, InternalError> {
		NonZeroScalar::from_repr(repr)
			.into_option()
			.ok_or(InternalError)
	}

	fn scalar_from_repr(
		repr: &Array<u8, Self::ScalarLength>,
	) -> Result<Self::Scalar, InternalError> {
		Scalar::from_repr(*repr).into_option().ok_or(InternalError)
	}

	fn element_identity() -> Self::Element {
		ProjectivePoint::IDENTITY
	}

	fn element_generator() -> Self::Element {
		ProjectivePoint::GENERATOR
	}

	fn hash_to_curve<E>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Element, InternalError>
	where
		E: ExpandMsg<Self::SecurityLevel>,
	{
		hash2curve::hash_from_bytes::<k256::Secp256k1, E>(input, dst).map_err(|_| InternalError)
	}

	fn element_to_repr(element: &Self::Element) -> Array<u8, Self::ElementLength> {
		element.to_bytes()
	}

	fn non_identity_element_batch_maybe_double_to_repr<const N: usize>(
		elements: &[Self::NonIdentityElement; N],
	) -> [Array<u8, Self::ElementLength>; N] {
		NonIdentity::<ProjectivePoint>::batch_normalize(elements).map(|point| point.to_bytes())
	}

	#[cfg(feature = "alloc")]
	fn non_identity_element_batch_alloc_maybe_double_to_repr(
		elements: &[Self::NonIdentityElement],
	) -> Vec<Array<u8, Self::ElementLength>> {
		NonIdentity::<ProjectivePoint>::batch_normalize(elements)
			.into_iter()
			.map(|point| point.to_bytes())
			.collect()
	}

	fn element_batch_maybe_double_to_repr<const N: usize>(
		elements: &[Self::Element; N],
	) -> [Array<u8, Self::ElementLength>; N] {
		ProjectivePoint::batch_normalize(elements).map(|point| point.to_bytes())
	}

	fn non_identity_element_from_repr(
		repr: &Array<u8, Self::ElementLength>,
	) -> Result<Self::NonIdentityElement, InternalError> {
		NonIdentity::<ProjectivePoint>::from_repr(repr)
			.into_option()
			.ok_or(InternalError)
	}

	fn lincomb<const N: usize>(
		elements_and_scalars: &[(Self::Element, Self::Scalar); N],
	) -> Self::Element {
		ProjectivePoint::lincomb(elements_and_scalars)
	}

	#[cfg(feature = "alloc")]
	fn alloc_lincomb(elements_and_scalars: &[(Self::Element, Self::Scalar)]) -> Self::Element {
		ProjectivePoint::lincomb(elements_and_scalars)
	}
}
