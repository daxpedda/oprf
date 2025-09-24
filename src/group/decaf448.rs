//! [`Decaf448`] implementation.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use digest::XofFixedWrapper;
use ed448_goldilocks::Decaf448;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::group::ff::PrimeField;
use elliptic_curve::ops::{BatchInvert, Invert, LinearCombination};
use elliptic_curve::point::NonIdentity;
use elliptic_curve::{FieldBytesSize, Group as _, NonZeroScalar, ProjectivePoint, Scalar};
use hash2curve::{ExpandMsg, GroupDigest, MapToCurve};
use hybrid_array::typenum::U64;
use hybrid_array::{Array, AssocArraySize};
use rand_core::TryCryptoRng;
use sha3::Shake256;

use crate::cipher_suite::{CipherSuite, Id};
use crate::error::InternalError;
use crate::group::Group;

impl CipherSuite for Decaf448 {
	const ID: Id = Id::new(b"decaf448-SHAKE256").unwrap();

	type Group = Self;
	type Hash = XofFixedWrapper<Shake256, U64>;
	type ExpandMsg = <Self as GroupDigest>::ExpandMsg;
}

impl Group for Decaf448 {
	type SecurityLevel = <Self as MapToCurve>::SecurityLevel;

	type NonZeroScalar = NonZeroScalar<Self>;
	type Scalar = Scalar<Self>;
	type ScalarLength = FieldBytesSize<Self>;

	type NonIdentityElement = NonIdentity<ProjectivePoint<Self>>;
	type Element = ProjectivePoint<Self>;
	type ElementLength = <<ProjectivePoint<Self> as GroupEncoding>::Repr as AssocArraySize>::Size;

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
		hash2curve::hash_to_scalar::<Self, E, U64>(input, dst).map_err(|_| InternalError)
	}

	fn non_zero_scalar_mul_by_generator(scalar: &Self::NonZeroScalar) -> Self::NonIdentityElement {
		NonIdentity::mul_by_generator(scalar)
	}

	fn scalar_mul_by_generator(scalar: &Self::Scalar) -> Self::Element {
		ProjectivePoint::<Self>::mul_by_generator(scalar)
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
		Scalar::<Self>::from_repr(*repr)
			.into_option()
			.ok_or(InternalError)
	}

	fn element_identity() -> Self::Element {
		ProjectivePoint::<Self>::IDENTITY
	}

	fn element_generator() -> Self::Element {
		ProjectivePoint::<Self>::GENERATOR
	}

	fn hash_to_curve<E>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Element, InternalError>
	where
		E: ExpandMsg<Self::SecurityLevel>,
	{
		hash2curve::hash_from_bytes::<Self, E>(input, dst).map_err(|_| InternalError)
	}

	fn element_to_repr(element: &Self::Element) -> Array<u8, Self::ElementLength> {
		element.to_bytes()
	}

	fn non_identity_element_from_repr(
		repr: &Array<u8, Self::ElementLength>,
	) -> Result<Self::NonIdentityElement, InternalError> {
		NonIdentity::<ProjectivePoint<Self>>::from_repr(repr)
			.into_option()
			.ok_or(InternalError)
	}

	fn lincomb<const N: usize>(
		elements_and_scalars: &[(Self::Element, Self::Scalar); N],
	) -> Self::Element {
		ProjectivePoint::<Self>::lincomb(elements_and_scalars)
	}

	#[cfg(feature = "alloc")]
	fn alloc_lincomb(elements_and_scalars: &[(Self::Element, Self::Scalar)]) -> Self::Element {
		ProjectivePoint::<Self>::lincomb(elements_and_scalars)
	}
}
