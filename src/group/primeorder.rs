//! NIST curves implementation.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::ops::Add;

use group::GroupEncoding;
use hash2curve::{ExpandMsg, GroupDigest, MapToCurve, OprfParameters};
use hybrid_array::typenum::{IsLess, True, U65536};
use hybrid_array::{Array, ArraySize};
use primeorder::elliptic_curve::ops::{BatchInvert, Invert, LinearCombination, Reduce};
use primeorder::elliptic_curve::point::NonIdentity;
use primeorder::elliptic_curve::sec1::{CompressedPointSize, ModulusSize, UncompressedPointSize};
use primeorder::elliptic_curve::{
	BatchNormalize, FieldBytes, FieldBytesSize, Group as _, NonZeroScalar, PrimeField, Scalar,
};
use primeorder::{AffinePoint, PrimeCurveParams, ProjectivePoint};
use rand_core::TryCryptoRng;

use super::Group;
use crate::cipher_suite::{CipherSuite, Id};
use crate::error::{InternalError, Result};

impl<G> CipherSuite for G
where
	G: Group<SecurityLevel = <G as MapToCurve>::SecurityLevel> + OprfParameters,
{
	const ID: Id = Id::new(G::ID).unwrap();

	type Group = G;
	type Hash = <G::ExpandMsg as ExpandMsg<<G as MapToCurve>::SecurityLevel>>::Hash;
	type ExpandMsg = G::ExpandMsg;
}

impl<C> Group for C
where
	C: GroupDigest<ProjectivePoint = ProjectivePoint<C>> + PrimeCurveParams,
	FieldBytes<C>: Copy,
	FieldBytesSize<C>: Add<FieldBytesSize<C>, Output: ArraySize> + ModulusSize,
	CompressedPointSize<C>: IsLess<U65536, Output = True>,
	ProjectivePoint<C>:
		group::Group<Scalar = Scalar<C>> + GroupEncoding<Repr = Array<u8, CompressedPointSize<C>>>,
	AffinePoint<C>: GroupEncoding<Repr = Array<u8, CompressedPointSize<C>>>,
	Scalar<C>: Reduce<Array<u8, C::Length>>,
	<CompressedPointSize<C> as ArraySize>::ArrayType<u8>: Copy,
	<UncompressedPointSize<C> as ArraySize>::ArrayType<u8>: Copy,
{
	type SecurityLevel = C::SecurityLevel;

	type NonZeroScalar = NonZeroScalar<C>;
	type Scalar = Scalar<C>;
	type ScalarLength = FieldBytesSize<C>;

	type NonIdentityElement = NonIdentity<ProjectivePoint<C>>;
	type Element = ProjectivePoint<C>;
	type ElementLength = CompressedPointSize<C>;

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
		hash2curve::hash_to_scalar::<C, E, C::Length>(input, dst).map_err(|_| InternalError)
	}

	fn non_zero_scalar_mul_by_generator(scalar: &Self::NonZeroScalar) -> Self::NonIdentityElement {
		NonIdentity::mul_by_generator(scalar)
	}

	fn scalar_mul_by_generator(scalar: &Self::Scalar) -> Self::Element {
		ProjectivePoint::<C>::mul_by_generator(scalar)
	}

	fn scalar_invert(scalar: &Self::NonZeroScalar) -> Self::NonZeroScalar {
		scalar.invert()
	}

	fn scalar_batch_invert<const N: usize>(
		scalars: [Self::NonZeroScalar; N],
	) -> [Self::NonZeroScalar; N] {
		NonZeroScalar::<C>::batch_invert(scalars)
	}

	#[cfg(feature = "alloc")]
	fn scalar_batch_alloc_invert(scalars: Vec<Self::NonZeroScalar>) -> Vec<Self::NonZeroScalar> {
		NonZeroScalar::<C>::batch_invert(scalars)
	}

	fn scalar_to_repr(scalar: &Self::Scalar) -> Array<u8, Self::ScalarLength> {
		scalar.to_repr()
	}

	fn non_zero_scalar_from_repr(
		repr: Array<u8, Self::ScalarLength>,
	) -> Result<Self::NonZeroScalar, InternalError> {
		NonZeroScalar::<C>::from_repr(repr)
			.into_option()
			.ok_or(InternalError)
	}

	fn scalar_from_repr(
		repr: &Array<u8, Self::ScalarLength>,
	) -> Result<Self::Scalar, InternalError> {
		Scalar::<C>::from_repr(*repr)
			.into_option()
			.ok_or(InternalError)
	}

	fn element_identity() -> Self::Element {
		ProjectivePoint::<C>::identity()
	}

	fn element_generator() -> Self::Element {
		ProjectivePoint::<C>::generator()
	}

	fn hash_to_curve<E>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Element, InternalError>
	where
		E: ExpandMsg<Self::SecurityLevel>,
	{
		hash2curve::hash_from_bytes::<C, E>(input, dst).map_err(|_| InternalError)
	}

	fn element_to_repr(element: &Self::Element) -> Array<u8, Self::ElementLength> {
		element.to_bytes()
	}

	fn non_identity_element_batch_maybe_double_to_repr<const N: usize>(
		elements: &[Self::NonIdentityElement; N],
	) -> [Array<u8, Self::ElementLength>; N] {
		NonIdentity::<ProjectivePoint<C>>::batch_normalize(elements).map(|point| point.to_bytes())
	}

	#[cfg(feature = "alloc")]
	fn non_identity_element_batch_alloc_maybe_double_to_repr(
		elements: &[Self::NonIdentityElement],
	) -> Vec<Array<u8, Self::ElementLength>> {
		NonIdentity::<ProjectivePoint<C>>::batch_normalize(elements)
			.into_iter()
			.map(|point| point.to_bytes())
			.collect()
	}

	fn element_batch_maybe_double_to_repr<const N: usize>(
		elements: &[Self::Element; N],
	) -> [Array<u8, Self::ElementLength>; N] {
		ProjectivePoint::<C>::batch_normalize(elements).map(|point| point.to_bytes())
	}

	fn non_identity_element_from_repr(
		repr: &Array<u8, Self::ElementLength>,
	) -> Result<Self::NonIdentityElement, InternalError> {
		NonIdentity::<ProjectivePoint<C>>::from_repr(repr)
			.into_option()
			.ok_or(InternalError)
	}

	fn lincomb<const N: usize>(
		elements_and_scalars: &[(Self::Element, Self::Scalar); N],
	) -> Self::Element {
		ProjectivePoint::<C>::lincomb(elements_and_scalars)
	}

	#[cfg(feature = "alloc")]
	fn alloc_lincomb(elements_and_scalars: &[(Self::Element, Self::Scalar)]) -> Self::Element {
		ProjectivePoint::<C>::lincomb(elements_and_scalars)
	}
}
