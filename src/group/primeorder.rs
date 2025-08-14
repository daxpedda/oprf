//! NIST curves implementation.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::ops::Add;

use elliptic_curve::group::GroupEncoding;
use elliptic_curve::ops::{BatchInvert, Invert, LinearCombination};
use elliptic_curve::point::NonIdentity;
use elliptic_curve::sec1::{CompressedPointSize, ModulusSize};
use elliptic_curve::{
	BatchNormalize, FieldBytesSize, Group as _, NonZeroScalar, PrimeField, Scalar,
};
use hash2curve::{ExpandMsg, GroupDigest, OprfParameters};
use hybrid_array::typenum::{IsLess, True, U65536};
use hybrid_array::{Array, ArraySize};
use primeorder::{AffinePoint, PrimeCurveParams, ProjectivePoint};
use rand_core::TryCryptoRng;

use super::Group;
use crate::cipher_suite::{CipherSuite, Id};
use crate::error::{InternalError, Result};
use crate::util::CollectArray;

impl<G> CipherSuite for G
where
	G: Group<SecurityLevel = <G as GroupDigest>::K> + OprfParameters,
{
	const ID: Id = Id::new(G::ID).unwrap();

	type Group = G;
	type Hash = G::Hash;
	type ExpandMsg = G::ExpandMsg;
}

impl<C> Group for C
where
	C: GroupDigest<ProjectivePoint = ProjectivePoint<C>> + PrimeCurveParams,
	FieldBytesSize<C>: Add<FieldBytesSize<C>, Output: ArraySize> + ModulusSize,
	CompressedPointSize<C>: IsLess<U65536, Output = True>,
	ProjectivePoint<C>: GroupEncoding<Repr = Array<u8, CompressedPointSize<C>>>,
	AffinePoint<C>: GroupEncoding<Repr = Array<u8, CompressedPointSize<C>>>,
{
	type SecurityLevel = C::K;

	type NonZeroScalar = NonZeroScalar<C>;
	type Scalar = C::Scalar;
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

			if let Some(result) = NonZeroScalar::from_repr(bytes.clone()).into() {
				break Ok(result);
			}
		}
	}

	fn hash_to_scalar<E>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Scalar, InternalError>
	where
		E: ExpandMsg<Self::SecurityLevel>,
	{
		C::hash_to_scalar::<E>(input, dst).map_err(|_| InternalError)
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
		bytes: Array<u8, Self::ScalarLength>,
	) -> Result<Self::NonZeroScalar, InternalError> {
		NonZeroScalar::<C>::from_repr(bytes)
			.into_option()
			.ok_or(InternalError)
	}

	fn scalar_from_repr(
		bytes: &Array<u8, Self::ScalarLength>,
	) -> Result<Self::Scalar, InternalError> {
		Scalar::<C>::from_repr(bytes.clone())
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
		C::hash_from_bytes::<E>(input, dst).map_err(|_| InternalError)
	}

	fn element_to_repr(element: &Self::Element) -> Array<u8, Self::ElementLength> {
		element.to_bytes()
	}

	fn non_identity_element_batch_multiply_and_repr<const N: usize>(
		elements_and_scalars: &[(Self::NonIdentityElement, Self::NonZeroScalar); N],
	) -> [(Self::NonIdentityElement, Array<u8, Self::ElementLength>); N] {
		let elements = elements_and_scalars
			.iter()
			.map(|(element, scalar)| scalar * element)
			.collect_array::<N>();
		let reprs = NonIdentity::<ProjectivePoint<C>>::batch_normalize(&elements);

		elements
			.into_iter()
			.zip(reprs)
			.map(|(element, repr)| (element, repr.to_bytes()))
			.collect_array()
	}

	fn non_identity_element_batch_multiply_to_repr<const N: usize>(
		elements_and_scalars: &[(Self::NonIdentityElement, Self::NonZeroScalar); N],
	) -> [Array<u8, Self::ElementLength>; N] {
		let elements = elements_and_scalars
			.iter()
			.map(|(element, scalar)| scalar * element)
			.collect_array();

		NonIdentity::<ProjectivePoint<C>>::batch_normalize(&elements).map(|point| point.to_bytes())
	}

	#[cfg(feature = "alloc")]
	fn non_identity_element_batch_alloc_multiply_and_repr(
		elements_and_scalars: &[(Self::NonIdentityElement, Self::NonZeroScalar)],
	) -> Vec<(Self::NonIdentityElement, Array<u8, Self::ElementLength>)> {
		let elements: Vec<_> = elements_and_scalars
			.iter()
			.map(|(element, scalar)| scalar * element)
			.collect();
		let reprs = NonIdentity::<ProjectivePoint<C>>::batch_normalize(elements.as_slice());

		elements
			.into_iter()
			.zip(reprs)
			.map(|(element, repr)| (element, repr.to_bytes()))
			.collect()
	}

	#[cfg(feature = "alloc")]
	fn non_identity_element_batch_alloc_multiply_to_repr(
		elements_and_scalars: &[(Self::NonIdentityElement, Self::NonZeroScalar)],
	) -> Vec<Array<u8, Self::ElementLength>> {
		let elements: Vec<_> = elements_and_scalars
			.iter()
			.map(|(element, scalar)| scalar * element)
			.collect();

		NonIdentity::<ProjectivePoint<C>>::batch_normalize(elements.as_slice())
			.into_iter()
			.map(|point| point.to_bytes())
			.collect()
	}

	fn element_batch_to_repr<const N: usize>(
		elements: &[Self::Element; N],
	) -> [Array<u8, Self::ElementLength>; N] {
		ProjectivePoint::<C>::batch_normalize(elements).map(|point| point.to_bytes())
	}

	fn non_identity_element_from_repr(
		bytes: &Array<u8, Self::ElementLength>,
	) -> Result<Self::NonIdentityElement, InternalError> {
		NonIdentity::<ProjectivePoint<C>>::from_repr(bytes)
			.into_option()
			.ok_or(InternalError)
	}

	fn lincomb(elements_and_scalars: [(Self::Element, Self::Scalar); 2]) -> Self::Element {
		ProjectivePoint::<C>::lincomb(&elements_and_scalars)
	}
}
