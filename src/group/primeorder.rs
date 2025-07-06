#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::ops::Add;

use elliptic_curve::group::GroupEncoding;
use elliptic_curve::hash2curve::{ExpandMsg, GroupDigest};
use elliptic_curve::ops::{BatchInvert, Invert, LinearCombination};
use elliptic_curve::point::NonIdentity;
use elliptic_curve::sec1::{CompressedPointSize, ModulusSize};
use elliptic_curve::{
	BatchNormalize, FieldBytesSize, Group as _, NonZeroScalar, OprfParameters, PrimeField, Scalar,
};
use hybrid_array::typenum::{IsLess, True, U65536};
use hybrid_array::{Array, ArraySize};
use primeorder::{AffinePoint, PrimeCurveParams, ProjectivePoint};
use rand_core::TryCryptoRng;

use super::{Dst, Group};
use crate::cipher_suite::{CipherSuite, Id};

impl<C> Group for C
where
	C: GroupDigest<ProjectivePoint = ProjectivePoint<C>> + PrimeCurveParams,
	FieldBytesSize<C>: Add<FieldBytesSize<C>, Output: ArraySize> + ModulusSize,
	CompressedPointSize<C>: IsLess<U65536, Output = True>,
	ProjectivePoint<C>: GroupEncoding<Repr = Array<u8, CompressedPointSize<C>>>,
	AffinePoint<C>: GroupEncoding<Repr = Array<u8, CompressedPointSize<C>>>,
{
	type K = C::K;

	type NonZeroScalar = NonZeroScalar<C>;
	type Scalar = C::Scalar;
	type ScalarLength = FieldBytesSize<C>;

	type NonIdentityElement = NonIdentity<ProjectivePoint<C>>;
	type Element = ProjectivePoint<C>;
	type ElementLength = CompressedPointSize<C>;

	fn scalar_random<R: TryCryptoRng>(rng: &mut R) -> Result<Self::NonZeroScalar, R::Error> {
		NonZeroScalar::try_from_rng(rng)
	}

	fn hash_to_scalar<E>(input: &[&[u8]], dst: Dst) -> Self::Scalar
	where
		E: ExpandMsg<Self::K>,
	{
		C::hash_to_scalar::<E>(input, dst.as_ref()).expect("invalid cipher suite")
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

	#[cfg(feature = "alloc")]
	fn scalar_batch_vec_invert(scalars: Vec<Self::NonZeroScalar>) -> Vec<Self::NonZeroScalar> {
		NonZeroScalar::<C>::batch_invert(scalars)
	}

	fn scalar_batch_invert<const N: usize>(
		scalars: [Self::NonZeroScalar; N],
	) -> [Self::NonZeroScalar; N] {
		NonZeroScalar::<C>::batch_invert(scalars)
	}

	fn scalar_to_repr(scalar: &Self::Scalar) -> Array<u8, Self::ScalarLength> {
		scalar.to_repr()
	}

	fn non_zero_scalar_from_repr(
		bytes: &Array<u8, Self::ScalarLength>,
	) -> Option<Self::NonZeroScalar> {
		NonZeroScalar::<C>::from_repr(bytes.clone()).into_option()
	}

	fn scalar_from_repr(bytes: &Array<u8, Self::ScalarLength>) -> Option<Self::Scalar> {
		Scalar::<C>::from_repr(bytes.clone()).into_option()
	}

	fn element_identity() -> Self::Element {
		ProjectivePoint::<C>::identity()
	}

	fn element_generator() -> Self::Element {
		ProjectivePoint::<C>::generator()
	}

	fn hash_to_curve<E>(input: &[&[u8]], dst: Dst) -> Self::Element
	where
		E: ExpandMsg<Self::K>,
	{
		C::hash_from_bytes::<E>(input, dst.as_ref()).expect("invalid cipher suite")
	}

	fn non_identity_element_from_repr(
		bytes: &Array<u8, Self::ElementLength>,
	) -> Option<Self::NonIdentityElement> {
		NonIdentity::<ProjectivePoint<C>>::from_repr(bytes).into_option()
	}

	#[cfg(feature = "alloc")]
	fn non_identity_element_batch_vec_to_repr(
		elements: &[Self::NonIdentityElement],
	) -> Vec<Array<u8, Self::ElementLength>> {
		NonIdentity::<ProjectivePoint<C>>::batch_normalize(elements)
			.into_iter()
			.map(|point| point.to_bytes())
			.collect()
	}

	fn non_identity_element_batch_to_repr<const N: usize>(
		elements: &[Self::NonIdentityElement; N],
	) -> [Array<u8, Self::ElementLength>; N] {
		NonIdentity::<ProjectivePoint<C>>::batch_normalize(elements).map(|point| point.to_bytes())
	}

	fn element_batch_to_repr<const N: usize>(
		elements: &[Self::Element; N],
	) -> [Array<u8, Self::ElementLength>; N] {
		ProjectivePoint::<C>::batch_normalize(elements).map(|point| point.to_bytes())
	}

	fn lincomb(points_and_scalars: [(Self::Element, Self::Scalar); 2]) -> Self::Element {
		ProjectivePoint::<C>::lincomb(&points_and_scalars)
	}
}

impl<G> CipherSuite for G
where
	G: Group<K = <G as GroupDigest>::K> + OprfParameters,
{
	const ID: Id = Id::new(G::ID).unwrap();

	type Group = G;
	type Hash = G::Hash;
	type ExpandMsg = G::ExpandMsg;
}
