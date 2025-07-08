#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use digest::XofFixedWrapper;
use ed448_goldilocks::sha3::Shake256;
use ed448_goldilocks::{Decaf448NonZeroScalar, DecafPoint, DecafScalar};
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::ops::{BatchInvert, Invert, LinearCombination};
use elliptic_curve::point::NonIdentity;
use elliptic_curve::{Group as _, PrimeField};
use hash2curve::{ExpandMsg, ExpandMsgXof, GroupDigest};
use hybrid_array::Array;
use hybrid_array::typenum::{U28, U56, U64};
use rand_core::TryCryptoRng;

use super::{Dst, Group};
use crate::CipherSuite;
use crate::cipher_suite::Id;
use crate::error::Result;
use crate::util::CollectArray;

#[derive(Clone, Copy, Debug)]
pub struct Decaf448;

impl Group for Decaf448 {
	type K = U28;

	type NonZeroScalar = Decaf448NonZeroScalar;
	type Scalar = DecafScalar;
	type ScalarLength = U56;

	type NonIdentityElement = NonIdentity<DecafPoint>;
	type Element = DecafPoint;
	type ElementLength = U56;

	fn scalar_random<R>(rng: &mut R) -> Result<Self::NonZeroScalar, R::Error>
	where
		R: ?Sized + TryCryptoRng,
	{
		let mut bytes = Array::default();

		loop {
			rng.try_fill_bytes(&mut bytes)?;

			if let Some(result) = Decaf448NonZeroScalar::from_repr(bytes).into() {
				break Ok(result);
			}
		}
	}

	fn hash_to_scalar<E>(input: &[&[u8]], dst: Dst) -> Option<Self::Scalar>
	where
		E: ExpandMsg<Self::K>,
	{
		ed448_goldilocks::Decaf448::hash_to_scalar::<E>(input, dst.as_ref()).ok()
	}

	fn non_zero_scalar_mul_by_generator(scalar: &Self::NonZeroScalar) -> Self::NonIdentityElement {
		NonIdentity::mul_by_generator(scalar)
	}

	fn scalar_mul_by_generator(scalar: &Self::Scalar) -> Self::Element {
		DecafPoint::mul_by_generator(scalar)
	}

	fn scalar_invert(scalar: &Self::NonZeroScalar) -> Self::NonZeroScalar {
		scalar.invert()
	}

	fn scalar_batch_invert<const N: usize>(
		scalars: [Self::NonZeroScalar; N],
	) -> [Self::NonZeroScalar; N] {
		Decaf448NonZeroScalar::batch_invert(scalars)
	}

	#[cfg(feature = "alloc")]
	fn scalar_batch_vec_invert(scalars: Vec<Self::NonZeroScalar>) -> Vec<Self::NonZeroScalar> {
		Decaf448NonZeroScalar::batch_invert(scalars)
	}

	fn scalar_to_repr(scalar: &Self::Scalar) -> Array<u8, Self::ScalarLength> {
		scalar.to_repr()
	}

	fn non_zero_scalar_from_repr(
		bytes: &Array<u8, Self::ScalarLength>,
	) -> Option<Self::NonZeroScalar> {
		Decaf448NonZeroScalar::from_repr(*bytes).into_option()
	}

	fn scalar_from_repr(bytes: &Array<u8, Self::ScalarLength>) -> Option<Self::Scalar> {
		DecafScalar::from_repr(*bytes).into_option()
	}

	fn element_identity() -> Self::Element {
		DecafPoint::IDENTITY
	}

	fn element_generator() -> Self::Element {
		DecafPoint::GENERATOR
	}

	fn hash_to_curve<E>(input: &[&[u8]], dst: Dst) -> Option<Self::Element>
	where
		E: ExpandMsg<Self::K>,
	{
		ed448_goldilocks::Decaf448::hash_from_bytes::<E>(input, dst.as_ref()).ok()
	}

	fn non_identity_element_batch_to_repr<const N: usize>(
		elements: &[Self::NonIdentityElement; N],
	) -> [Array<u8, Self::ElementLength>; N] {
		elements.iter().map(NonIdentity::to_bytes).collect_array()
	}

	#[cfg(feature = "alloc")]
	fn non_identity_element_batch_vec_to_repr(
		elements: &[Self::NonIdentityElement],
	) -> Vec<Array<u8, Self::ElementLength>> {
		elements.iter().map(NonIdentity::to_bytes).collect()
	}

	fn element_batch_to_repr<const N: usize>(
		elements: &[Self::Element; N],
	) -> [Array<u8, Self::ElementLength>; N] {
		elements.iter().map(DecafPoint::to_bytes).collect_array()
	}

	fn non_identity_element_from_repr(
		bytes: &Array<u8, Self::ElementLength>,
	) -> Option<Self::NonIdentityElement> {
		NonIdentity::from_repr(bytes).into_option()
	}

	fn lincomb(elements_and_scalars: [(Self::Element, Self::Scalar); 2]) -> Self::Element {
		DecafPoint::lincomb(&elements_and_scalars)
	}
}

impl CipherSuite for Decaf448 {
	const ID: Id = Id::new(b"decaf448-SHAKE256").unwrap();

	type Group = Self;
	type Hash = XofFixedWrapper<Shake256, U64>;
	type ExpandMsg = ExpandMsgXof<Shake256>;
}
