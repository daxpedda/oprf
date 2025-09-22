//! [`Edwards25519`] implementation.

use core::ops::{Deref, Mul};

use curve25519_dalek::traits::MultiscalarMul;
use curve25519_dalek::{EdwardsPoint, Scalar};
use group::{Group as _, GroupEncoding};
use hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};
use hybrid_array::Array;
use hybrid_array::typenum::{U16, U32};
use oprf::cipher_suite::{CipherSuite, Id};
use oprf::error::InternalError;
use oprf::group::Group;
use rand_core::TryCryptoRng;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use subtle::{ConstantTimeEq, CtOption};
use zeroize::Zeroize;

use crate::util::CollectArray;

/// OPRF implementation for Edwards25519.
#[derive(Clone, Copy, Debug)]
pub struct Edwards25519;

impl CipherSuite for Edwards25519 {
	const ID: Id = Id::new(b"edwards25519-SHA512").unwrap();

	type Group = Self;
	type Hash = Sha512;
	type ExpandMsg = ExpandMsgXmd<Sha512>;
}

impl Group for Edwards25519 {
	type SecurityLevel = U16;

	type NonZeroScalar = NonZeroScalar;
	type Scalar = Scalar;
	type ScalarLength = U32;

	type NonIdentityElement = NonIdentityElement;
	type Element = EdwardsPoint;
	type ElementLength = U32;

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
		let mut uniform_bytes = [0; 64];
		E::expand_message(
			input,
			dst,
			64.try_into().expect("`64` is smaller than `U16::MAX"),
		)
		.map_err(|_| InternalError)?
		.fill_bytes(&mut uniform_bytes)
		.expect("sizes match");

		Ok(Scalar::from_bytes_mod_order_wide(&uniform_bytes))
	}

	fn non_zero_scalar_mul_by_generator(scalar: &Self::NonZeroScalar) -> Self::NonIdentityElement {
		NonIdentityElement(EdwardsPoint::mul_by_generator(scalar))
	}

	fn scalar_mul_by_generator(scalar: &Self::Scalar) -> Self::Element {
		EdwardsPoint::mul_by_generator(scalar)
	}

	fn scalar_invert(scalar: &Self::NonZeroScalar) -> Self::NonZeroScalar {
		NonZeroScalar(scalar.0.invert())
	}

	fn scalar_batch_invert<const N: usize>(
		scalars: [Self::NonZeroScalar; N],
	) -> [Self::NonZeroScalar; N] {
		let mut scalars: [_; N] = scalars.map(|scalar| scalar.0);
		Scalar::invert_batch(&mut scalars);
		scalars.map(NonZeroScalar)
	}

	#[cfg(feature = "alloc")]
	fn scalar_batch_alloc_invert(scalars: Vec<Self::NonZeroScalar>) -> Vec<Self::NonZeroScalar> {
		let mut scalars: Vec<_> = scalars.into_iter().map(|scalar| scalar.0).collect();
		Scalar::invert_batch_alloc(&mut scalars);
		scalars.into_iter().map(NonZeroScalar).collect()
	}

	fn scalar_to_repr(scalar: &Self::Scalar) -> Array<u8, Self::ScalarLength> {
		scalar.to_bytes().into()
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
		Scalar::from_canonical_bytes(repr.0)
			.into_option()
			.ok_or(InternalError)
	}

	fn element_identity() -> Self::Element {
		EdwardsPoint::identity()
	}

	fn element_generator() -> Self::Element {
		EdwardsPoint::generator()
	}

	fn hash_to_curve<E>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Element, InternalError>
	where
		E: ExpandMsg<Self::SecurityLevel>,
	{
		let mut uniform_bytes = [0; 64];
		E::expand_message(
			input,
			dst,
			64.try_into().expect("`64` is smaller than `U16::MAX"),
		)
		.map_err(|_| InternalError)?
		.fill_bytes(&mut uniform_bytes)
		.expect("sizes match");

		Ok(EdwardsPoint::from_uniform_bytes(&uniform_bytes))
	}

	fn element_to_repr(element: &Self::Element) -> Array<u8, Self::ElementLength> {
		element.to_bytes().into()
	}

	fn non_identity_element_batch_maybe_double_to_repr<const N: usize>(
		elements: &[Self::NonIdentityElement; N],
	) -> [Array<u8, Self::ElementLength>; N] {
		let elements = elements.iter().map(|element| element.0).collect_array();
		EdwardsPoint::compress_batch(&elements).map(|compressed| compressed.0.into())
	}

	#[cfg(feature = "alloc")]
	fn non_identity_element_batch_alloc_maybe_double_to_repr(
		elements: &[Self::NonIdentityElement],
	) -> Vec<Array<u8, Self::ElementLength>> {
		let elements: Vec<_> = elements.iter().map(|element| element.0).collect();
		EdwardsPoint::compress_batch_alloc(elements.as_slice())
			.into_iter()
			.map(|repr| repr.0.into())
			.collect()
	}

	fn element_batch_maybe_double_to_repr<const N: usize>(
		elements: &[Self::Element; N],
	) -> [Array<u8, Self::ElementLength>; N] {
		EdwardsPoint::compress_batch(elements).map(|compressed| compressed.0.into())
	}

	fn non_identity_element_from_repr(
		repr: &Array<u8, Self::ElementLength>,
	) -> Result<Self::NonIdentityElement, InternalError> {
		NonIdentityElement::from_repr(repr)
			.into_option()
			.ok_or(InternalError)
	}

	fn lincomb<const N: usize>(
		elements_and_scalars: &[(Self::Element, Self::Scalar); N],
	) -> Self::Element {
		EdwardsPoint::multiscalar_mul(elements_and_scalars)
	}

	#[cfg(feature = "alloc")]
	fn alloc_lincomb(elements_and_scalars: &[(Self::Element, Self::Scalar)]) -> Self::Element {
		EdwardsPoint::multiscalar_mul_alloc(
			elements_and_scalars
				.iter()
				.map(|(element, scalar)| (element, scalar)),
		)
	}
}

/// Analogous to [`elliptic_curve::NonZeroScalar`].
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct NonZeroScalar(Scalar);

impl NonZeroScalar {
	/// Creates a [`NonZeroScalar`]. Returns [`None`] if the provided [`Scalar`]
	/// is the zero-scalar.
	#[must_use]
	pub fn new(scalar: Scalar) -> CtOption<Self> {
		CtOption::new(Self(scalar), !scalar.ct_eq(&Scalar::ZERO))
	}

	/// Returns the deserialized [`NonZeroScalar`]. Returns [`None`] if the
	/// resulting [`Scalar`] is the zero-scalar or not a canonical
	/// representation.
	pub fn from_repr(repr: Array<u8, U32>) -> CtOption<Self> {
		Scalar::from_canonical_bytes(repr.0).and_then(Self::new)
	}
}

impl Deref for NonZeroScalar {
	type Target = Scalar;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl From<NonZeroScalar> for Scalar {
	fn from(value: NonZeroScalar) -> Self {
		value.0
	}
}

impl Mul<&NonIdentityElement> for NonZeroScalar {
	type Output = NonIdentityElement;

	fn mul(self, rhs: &NonIdentityElement) -> Self::Output {
		NonIdentityElement(self.0 * rhs.0)
	}
}

impl TryFrom<Scalar> for NonZeroScalar {
	type Error = ();

	fn try_from(value: Scalar) -> Result<Self, Self::Error> {
		Self::new(value).into_option().ok_or(())
	}
}

impl Zeroize for NonZeroScalar {
	fn zeroize(&mut self) {
		self.0 = Scalar::ONE;
	}
}

/// Analogous to [`elliptic_curve::point::NonIdentity`].
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonIdentityElement(EdwardsPoint);

impl NonIdentityElement {
	/// Creates a [`NonIdentityElement`]. Returns [`None`] if the provided
	/// [`EdwardsPoint`] is the identity point.
	#[must_use]
	pub fn new(point: EdwardsPoint) -> CtOption<Self> {
		CtOption::new(Self(point), !EdwardsPoint::is_identity(&point))
	}

	/// Returns the deserialized [`NonIdentityElement`]. Returns [`None`] if the
	/// resulting [`EdwardsPoint`] is the identity point or not a canonical
	/// representation.
	pub fn from_repr(repr: &Array<u8, U32>) -> CtOption<Self> {
		EdwardsPoint::from_bytes(&repr.0).and_then(Self::new)
	}
}

impl Deref for NonIdentityElement {
	type Target = EdwardsPoint;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl From<NonIdentityElement> for EdwardsPoint {
	fn from(value: NonIdentityElement) -> Self {
		value.0
	}
}

impl TryFrom<EdwardsPoint> for NonIdentityElement {
	type Error = ();

	fn try_from(value: EdwardsPoint) -> Result<Self, Self::Error> {
		Self::new(value).into_option().ok_or(())
	}
}

impl Zeroize for NonIdentityElement {
	fn zeroize(&mut self) {
		self.0 = EdwardsPoint::generator();
	}
}
