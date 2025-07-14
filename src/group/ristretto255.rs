#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::ops::{Deref, Mul};

use curve25519_dalek::{RistrettoPoint, Scalar};
use elliptic_curve::Group as _;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::subtle::{ConstantTimeEq, CtOption};
#[cfg(feature = "ristretto255-ciphersuite")]
use hash2curve::ExpandMsgXmd;
use hash2curve::{ExpandMsg, Expander};
use hybrid_array::Array;
use hybrid_array::typenum::{U16, U32};
use rand_core::TryCryptoRng;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "ristretto255-ciphersuite")]
use sha2::Sha512;
use zeroize::Zeroize;

use super::{Dst, Group};
use crate::cipher_suite::{CipherSuite, Id};
use crate::error::Result;

#[derive(Clone, Copy, Debug)]
pub struct Ristretto255;

impl Group for Ristretto255 {
	type K = U16;

	type NonZeroScalar = NonZeroScalar;
	type Scalar = Scalar;
	type ScalarLength = U32;

	type NonIdentityElement = NonIdentityElement;
	type Element = RistrettoPoint;
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

	fn hash_to_scalar<E>(input: &[&[u8]], dst: Dst) -> Option<Self::Scalar>
	where
		E: ExpandMsg<Self::K>,
	{
		let mut uniform_bytes = [0; 64];
		E::expand_message(
			input,
			&dst,
			64.try_into().expect("`64` is smaller than `U16::MAX"),
		)
		.ok()?
		.fill_bytes(&mut uniform_bytes);

		Some(Scalar::from_bytes_mod_order_wide(&uniform_bytes))
	}

	fn non_zero_scalar_mul_by_generator(scalar: &Self::NonZeroScalar) -> Self::NonIdentityElement {
		NonIdentityElement(RistrettoPoint::mul_by_generator(scalar))
	}

	fn scalar_mul_by_generator(scalar: &Self::Scalar) -> Self::Element {
		RistrettoPoint::mul_by_generator(scalar)
	}

	fn scalar_invert(scalar: &Self::NonZeroScalar) -> Self::NonZeroScalar {
		NonZeroScalar(scalar.0.invert())
	}

	fn scalar_batch_invert<const N: usize>(
		scalars: [Self::NonZeroScalar; N],
	) -> [Self::NonZeroScalar; N] {
		let mut scalars: [_; N] = scalars.map(|scalar| scalar.0);
		Scalar::batch_invert(&mut scalars);
		scalars.map(NonZeroScalar)
	}

	#[cfg(feature = "alloc")]
	fn scalar_batch_alloc_invert(scalars: Vec<Self::NonZeroScalar>) -> Vec<Self::NonZeroScalar> {
		let mut scalars: Vec<_> = scalars.into_iter().map(|scalar| scalar.0).collect();
		Scalar::batch_alloc_invert(&mut scalars);
		scalars.into_iter().map(NonZeroScalar).collect()
	}

	fn scalar_to_repr(scalar: &Self::Scalar) -> Array<u8, Self::ScalarLength> {
		scalar.to_bytes().into()
	}

	fn non_zero_scalar_from_repr(
		bytes: Array<u8, Self::ScalarLength>,
	) -> Option<Self::NonZeroScalar> {
		NonZeroScalar::from_repr(bytes).into_option()
	}

	fn scalar_from_repr(bytes: &Array<u8, Self::ScalarLength>) -> Option<Self::Scalar> {
		Scalar::from_canonical_bytes(bytes.0).into_option()
	}

	fn element_identity() -> Self::Element {
		RistrettoPoint::identity()
	}

	fn element_generator() -> Self::Element {
		RistrettoPoint::generator()
	}

	fn hash_to_curve<E>(input: &[&[u8]], dst: Dst) -> Option<Self::Element>
	where
		E: ExpandMsg<Self::K>,
	{
		let mut uniform_bytes = [0; 64];
		E::expand_message(
			input,
			&dst,
			64.try_into().expect("`64` is smaller than `U16::MAX"),
		)
		.ok()?
		.fill_bytes(&mut uniform_bytes);

		Some(RistrettoPoint::from_uniform_bytes(&uniform_bytes))
	}

	fn element_to_repr(element: &Self::Element) -> Array<u8, Self::ElementLength> {
		element.to_bytes().into()
	}

	fn non_identity_element_from_repr(
		bytes: &Array<u8, Self::ElementLength>,
	) -> Option<Self::NonIdentityElement> {
		NonIdentityElement::from_repr(bytes).into_option()
	}
}

#[cfg(feature = "ristretto255-ciphersuite")]
impl CipherSuite for Ristretto255 {
	const ID: Id = Id::new(b"ristretto255-SHA512").unwrap();

	type Group = Self;
	type Hash = Sha512;
	type ExpandMsg = ExpandMsgXmd<Sha512>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonZeroScalar(Scalar);

impl NonZeroScalar {
	#[must_use]
	pub fn new(scalar: Scalar) -> CtOption<Self> {
		CtOption::new(Self(scalar), !scalar.ct_eq(&Scalar::ZERO))
	}

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

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for NonZeroScalar {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		use serde::de::{Error, Unexpected};

		Self::new(Scalar::deserialize(deserializer)?)
			.into_option()
			.ok_or_else(|| {
				Error::invalid_value(Unexpected::Other("zero scalar"), &"non-zero scalar")
			})
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

#[cfg(feature = "serde")]
impl Serialize for NonZeroScalar {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		self.0.serialize(serializer)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonIdentityElement(RistrettoPoint);

impl NonIdentityElement {
	#[must_use]
	pub fn new(point: RistrettoPoint) -> CtOption<Self> {
		CtOption::new(Self(point), !RistrettoPoint::is_identity(&point))
	}

	pub fn from_repr(repr: &Array<u8, U32>) -> CtOption<Self> {
		RistrettoPoint::from_bytes(&repr.0).and_then(Self::new)
	}
}

impl Deref for NonIdentityElement {
	type Target = RistrettoPoint;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl From<NonIdentityElement> for RistrettoPoint {
	fn from(value: NonIdentityElement) -> Self {
		value.0
	}
}

impl TryFrom<RistrettoPoint> for NonIdentityElement {
	type Error = ();

	fn try_from(value: RistrettoPoint) -> Result<Self, Self::Error> {
		Self::new(value).into_option().ok_or(())
	}
}

impl Zeroize for NonIdentityElement {
	fn zeroize(&mut self) {
		self.0 = RistrettoPoint::generator();
	}
}
