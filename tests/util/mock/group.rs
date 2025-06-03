//! [`MockCurve`] implementation.

use core::convert::Infallible;
use core::ops::{Add, Deref, Mul, Sub};

use elliptic_curve::hash2curve::ExpandMsg;
use elliptic_curve::subtle::{Choice, CtOption};
use hybrid_array::Array;
use hybrid_array::typenum::U0;
use oprf::group::{Dst, Group};
use zeroize::Zeroize;

/// A mock [`Group`] for testing purposes. It is zero-sized and does no checks
/// whatsoever.
pub struct MockCurve;

/// A mock [`Group::NonZeroScalar`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub struct NonZeroScalar;

/// A mock [`Group::Scalar`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub struct Scalar;

/// A mock [`Group::NonIdentityElement`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub struct NonIdentityElement;

/// A mock [`Group::Element`].
#[derive(Clone, Copy)]
pub struct Element;

impl Group for MockCurve {
	type K = U0;

	type NonZeroScalar = NonZeroScalar;
	type Scalar = Scalar;
	type ScalarLength = U0;

	type NonIdentityElement = NonIdentityElement;
	type Element = Element;
	type ElementLength = U0;

	fn scalar_random<R: rand::TryCryptoRng>(_: &mut R) -> Result<Self::NonZeroScalar, R::Error> {
		Ok(NonZeroScalar)
	}

	fn hash_to_scalar<E>(_: &[&[u8]], _: Dst) -> Self::Scalar
	where
		E: ExpandMsg<Self::K>,
	{
		Scalar
	}

	fn non_zero_scalar_mul_by_generator(_: &Self::NonZeroScalar) -> Self::NonIdentityElement {
		NonIdentityElement
	}

	fn scalar_mul_by_generator(_: &Self::Scalar) -> Self::Element {
		Element
	}

	fn scalar_invert(_: &Self::NonZeroScalar) -> Self::NonZeroScalar {
		NonZeroScalar
	}

	fn scalar_to_repr(_: &Self::Scalar) -> Array<u8, Self::ScalarLength> {
		Array::default()
	}

	fn non_zero_scalar_from_repr(_: &Array<u8, Self::ScalarLength>) -> Option<Self::NonZeroScalar> {
		Some(NonZeroScalar)
	}

	fn scalar_from_repr(_: &Array<u8, Self::ScalarLength>) -> Option<Self::Scalar> {
		Some(Scalar)
	}

	fn element_identity() -> Self::Element {
		Element
	}

	fn element_generator() -> Self::Element {
		Element
	}

	fn hash_to_curve<E>(_: &[&[u8]], _: Dst) -> Self::Element
	where
		E: ExpandMsg<Self::K>,
	{
		Element
	}

	#[cfg(feature = "alloc")]
	fn scalar_batch_invert(scalars: Vec<Self::Scalar>) -> CtOption<Vec<Self::Scalar>> {
		CtOption::new(scalars, Choice::from(1))
	}

	fn scalar_batch_invert_fixed<const N: usize>(
		scalars: [Self::Scalar; N],
	) -> CtOption<[Self::Scalar; N]> {
		CtOption::new(scalars, Choice::from(1))
	}

	fn element_to_repr(_: &Self::Element) -> Array<u8, Self::ElementLength> {
		Array::default()
	}

	#[cfg(feature = "alloc")]
	fn element_batch_to_repr(elements: &[Self::Element]) -> Vec<Array<u8, Self::ElementLength>> {
		vec![Array::default(); elements.len()]
	}

	fn element_batch_to_repr_fixed<const N: usize>(
		_: &[Self::Element; N],
	) -> [Array<u8, Self::ElementLength>; N] {
		[Array::default(); N]
	}

	fn non_identity_element_from_repr(
		_: &Array<u8, Self::ElementLength>,
	) -> Option<Self::NonIdentityElement> {
		Some(NonIdentityElement)
	}

	fn lincomb(_: [(Self::Element, Self::Scalar); 2]) -> Self::Element {
		Element
	}
}

impl Deref for NonZeroScalar {
	type Target = Scalar;

	fn deref(&self) -> &Self::Target {
		&Scalar
	}
}

impl Mul<&NonIdentityElement> for NonZeroScalar {
	type Output = NonIdentityElement;

	fn mul(self, _: &NonIdentityElement) -> Self::Output {
		NonIdentityElement
	}
}

impl TryFrom<Scalar> for NonZeroScalar {
	type Error = Infallible;

	fn try_from(_: Scalar) -> Result<Self, Self::Error> {
		Ok(Self)
	}
}

impl Add<&Self> for Scalar {
	type Output = Self;

	fn add(self, _: &Self) -> Self::Output {
		Self
	}
}

impl From<NonZeroScalar> for Scalar {
	fn from(_: NonZeroScalar) -> Self {
		Self
	}
}

impl Mul<&Element> for Scalar {
	type Output = Element;

	fn mul(self, _: &Element) -> Self::Output {
		Element
	}
}

impl Mul<&Self> for Scalar {
	type Output = Self;

	fn mul(self, _: &Self) -> Self::Output {
		Self
	}
}

impl Sub<&Self> for Scalar {
	type Output = Self;

	fn sub(self, _: &Self) -> Self::Output {
		Self
	}
}

impl Deref for NonIdentityElement {
	type Target = Element;

	fn deref(&self) -> &Self::Target {
		&Element
	}
}

impl TryFrom<Element> for NonIdentityElement {
	type Error = Infallible;

	fn try_from(_: Element) -> Result<Self, Self::Error> {
		Ok(Self)
	}
}

impl Add<&Self> for Element {
	type Output = Self;

	fn add(self, _: &Self) -> Self::Output {
		Self
	}
}

impl From<NonIdentityElement> for Element {
	fn from(_: NonIdentityElement) -> Self {
		Self
	}
}
