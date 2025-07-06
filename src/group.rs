#[cfg(feature = "primeorder")]
mod primeorder;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt::Debug;
use core::ops::{Add, Deref, Mul, Sub};

use elliptic_curve::hash2curve::ExpandMsg;
use hybrid_array::typenum::{IsLess, True, U65536, Unsigned};
use hybrid_array::{Array, ArraySize};
use rand_core::TryCryptoRng;
use zeroize::Zeroize;

use crate::cipher_suite::{CipherSuite, ElementLength, NonIdentityElement, Scalar};
use crate::common::Mode;
use crate::error::{Error, Result};
use crate::internal;
use crate::util::Concat;

pub trait Group {
	type K: Unsigned;

	type NonZeroScalar: Copy
		+ Debug
		+ Deref<Target = Self::Scalar>
		+ Eq
		+ Into<Self::Scalar>
		+ for<'scalar> Mul<&'scalar Self::NonIdentityElement, Output = Self::NonIdentityElement>
		+ Zeroize;
	type Scalar: Copy
		+ Debug
		+ Eq
		+ for<'scalar> Add<&'scalar Self::Scalar, Output = Self::Scalar>
		+ for<'scalar> Sub<&'scalar Self::Scalar, Output = Self::Scalar>
		+ for<'scalar> Mul<&'scalar Self::Scalar, Output = Self::Scalar>
		+ for<'scalar> Mul<&'scalar Self::Element, Output = Self::Element>
		+ TryInto<Self::NonZeroScalar>
		+ Zeroize;
	type ScalarLength: Add<Self::ScalarLength, Output: ArraySize> + ArraySize;

	type NonIdentityElement: Copy
		+ Debug
		+ Deref<Target = Self::Element>
		+ Eq
		+ Into<Self::Element>
		+ Zeroize;
	type Element: Copy
		+ for<'element> Add<&'element Self::Element, Output = Self::Element>
		+ TryInto<Self::NonIdentityElement>;
	type ElementLength: ArraySize + IsLess<U65536, Output = True>;

	fn scalar_random<R: TryCryptoRng>(rng: &mut R) -> Result<Self::NonZeroScalar, R::Error>;

	fn hash_to_scalar<E>(input: &[&[u8]], dst: Dst) -> Option<Self::Scalar>
	where
		E: ExpandMsg<Self::K>;

	fn non_zero_scalar_mul_by_generator(scalar: &Self::NonZeroScalar) -> Self::NonIdentityElement;

	fn scalar_mul_by_generator(scalar: &Self::Scalar) -> Self::Element;

	fn scalar_invert(scalar: &Self::NonZeroScalar) -> Self::NonZeroScalar;

	fn scalar_batch_invert<const N: usize>(
		scalars: [Self::NonZeroScalar; N],
	) -> [Self::NonZeroScalar; N];

	#[cfg(feature = "alloc")]
	fn scalar_batch_vec_invert(scalars: Vec<Self::NonZeroScalar>) -> Vec<Self::NonZeroScalar>;

	fn scalar_to_repr(scalar: &Self::Scalar) -> Array<u8, Self::ScalarLength>;

	fn non_zero_scalar_from_repr(
		bytes: &Array<u8, Self::ScalarLength>,
	) -> Option<Self::NonZeroScalar>;

	fn scalar_from_repr(bytes: &Array<u8, Self::ScalarLength>) -> Option<Self::Scalar>;

	fn element_identity() -> Self::Element;

	fn element_generator() -> Self::Element;

	fn hash_to_curve<E>(input: &[&[u8]], dst: Dst) -> Option<Self::Element>
	where
		E: ExpandMsg<Self::K>;

	fn non_identity_element_batch_to_repr<const N: usize>(
		elements: &[Self::NonIdentityElement; N],
	) -> [Array<u8, Self::ElementLength>; N];

	#[cfg(feature = "alloc")]
	fn non_identity_element_batch_vec_to_repr(
		elements: &[Self::NonIdentityElement],
	) -> Vec<Array<u8, Self::ElementLength>>;

	fn element_batch_to_repr<const N: usize>(
		elements: &[Self::Element; N],
	) -> [Array<u8, Self::ElementLength>; N];

	fn non_identity_element_from_repr(
		bytes: &Array<u8, Self::ElementLength>,
	) -> Option<Self::NonIdentityElement>;

	fn lincomb(points_and_scalars: [(Self::Element, Self::Scalar); 2]) -> Self::Element;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Dst([&'static [u8]; 5]);

impl Dst {
	fn new<CS: CipherSuite>(mode: Mode, pre_concat: &'static [u8]) -> Self {
		let context_string = internal::create_context_string::<CS>(mode);
		debug_assert_ne!(
			context_string
				.iter()
				.map(|slice| slice.len())
				.sum::<usize>(),
			0,
			"found empty context string",
		);

		Self([pre_concat].concat(context_string))
	}
}

impl Deref for Dst {
	type Target = [&'static [u8]];

	fn deref(&self) -> &[&'static [u8]] {
		&self.0
	}
}

pub(crate) trait InternalGroup: CipherSuite {
	const I2OSP_ELEMENT_LEN: [u8; 2];

	fn hash_to_scalar(
		mode: Mode,
		input: &[&[u8]],
		dst_pre_concat: Option<&'static [u8]>,
	) -> Result<Scalar<Self>>;

	fn hash_to_curve(mode: Mode, input: &[&[u8]]) -> Result<NonIdentityElement<Self>>;
}

impl<CS: CipherSuite> InternalGroup for CS {
	const I2OSP_ELEMENT_LEN: [u8; 2] = ElementLength::<CS>::U16.to_be_bytes();

	fn hash_to_scalar(
		mode: Mode,
		input: &[&[u8]],
		dst_pre_concat: Option<&'static [u8]>,
	) -> Result<Scalar<Self>> {
		CS::Group::hash_to_scalar::<CS::ExpandMsg>(
			input,
			Dst::new::<CS>(mode, dst_pre_concat.unwrap_or(b"HashToScalar-")),
		)
		.ok_or(Error::InvalidCipherSuite)
	}

	fn hash_to_curve(mode: Mode, input: &[&[u8]]) -> Result<NonIdentityElement<Self>> {
		CS::Group::hash_to_curve::<CS::ExpandMsg>(input, Dst::new::<CS>(mode, b"HashToGroup-"))
			.ok_or(Error::InvalidCipherSuite)?
			.try_into()
			.map_err(|_| Error::InvalidInput)
	}
}
