//! The [`Group`] trait.

#[cfg(feature = "decaf448")]
pub mod decaf448;
#[cfg(feature = "primeorder")]
mod primeorder;
#[cfg(feature = "ristretto255")]
pub mod ristretto255;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt::Debug;
use core::ops::{Add, Deref, Mul, Sub};

use hash2curve::ExpandMsg;
use hybrid_array::typenum::{IsLess, True, U65536, Unsigned};
use hybrid_array::{Array, ArraySize};
use rand_core::TryCryptoRng;
use zeroize::Zeroize;

use crate::cipher_suite::{CipherSuite, ElementLength, NonIdentityElement, Scalar};
use crate::common::Mode;
use crate::error::{Error, InternalError, Result};
use crate::internal;
use crate::util::{CollectArray, Concat};

/// Prime-order group implementation for OPRF.
///
/// See [RFC 9497 § 4](https://www.rfc-editor.org/rfc/rfc9497.html#section-4-3.2).
pub trait Group {
	/// Target security level of this [`Group`].
	///
	/// See [RFC 9380 § 10.8](https://www.rfc-editor.org/rfc/rfc9380.html#name-target-security-levels).
	type SecurityLevel: Unsigned;

	/// Non-zero scalar type. This type must ensure that its value is not zero.
	type NonZeroScalar: Copy
		+ Debug
		+ Deref<Target = Self::Scalar>
		+ Eq
		+ Into<Self::Scalar>
		+ for<'scalar> Mul<&'scalar Self::NonIdentityElement, Output = Self::NonIdentityElement>
		+ Zeroize;

	/// Scalar type.
	type Scalar: Copy
		+ Debug
		+ Default
		+ Eq
		+ for<'scalar> Add<&'scalar Self::Scalar, Output = Self::Scalar>
		+ for<'scalar> Sub<&'scalar Self::Scalar, Output = Self::Scalar>
		+ for<'scalar> Mul<&'scalar Self::Scalar, Output = Self::Scalar>
		+ for<'scalar> Mul<&'scalar Self::Element, Output = Self::Element>
		+ TryInto<Self::NonZeroScalar>
		+ Zeroize;

	/// Length of a serialized [`Scalar`](Group::Scalar).
	type ScalarLength: Add<Self::ScalarLength, Output: ArraySize> + ArraySize;

	/// Non-identity element type. This type must ensure that its value is not
	/// the identity element.
	type NonIdentityElement: Copy
		+ Debug
		+ Deref<Target = Self::Element>
		+ Eq
		+ Into<Self::Element>
		+ Zeroize;

	/// Element type.
	type Element: Copy
		+ Default
		+ for<'element> Add<&'element Self::Element, Output = Self::Element>
		+ TryInto<Self::NonIdentityElement>;

	/// Length of a serialized [`Element`](Group::Element).
	type ElementLength: ArraySize + IsLess<U65536, Output = True>;

	/// Generates a random scalar with the given `rng`. Implementation
	/// guidelines can be found in [RFC 9497 § 4.7](https://www.rfc-editor.org/rfc/rfc9497.html#random-scalar).
	///
	/// Corresponds to [`RandomScalar()` in RFC 9497 § 2.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-2.1-4.12).
	///
	/// # Errors
	///
	/// Returns [`TryRngCore::Error`](rand_core::TryRngCore::Error) if the given
	/// `rng` fails.
	fn scalar_random<R>(rng: &mut R) -> Result<Self::NonZeroScalar, R::Error>
	where
		R: ?Sized + TryCryptoRng;

	/// Deterministically maps input to a [`Scalar`](Group::Scalar).
	///
	/// Corresponds to [`HashToScalar()` in RFC 9497 § 2.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-2.1-4.10) and
	/// [RFC 9380 § 5](https://www.rfc-editor.org/rfc/rfc9380#name-hashing-to-a-finite-field).
	///
	/// # Errors
	///
	/// Returns [`InternalError`] if the [`Group`] and [`ExpandMsg`] are
	/// incompatible.
	fn hash_to_scalar<E>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Scalar, InternalError>
	where
		E: ExpandMsg<Self::SecurityLevel>;

	/// Multiply the given [`NonZeroScalar`](Group::NonZeroScalar) with the
	/// generator element of this prime-order subgroup.
	///
	/// This is expected to be cheaper to compute than via regular
	/// multiplication, e.g. via precomputed tables.
	#[must_use]
	fn non_zero_scalar_mul_by_generator(scalar: &Self::NonZeroScalar) -> Self::NonIdentityElement;

	/// Multiply the given [`Scalar`](Group::Scalar) with the generator element
	/// of this prime-order subgroup.
	///
	/// This is expected to be cheaper to compute than via regular
	/// multiplication, e.g. via precomputed tables.
	#[must_use]
	fn scalar_mul_by_generator(scalar: &Self::Scalar) -> Self::Element;

	/// Computes the inverse of the given
	/// [`NonZeroScalar`](Group::NonZeroScalar).
	///
	/// Corresponds to [`ScalarInverse()` in RFC 9497 § 2.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-2.1-4.14).
	#[must_use]
	fn scalar_invert(scalar: &Self::NonZeroScalar) -> Self::NonZeroScalar;

	/// Potentially halves the scalar if
	/// [`Self::non_identity_element_batch_maybe_double_to_repr()`] serializes
	/// double the point.
	#[must_use]
	fn non_zero_scalar_maybe_halve(scalar: &Self::NonZeroScalar) -> Self::NonZeroScalar {
		*scalar
	}

	/// Potentially halves the scalar if
	/// [`Self::element_batch_maybe_double_to_repr()`] serializes double the
	/// point.
	#[must_use]
	fn scalar_maybe_halve(scalar: &Self::Scalar) -> Self::Scalar {
		*scalar
	}

	/// Batch computes the inverse of the given
	/// [`NonZeroScalar`](Group::NonZeroScalar)s *without allocation*.
	///
	/// This is expected to reduce the problem of computing `N` inverses to
	/// computing a single inversion.
	#[must_use]
	fn scalar_batch_invert<const N: usize>(
		scalars: [Self::NonZeroScalar; N],
	) -> [Self::NonZeroScalar; N] {
		scalars.map(|scalar| Self::scalar_invert(&scalar))
	}

	/// Batch computes the inverse of the given
	/// [`NonZeroScalar`](Group::NonZeroScalar)s.
	///
	/// This is expected to reduce the problem of computing `N` inverses to
	/// computing a single inversion.
	#[must_use]
	#[cfg(feature = "alloc")]
	fn scalar_batch_alloc_invert(scalars: Vec<Self::NonZeroScalar>) -> Vec<Self::NonZeroScalar> {
		scalars
			.into_iter()
			.map(|scalar| Self::scalar_invert(&scalar))
			.collect()
	}

	/// Serializes the given [`Scalar`](Group::Scalar).
	///
	/// Corresponds to [`SerializeScalar()` in RFC 9497 § 2.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-2.1-4.20).
	#[must_use]
	fn scalar_to_repr(scalar: &Self::Scalar) -> Array<u8, Self::ScalarLength>;

	/// Deserializes the given `bytes` to a
	/// [`NonZeroScalar`](Group::NonZeroScalar).
	///
	/// Corresponds to [`DeserializeScalar()` in RFC 9497 § 2.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-2.1-4.22).
	///
	/// # Errors
	///
	/// Returns [`InternalError`] if deserialization fails.
	fn non_zero_scalar_from_repr(
		bytes: Array<u8, Self::ScalarLength>,
	) -> Result<Self::NonZeroScalar, InternalError>;

	/// Deserializes the given `bytes` to a [`Scalar`](Group::Scalar).
	///
	/// Corresponds to [`DeserializeScalar()` in RFC 9497 § 2.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-2.1-4.22).
	///
	/// # Errors
	///
	/// Returns [`InternalError`] if deserialization fails.
	fn scalar_from_repr(
		bytes: &Array<u8, Self::ScalarLength>,
	) -> Result<Self::Scalar, InternalError>;

	/// Returns the identity element.
	///
	/// Corresponds to [`Identity()` in RFC 9497 § 2.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-2.1-4.4).
	fn element_identity() -> Self::Element;

	/// Returns the generator element of this prime-order subgroup.
	///
	/// Corresponds to [`Generator()` in RFC 9497 § 2.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-2.1-4.6).
	fn element_generator() -> Self::Element;

	/// Deterministically maps input to a [`Element`](Group::Element).
	///
	/// Corresponds to
	/// [`HashToGroup()` in RFC 9497 § 2.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-2.1-4.8)
	/// and
	/// [`hash_to_curve()` in RFC 9380 § 3](https://www.rfc-editor.org/rfc/rfc9380.html#section-3-4.2.1).
	///
	/// # Errors
	///
	/// Returns [`InternalError`] if the [`Group`] and [`ExpandMsg`] are
	/// incompatible.
	fn hash_to_curve<E>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Element, InternalError>
	where
		E: ExpandMsg<Self::SecurityLevel>;

	/// Potentially doubles the element if
	/// [`Self::non_identity_element_batch_maybe_double_to_repr()`] serializes
	/// double the point.
	#[must_use]
	fn non_identity_element_maybe_double(
		element: &Self::NonIdentityElement,
	) -> Self::NonIdentityElement {
		*element
	}

	/// Serializes the given [`Element`](Group::Element).
	///
	/// Corresponds to
	/// [`SerializeElement()` in RFC 9497 § 2.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-2.1-4.16).
	fn element_to_repr(element: &Self::Element) -> Array<u8, Self::ElementLength>;

	/// Batch serialization of the given
	/// [`NonIdentityElement`](Group::NonIdentityElement)s, potentially doubling
	/// them, *without allocation*.
	///
	/// This is expected to be practically as efficient as a single
	/// serialization.
	fn non_identity_element_batch_maybe_double_to_repr<const N: usize>(
		elements: &[Self::NonIdentityElement; N],
	) -> [Array<u8, Self::ElementLength>; N] {
		elements
			.iter()
			.map(|element| Self::element_to_repr(element))
			.collect_array()
	}

	/// Batch serialization of the given
	/// [`NonIdentityElement`](Group::NonIdentityElement)s, potentially doubling
	/// them.
	///
	/// This is expected to be practically as efficient as a single
	/// serialization.
	#[cfg(feature = "alloc")]
	fn non_identity_element_batch_alloc_maybe_double_to_repr(
		elements: &[Self::NonIdentityElement],
	) -> Vec<Array<u8, Self::ElementLength>> {
		elements
			.iter()
			.map(|element| Self::element_to_repr(element))
			.collect()
	}

	/// Batch serialization of the given [`Element`](Group::Element)s,
	/// potentially doubling them, *without allocation*.
	///
	/// This is expected to be practically as efficient as a single
	/// serialization.
	fn element_batch_maybe_double_to_repr<const N: usize>(
		elements: &[Self::Element; N],
	) -> [Array<u8, Self::ElementLength>; N] {
		elements.iter().map(Self::element_to_repr).collect_array()
	}

	/// Deserializes the given `bytes` to a
	/// [`NonIdentityElement`](Group::NonIdentityElement).
	///
	/// Corresponds to
	/// [`DeserializeElement()` in RFC 9497 § 2.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-2.1-4.18).
	///
	/// # Errors
	///
	/// Returns [`InternalError`] if deserialization fails.
	fn non_identity_element_from_repr(
		bytes: &Array<u8, Self::ElementLength>,
	) -> Result<Self::NonIdentityElement, InternalError>;

	/// Computes `element1 * scalar1 + element2 * scalar2` *without allocation*.
	///
	/// This is expected to be an optimized implementations of linear
	/// combinations.
	fn lincomb<const N: usize>(
		elements_and_scalars: &[(Self::Element, Self::Scalar); N],
	) -> Self::Element {
		elements_and_scalars
			.iter()
			.map(|(element, scalar)| *scalar * element)
			.reduce(|acc, element| acc + &element)
			.unwrap_or_else(Self::Element::default)
	}

	/// Computes `element1 * scalar1 + element2 * scalar2`.
	///
	/// This is expected to be an optimized implementations of linear
	/// combinations.
	#[cfg(feature = "alloc")]
	fn alloc_lincomb(elements_and_scalars: &[(Self::Element, Self::Scalar)]) -> Self::Element {
		elements_and_scalars
			.iter()
			.map(|(element, scalar)| *scalar * element)
			.reduce(|acc, element| acc + &element)
			.unwrap_or_else(Self::Element::default)
	}
}

pub(crate) trait InternalGroup: CipherSuite {
	const I2OSP_ELEMENT_LEN: [u8; 2];

	/// # Errors
	///
	/// Returns [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	/// [`Group`](CipherSuite::Group) and [`ExpandMsg`](CipherSuite::ExpandMsg)
	/// are incompatible.
	fn hash_to_scalar(
		mode: Mode,
		input: &[&[u8]],
		dst_pre_concat: Option<&'static [u8]>,
	) -> Result<Scalar<Self>>;

	/// # Errors
	///
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInput`] if the given `input` can never produce a valid
	///   output.
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
			&dst::<CS>(mode, dst_pre_concat.unwrap_or(b"HashToScalar-")),
		)
		.map_err(|_| Error::InvalidCipherSuite)
	}

	fn hash_to_curve(mode: Mode, input: &[&[u8]]) -> Result<NonIdentityElement<Self>> {
		CS::Group::hash_to_curve::<CS::ExpandMsg>(input, &dst::<CS>(mode, b"HashToGroup-"))
			.map_err(|_| Error::InvalidCipherSuite)?
			.try_into()
			.map_err(|_| Error::InvalidInput)
	}
}

fn dst<CS: CipherSuite>(mode: Mode, pre_concat: &'static [u8]) -> [&'static [u8]; 5] {
	[pre_concat].concat(internal::create_context_string::<CS>(mode))
}
