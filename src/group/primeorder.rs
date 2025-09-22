//! NIST curves implementation.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use hash2curve::{ExpandMsg, MapToCurve};
#[cfg(any(
	feature = "p256-ciphersuite",
	feature = "p384-ciphersuite",
	feature = "p521-ciphersuite"
))]
use hash2curve::{GroupDigest, OprfParameters};
use hybrid_array::Array;
use rand_core::TryCryptoRng;

#[cfg(any(
	feature = "p256-ciphersuite",
	feature = "p384-ciphersuite",
	feature = "p521-ciphersuite"
))]
use crate::cipher_suite::{CipherSuite, Id};
use crate::error::InternalError;
use crate::group::Group;

/// Implements [`CipherSuite`] for a curve.
#[cfg(any(
	feature = "p256-ciphersuite",
	feature = "p384-ciphersuite",
	feature = "p521-ciphersuite"
))]
macro_rules! cipher_suite {
	($crate_:ident, $curve:ident) => {
		impl CipherSuite for $crate_::$curve {
			const ID: Id = Id::new(<Self as OprfParameters>::ID).unwrap();

			type Group = Self;
			type Hash = <<Self as GroupDigest>::ExpandMsg as ExpandMsg<
				<Self as MapToCurve>::SecurityLevel,
			>>::Hash;
			type ExpandMsg = <Self as GroupDigest>::ExpandMsg;
		}
	};
}

/// Implements [`Group`] for a curve.
macro_rules! group {
	($crate_:ident, $curve:ident) => {
		const _: () = {
			use $crate_::elliptic_curve::group::GroupEncoding;
			use $crate_::elliptic_curve::group::ff::PrimeField;
			use $crate_::elliptic_curve::ops::{BatchInvert, Invert, LinearCombination};
			use $crate_::elliptic_curve::point::NonIdentity;
			use $crate_::elliptic_curve::sec1::CompressedPointSize;
			use $crate_::elliptic_curve::{BatchNormalize, FieldBytesSize, Group as _};
			use $crate_::{NonZeroScalar, ProjectivePoint, Scalar, $curve};

			impl Group for $curve {
				type SecurityLevel = <Self as MapToCurve>::SecurityLevel;

				type NonZeroScalar = NonZeroScalar;
				type Scalar = Scalar;
				type ScalarLength = FieldBytesSize<Self>;

				type NonIdentityElement = NonIdentity<ProjectivePoint>;
				type Element = ProjectivePoint;
				type ElementLength = CompressedPointSize<Self>;

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

				fn hash_to_scalar<E>(
					input: &[&[u8]],
					dst: &[&[u8]],
				) -> Result<Self::Scalar, InternalError>
				where
					E: ExpandMsg<Self::SecurityLevel>,
				{
					hash2curve::hash_to_scalar::<Self, E, <Self as MapToCurve>::Length>(input, dst)
						.map_err(|_| InternalError)
				}

				fn non_zero_scalar_mul_by_generator(
					scalar: &Self::NonZeroScalar,
				) -> Self::NonIdentityElement {
					NonIdentity::mul_by_generator(scalar)
				}

				fn scalar_mul_by_generator(scalar: &Self::Scalar) -> Self::Element {
					ProjectivePoint::mul_by_generator(scalar)
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
				fn scalar_batch_alloc_invert(
					scalars: Vec<Self::NonZeroScalar>,
				) -> Vec<Self::NonZeroScalar> {
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
					Scalar::from_repr(*repr).into_option().ok_or(InternalError)
				}

				fn element_identity() -> Self::Element {
					ProjectivePoint::identity()
				}

				fn element_generator() -> Self::Element {
					ProjectivePoint::generator()
				}

				fn hash_to_curve<E>(
					input: &[&[u8]],
					dst: &[&[u8]],
				) -> Result<Self::Element, InternalError>
				where
					E: ExpandMsg<Self::SecurityLevel>,
				{
					hash2curve::hash_from_bytes::<Self, E>(input, dst).map_err(|_| InternalError)
				}

				fn element_to_repr(element: &Self::Element) -> Array<u8, Self::ElementLength> {
					element.to_bytes()
				}

				fn non_identity_element_batch_maybe_double_to_repr<const N: usize>(
					elements: &[Self::NonIdentityElement; N],
				) -> [Array<u8, Self::ElementLength>; N] {
					NonIdentity::<ProjectivePoint>::batch_normalize(elements)
						.map(|point| point.to_bytes())
				}

				#[cfg(feature = "alloc")]
				fn non_identity_element_batch_alloc_maybe_double_to_repr(
					elements: &[Self::NonIdentityElement],
				) -> Vec<Array<u8, Self::ElementLength>> {
					NonIdentity::<ProjectivePoint>::batch_normalize(elements)
						.into_iter()
						.map(|point| point.to_bytes())
						.collect()
				}

				fn element_batch_maybe_double_to_repr<const N: usize>(
					elements: &[Self::Element; N],
				) -> [Array<u8, Self::ElementLength>; N] {
					ProjectivePoint::batch_normalize(elements).map(|point| point.to_bytes())
				}

				fn non_identity_element_from_repr(
					repr: &Array<u8, Self::ElementLength>,
				) -> Result<Self::NonIdentityElement, InternalError> {
					NonIdentity::<ProjectivePoint>::from_repr(repr)
						.into_option()
						.ok_or(InternalError)
				}

				fn lincomb<const N: usize>(
					elements_and_scalars: &[(Self::Element, Self::Scalar); N],
				) -> Self::Element {
					ProjectivePoint::lincomb(elements_and_scalars)
				}

				#[cfg(feature = "alloc")]
				fn alloc_lincomb(
					elements_and_scalars: &[(Self::Element, Self::Scalar)],
				) -> Self::Element {
					ProjectivePoint::lincomb(elements_and_scalars)
				}
			}
		};
	};
}

#[cfg(feature = "p256-ciphersuite")]
cipher_suite!(p256, NistP256);

#[cfg(feature = "p256")]
group!(p256, NistP256);

#[cfg(feature = "p384-ciphersuite")]
cipher_suite!(p384, NistP384);

#[cfg(feature = "p384")]
group!(p384, NistP384);

#[cfg(feature = "p521-ciphersuite")]
cipher_suite!(p521, NistP521);

#[cfg(feature = "p521")]
group!(p521, NistP521);
