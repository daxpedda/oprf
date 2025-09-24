//! [`CipherSuite`](crate::cipher_suite::CipherSuite) and [`Group`]
//! implementation for curves implementing the traits of [`elliptic_curve`].

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use elliptic_curve::group::GroupEncoding;
use elliptic_curve::group::ff::PrimeField;
use elliptic_curve::ops::{BatchInvert, Invert, LinearCombination};
use elliptic_curve::point::NonIdentity;
use elliptic_curve::{
	BatchNormalize, FieldBytesSize, Group as _, NonZeroScalar, ProjectivePoint, Scalar,
};
use hash2curve::{ExpandMsg, MapToCurve};
use hybrid_array::{Array, AssocArraySize, typenum};
use rand_core::TryCryptoRng;

use crate::error::InternalError;
use crate::group::Group;

/// Implements [`Group`] for a curve.
macro_rules! group {
	(
		cipher_suite_feature = $cipher_suite_feature:literal,
		crate = $crate_:ident,
		type = $curve:ident,
		ID = $id:literal,
		Hash = $hash:ty,
		hash_to_scalar = $hash_to_scalar:ty,
	) => {
		const _: () = {
			#[cfg(feature = $cipher_suite_feature)]
			use hash2curve::GroupDigest;
			use $crate_::$curve;

			#[cfg(feature = $cipher_suite_feature)]
			use crate::cipher_suite::{CipherSuite, Id};

			#[cfg(feature = $cipher_suite_feature)]
			impl CipherSuite for $curve {
				const ID: Id = Id::new($id).unwrap();

				type Group = Self;
				type Hash = $hash;
				type ExpandMsg = <Self as GroupDigest>::ExpandMsg;
			}

			impl Group for $curve {
				type SecurityLevel = <Self as MapToCurve>::SecurityLevel;

				type NonZeroScalar = NonZeroScalar<Self>;
				type Scalar = Scalar<Self>;
				type ScalarLength = FieldBytesSize<Self>;

				type NonIdentityElement = NonIdentity<ProjectivePoint<Self>>;
				type Element = ProjectivePoint<Self>;
				type ElementLength =
					<<ProjectivePoint<Self> as GroupEncoding>::Repr as AssocArraySize>::Size;

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
					hash2curve::hash_to_scalar::<Self, E, $hash_to_scalar>(input, dst)
						.map_err(|_| InternalError)
				}

				fn non_zero_scalar_mul_by_generator(
					scalar: &Self::NonZeroScalar,
				) -> Self::NonIdentityElement {
					NonIdentity::mul_by_generator(scalar)
				}

				fn scalar_mul_by_generator(scalar: &Self::Scalar) -> Self::Element {
					ProjectivePoint::<Self>::mul_by_generator(scalar)
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
					Scalar::<Self>::from_repr(*repr)
						.into_option()
						.ok_or(InternalError)
				}

				fn element_identity() -> Self::Element {
					ProjectivePoint::<Self>::IDENTITY
				}

				fn element_generator() -> Self::Element {
					ProjectivePoint::<Self>::GENERATOR
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
					NonIdentity::<ProjectivePoint<Self>>::batch_normalize(elements)
						.map(|point| point.to_bytes())
				}

				#[cfg(feature = "alloc")]
				fn non_identity_element_batch_alloc_maybe_double_to_repr(
					elements: &[Self::NonIdentityElement],
				) -> Vec<Array<u8, Self::ElementLength>> {
					NonIdentity::<ProjectivePoint<Self>>::batch_normalize(elements)
						.into_iter()
						.map(|point| point.to_bytes())
						.collect()
				}

				fn element_batch_maybe_double_to_repr<const N: usize>(
					elements: &[Self::Element; N],
				) -> [Array<u8, Self::ElementLength>; N] {
					ProjectivePoint::<Self>::batch_normalize(elements).map(|point| point.to_bytes())
				}

				fn non_identity_element_from_repr(
					repr: &Array<u8, Self::ElementLength>,
				) -> Result<Self::NonIdentityElement, InternalError> {
					NonIdentity::<ProjectivePoint<Self>>::from_repr(repr)
						.into_option()
						.ok_or(InternalError)
				}

				fn lincomb<const N: usize>(
					elements_and_scalars: &[(Self::Element, Self::Scalar); N],
				) -> Self::Element {
					ProjectivePoint::<Self>::lincomb(elements_and_scalars)
				}

				#[cfg(feature = "alloc")]
				fn alloc_lincomb(
					elements_and_scalars: &[(Self::Element, Self::Scalar)],
				) -> Self::Element {
					ProjectivePoint::<Self>::lincomb(elements_and_scalars)
				}
			}
		};
	};
}

#[cfg(feature = "p256")]
group!(
	cipher_suite_feature = "p256-ciphersuite",
	crate = p256,
	type = NistP256,
	ID = b"P256-SHA256",
	Hash = sha2::Sha256,
	hash_to_scalar = typenum::U48,
);

#[cfg(feature = "p384")]
group!(
	cipher_suite_feature = "p384-ciphersuite",
	crate = p384,
	type = NistP384,
	ID = b"P384-SHA384",
	Hash = sha2::Sha384,
	hash_to_scalar = typenum::U72,
);

#[cfg(feature = "p521")]
group!(
	cipher_suite_feature = "p521-ciphersuite",
	crate = p521,
	type = NistP521,
	ID = b"P521-SHA512",
	Hash = sha2::Sha512,
	hash_to_scalar = typenum::U98,
);
