use core::ops::Add;

use digest::{FixedOutput, Update};
use elliptic_curve::group::cofactor::CofactorGroup;
use elliptic_curve::hash2curve::{ExpandMsg, FromOkm, GroupDigest};
use elliptic_curve::ops::{Invert, LinearCombination};
use elliptic_curve::point::NonIdentity;
use elliptic_curve::sec1::{CompressedPointSize, ModulusSize, Tag, ToEncodedPoint};
use elliptic_curve::{
	FieldBytesSize, Group as _, NonZeroScalar, PrimeField, ProjectivePoint, VoprfParameters,
};
use hybrid_array::{Array, ArraySize};
use rand_core::TryCryptoRng;
use typenum::{IsLess, True, U65536};

use super::{Dst, Group};
use crate::ciphersuite::{CipherSuite, Id};

impl<C> Group for C
where
	C: GroupDigest,
	C::Scalar: FromOkm,
	FieldBytesSize<C>: Add<FieldBytesSize<C>, Output: ArraySize> + ModulusSize,
	CompressedPointSize<C>: IsLess<U65536, Output = True>,
	ProjectivePoint<C>: CofactorGroup + ToEncodedPoint<C>,
{
	type NonZeroScalar = NonZeroScalar<C>;
	type Scalar = C::Scalar;
	type ScalarLength = FieldBytesSize<C>;

	type NonIdentityElement = NonIdentity<ProjectivePoint<C>>;
	type Element = ProjectivePoint<C>;
	type ElementLength = CompressedPointSize<C>;

	fn random_scalar<R: TryCryptoRng>(rng: &mut R) -> Result<Self::NonZeroScalar, R::Error> {
		NonZeroScalar::try_from_rng(rng)
	}

	fn hash_to_scalar<E: for<'dst> ExpandMsg<'dst>>(input: &[&[u8]], dst: Dst) -> Self::Scalar {
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

	fn serialize_scalar(scalar: &Self::Scalar) -> Array<u8, Self::ScalarLength> {
		scalar.to_repr()
	}

	fn identity_element() -> Self::Element {
		ProjectivePoint::<C>::identity()
	}

	fn generator_element() -> Self::Element {
		ProjectivePoint::<C>::generator()
	}

	fn hash_to_group<E: for<'dst> ExpandMsg<'dst>>(input: &[&[u8]], dst: Dst) -> Self::Element {
		C::hash_from_bytes::<E>(input, dst.as_ref()).expect("invalid cipher suite")
	}

	fn lincomb(points_and_scalars: [(Self::Element, Self::Scalar); 2]) -> Self::Element {
		ProjectivePoint::<C>::lincomb(&points_and_scalars)
	}

	fn serialize_element(element: &Self::Element) -> Array<u8, Self::ElementLength> {
		#[expect(clippy::indexing_slicing, reason = "otherwise invalid SEC1 encoding")]
		#[expect(clippy::as_conversions, reason = "no other way to convert enums")]
		if element.is_identity().into() {
			let mut output = Array::default();
			output[0] = Tag::Identity as u8;
			output
		} else {
			element
				.to_encoded_point(true)
				.as_bytes()
				.try_into()
				.expect("found invalid compressed SEC1 encoding")
		}
	}
}

impl<G: Group + VoprfParameters> CipherSuite for G
where
	G::Hash: Default + FixedOutput<OutputSize: IsLess<U65536, Output = True>> + Update,
{
	const ID: Id = Id::new(G::ID.as_bytes()).unwrap();

	type Group = G;
	type Hash = G::Hash;
	type ExpandMsg = G::ExpandMsg;
}
