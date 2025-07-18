#![expect(non_snake_case, reason = "following the specification exactly")]

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt::{self, Debug, Formatter};
use core::ops::Deref;

#[cfg(feature = "serde")]
use ::serde::de::Error as _;
#[cfg(feature = "serde")]
use ::serde::{Deserialize, Deserializer, Serialize, Serializer};
use digest::{FixedOutput, Output, OutputSizeUser, Update};
use hybrid_array::typenum::Unsigned;
use hybrid_array::{Array, ArrayN, ArraySize, AssocArraySize};
use rand_core::TryCryptoRng;
use zeroize::Zeroize;

use crate::cipher_suite::{
	CipherSuite, Element, ElementLength, NonIdentityElement, NonZeroScalar, Scalar,
};
use crate::common::{BlindedElement, Mode, Proof};
use crate::error::{Error, Result};
use crate::group::{Group, InternalGroup};
use crate::util::{CollectArray, Concat, I2osp, I2ospLength, UpdateIter};

pub(crate) struct BatchBlindResult<CS: CipherSuite, const N: usize> {
	pub(crate) blinds: [NonZeroScalar<CS>; N],
	pub(crate) blinded_elements: [BlindedElement<CS>; N],
}

#[cfg(feature = "alloc")]
pub(crate) struct BatchAllocBlindResult<CS: CipherSuite> {
	pub(crate) blinds: Vec<NonZeroScalar<CS>>,
	pub(crate) blinded_elements: Vec<BlindedElement<CS>>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Info<'info> {
	i2osp: [u8; 2],
	info: &'info [u8],
}

pub(crate) struct ElementWrapper<G: Group> {
	element: G::NonIdentityElement,
	repr: Array<u8, G::ElementLength>,
}

struct Composites<CS: CipherSuite> {
	M: Element<CS>,
	Z: Element<CS>,
}

impl<'info> Info<'info> {
	/// # Errors
	///
	/// Returns [`Error::InfoLength`] if `info` exceeds a length of
	/// [`u16::MAX`].
	pub(crate) fn new(info: &'info [u8]) -> Result<Self> {
		Ok(Self {
			i2osp: info.i2osp_length().ok_or(Error::InfoLength)?,
			info,
		})
	}

	pub(crate) const fn i2osp(&self) -> &[u8; 2] {
		&self.i2osp
	}

	pub(crate) const fn info(&self) -> &[u8] {
		self.info
	}
}

impl<G: Group> ElementWrapper<G> {
	pub(crate) fn new_batch<const N: usize>(
		elements: &[G::NonIdentityElement; N],
	) -> impl Iterator<Item = Self> {
		let repr = G::non_identity_element_batch_to_repr(elements);

		elements
			.iter()
			.copied()
			.zip(repr)
			.map(|(element, repr)| Self { element, repr })
	}

	#[cfg(feature = "alloc")]
	pub(crate) fn new_batch_alloc(
		elements: Vec<G::NonIdentityElement>,
	) -> impl Iterator<Item = Self> {
		let repr = G::non_identity_element_batch_alloc_to_repr(&elements);

		elements
			.into_iter()
			.zip(repr)
			.map(|(element, repr)| Self { element, repr })
	}

	pub(crate) fn into_element(self) -> G::NonIdentityElement {
		self.element
	}

	pub(crate) const fn as_element(&self) -> &G::NonIdentityElement {
		&self.element
	}

	pub(crate) const fn as_repr(&self) -> &Array<u8, G::ElementLength> {
		&self.repr
	}

	pub(crate) fn from_element(element: G::NonIdentityElement) -> Self {
		Self {
			element,
			repr: G::element_to_repr(&element),
		}
	}

	/// # Errors
	///
	/// Returns [`Error::FromRepr`] if deserialization fails.
	pub(crate) fn from_repr(bytes: &[u8]) -> Result<Self> {
		Self::from_array(bytes.try_into().map_err(|_| Error::FromRepr)?)
	}

	fn from_array(repr: Array<u8, G::ElementLength>) -> Result<Self> {
		let element = G::non_identity_element_from_repr(&repr).map_err(|_| Error::FromRepr)?;

		Ok(Self { element, repr })
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<G: Group> Clone for ElementWrapper<G> {
	fn clone(&self) -> Self {
		Self {
			element: self.element,
			repr: self.repr.clone(),
		}
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<G: Group> Debug for ElementWrapper<G> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("ElementWrapper")
			.field("element", &self.element)
			.field("repr", &self.repr)
			.finish()
	}
}

#[cfg(feature = "serde")]
impl<'de, G: Group> Deserialize<'de> for ElementWrapper<G> {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		let mut array = Array::default();
		serdect::array::deserialize_hex_or_bin(&mut array, deserializer)?;

		Self::from_array(array).map_err(D::Error::custom)
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<G: Group> Drop for ElementWrapper<G> {
	fn drop(&mut self) {
		self.element.zeroize();
		self.repr.zeroize();
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<G: Group> PartialEq for ElementWrapper<G> {
	fn eq(&self, other: &Self) -> bool {
		self.repr.eq(&other.repr)
	}
}

#[cfg(feature = "serde")]
impl<G: Group> Serialize for ElementWrapper<G> {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serdect::array::serialize_hex_upper_or_bin(&self.repr, serializer)
	}
}

/// Corresponds to
/// [`GenerateProof()` in RFC 9497 § 2.2.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2.1-3).
///
/// # Errors
///
/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
///   [`Group`](CipherSuite::Group) and [`ExpandMsg`](CipherSuite::ExpandMsg)
///   are incompatible.
/// - [`Error::Random`] if the given `rng` fails.
pub(crate) fn generate_proof<'items, CS, R>(
	mode: Mode,
	rng: &mut R,
	k: NonZeroScalar<CS>,
	B: &ElementWrapper<CS::Group>,
	C: impl ExactSizeIterator<Item = &'items ElementWrapper<CS::Group>>,
	D: impl ExactSizeIterator<Item = &'items ElementWrapper<CS::Group>>,
) -> Result<Proof<CS>, Error<R::Error>>
where
	CS: CipherSuite,
	R: ?Sized + TryCryptoRng,
{
	debug_assert_ne!(C.len(), 0, "found zero item length");
	debug_assert_eq!(C.len(), D.len(), "found unequal item length");
	debug_assert!(C.len() <= u16::MAX.into(), "found overflowing item length");

	let Composites::<CS> { M, Z } =
		compute_composites(mode, Some(k), B, C, D).map_err(Error::into_random::<R>)?;

	let r = CS::Group::scalar_random(rng).map_err(Error::Random)?;
	// `A` is always the generator element.
	let t2 = CS::Group::non_zero_scalar_mul_by_generator(&r);
	let t3 = r.into() * &M;

	let c = compute_c::<CS>(mode, B.element.into(), M, Z, t2.into(), t3)
		.map_err(Error::into_random::<R>)?;
	let s = r.into() - &(c * k.deref());

	Ok(Proof { c, s })
}

/// Corresponds to
/// [`VerifyProof()` in RFC 9497 § 2.2.2](https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2.2-2).
///
/// # Errors
///
/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
///   [`Group`](CipherSuite::Group) and [`ExpandMsg`](CipherSuite::ExpandMsg)
///   are incompatible.
/// - [`Error::Proof`] if the [`Proof`] is invalid.
pub(crate) fn verify_proof<'items, CS>(
	mode: Mode,
	B: &ElementWrapper<CS::Group>,
	C: impl ExactSizeIterator<Item = &'items ElementWrapper<CS::Group>>,
	D: impl ExactSizeIterator<Item = &'items ElementWrapper<CS::Group>>,
	proof: &Proof<CS>,
) -> Result<()>
where
	CS: CipherSuite,
{
	debug_assert_ne!(C.len(), 0, "found zero item length");
	debug_assert_eq!(C.len(), D.len(), "found unequal item length");
	debug_assert!(C.len() <= u16::MAX.into(), "found overflowing item length");

	let Composites::<CS> { M, Z } = compute_composites(mode, None, B, C, D)?;
	let Proof { c, s } = proof;

	let t2 = CS::Group::lincomb([(CS::Group::element_generator(), *s), (B.element.into(), *c)]);
	let t3 = CS::Group::lincomb([(M, *s), (Z, *c)]);

	let expected_c = compute_c::<CS>(mode, B.element.into(), M, Z, t2, t3)?;

	if &expected_c == c {
		Ok(())
	} else {
		Err(Error::Proof)
	}
}

/// Shared code between
/// [`GenerateProof()` in RFC 9497 § 2.2.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2.1-3)
/// and
/// [`VerifyProof()` in RFC 9497 § 2.2.2](https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2.2-2).
///
/// # Errors
///
/// Returns [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
/// [`Group`](CipherSuite::Group) and [`ExpandMsg`](CipherSuite::ExpandMsg)
/// are incompatible.
fn compute_c<CS: CipherSuite>(
	mode: Mode,
	B: Element<CS>,
	M: Element<CS>,
	Z: Element<CS>,
	t2: Element<CS>,
	t3: Element<CS>,
) -> Result<Scalar<CS>> {
	let [Bm, a0, a1, a2, a3] = CS::Group::element_batch_to_repr(&[B, M, Z, t2, t3]);

	CS::hash_to_scalar(
		mode,
		&[
			&CS::I2OSP_ELEMENT_LEN,
			&Bm,
			&CS::I2OSP_ELEMENT_LEN,
			&a0,
			&CS::I2OSP_ELEMENT_LEN,
			&a1,
			&CS::I2OSP_ELEMENT_LEN,
			&a2,
			&CS::I2OSP_ELEMENT_LEN,
			&a3,
			b"Challenge",
		],
		None,
	)
}

/// Corresponds to
/// [`ComputeComposites()` in RFC 9497 § 2.2.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2.1-5)
/// and
/// [`ComputeCompositesFast()` in RFC 9497 § 2.2.2](https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2.2-4).
///
/// # Errors
///
/// Returns [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
/// [`Group`](CipherSuite::Group) and [`ExpandMsg`](CipherSuite::ExpandMsg)
/// are incompatible.
fn compute_composites<'items, CS>(
	mode: Mode,
	k: Option<NonZeroScalar<CS>>,
	B: &ElementWrapper<CS::Group>,
	C: impl ExactSizeIterator<Item = &'items ElementWrapper<CS::Group>>,
	D: impl ExactSizeIterator<Item = &'items ElementWrapper<CS::Group>>,
) -> Result<Composites<CS>>
where
	CS: CipherSuite,
{
	debug_assert_ne!(C.len(), 0, "found zero item length");
	debug_assert_eq!(C.len(), D.len(), "found unequal item length");
	debug_assert!(C.len() <= u16::MAX.into(), "found overflowing item length");

	let Bm = &B.repr;
	let seed_dst = [b"Seed-".as_slice()].concat(create_context_string::<CS>(mode));
	let seed = CS::Hash::default()
		.chain(CS::I2OSP_ELEMENT_LEN)
		.chain(Bm)
		.chain(seed_dst.i2osp_length().expect("`CS::Id` too long"))
		.chain_iter(seed_dst.into_iter())
		.finalize_fixed();

	let mut M = CS::Group::element_identity();
	let mut Z = CS::Group::element_identity();

	for (i, (Ci, Di)) in (0..=u16::MAX).zip(C.zip(D)) {
		let di = CS::hash_to_scalar(
			mode,
			&[
				&<CS::Hash as OutputSizeUser>::OutputSize::U16.i2osp(),
				&seed,
				&i.i2osp(),
				&CS::I2OSP_ELEMENT_LEN,
				&Ci.repr,
				&CS::I2OSP_ELEMENT_LEN,
				&Di.repr,
				b"Composite",
			],
			None,
		)?;

		M = di * Ci.element.deref() + &M;

		if k.is_none() {
			Z = di * Di.element.deref() + &Z;
		}
	}

	if let Some(k) = k {
		Z = k.into() * &M;
	}

	Ok(Composites { M, Z })
}

/// Corresponds to
/// [`CreateContextString()` in RFC 9497 § 3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.1-5).
pub(crate) fn create_context_string<CS: CipherSuite>(mode: Mode) -> [&'static [u8]; 4] {
	[b"OPRFV1-", mode.i2osp(), b"-", &CS::ID]
}

/// Corresponds to
/// [`Blind()` in RFC 9497 § 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-2).
///
/// # Errors
///
/// - [`Error::InputLength`] if a given input exceeds a length of [`u16::MAX`].
/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
///   [`Group`](CipherSuite::Group) and [`ExpandMsg`](CipherSuite::ExpandMsg)
///   are incompatible.
/// - [`Error::InvalidInput`] if a given input can never produce a valid
///   [`BlindedElement`].
/// - [`Error::Random`] if the given `rng` fails.
pub(crate) fn batch_blind<CS, R, const N: usize>(
	mode: Mode,
	rng: &mut R,
	inputs: &[&[&[u8]]; N],
) -> Result<BatchBlindResult<CS, N>, Error<R::Error>>
where
	[NonIdentityElement<CS>; N]: AssocArraySize<
		Size: ArraySize<ArrayType<NonIdentityElement<CS>> = [NonIdentityElement<CS>; N]>,
	>,
	[NonZeroScalar<CS>; N]:
		AssocArraySize<Size: ArraySize<ArrayType<NonZeroScalar<CS>> = [NonZeroScalar<CS>; N]>>,
	CS: CipherSuite,
	R: ?Sized + TryCryptoRng,
{
	let input_elements = ArrayN::<_, N>::try_from_fn(|index| {
		#[expect(clippy::indexing_slicing, reason = "`N` matches")]
		let input = inputs[index];

		// Fail early.
		let _ = input.i2osp_length().ok_or(Error::InputLength)?;

		CS::hash_to_curve(mode, input).map_err(Error::into_random::<R>)
	})?
	.0;

	let blinds = ArrayN::<_, N>::try_from_fn(|_| {
		// Moved `blind` after to fail early.
		CS::Group::scalar_random(rng).map_err(Error::Random)
	})?
	.0;

	let blinded_elements = blinds
		.iter()
		.zip(input_elements)
		.map(|(blind, input_element)| *blind * &input_element)
		.collect_array();

	let blinded_elements = BlindedElement::new_batch(&blinded_elements);

	Ok(BatchBlindResult {
		blinds,
		blinded_elements,
	})
}

/// Corresponds to
/// [`Blind()` in RFC 9497 § 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-2).
///
/// # Errors
///
/// - [`Error::InputLength`] if a given input exceeds a length of [`u16::MAX`].
/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
///   [`Group`](CipherSuite::Group) and [`ExpandMsg`](CipherSuite::ExpandMsg)
///   are incompatible.
/// - [`Error::InvalidInput`] if a given input can never produce a valid
///   [`BlindedElement`].
/// - [`Error::Random`] if the given `rng` fails.
#[cfg(feature = "alloc")]
pub(crate) fn batch_alloc_blind<'inputs, CS, R>(
	mode: Mode,
	rng: &mut R,
	mut inputs: impl Iterator<Item = &'inputs [&'inputs [u8]]>,
) -> Result<BatchAllocBlindResult<CS>, Error<R::Error>>
where
	CS: CipherSuite,
	R: ?Sized + TryCryptoRng,
{
	let (blinds, blinded_elements) = inputs.try_fold(
		(Vec::new(), Vec::new()),
		|(mut blinds, mut blinded_elements), input| {
			// Fail early.
			let _ = input.i2osp_length().ok_or(Error::InputLength)?;

			let input_element = CS::hash_to_curve(mode, input).map_err(Error::into_random::<R>)?;

			// Moved `blind` after to fail early.
			let blind = CS::Group::scalar_random(rng).map_err(Error::Random)?;

			let blinded_element = blind * &input_element;

			blinds.push(blind);
			blinded_elements.push(blinded_element);

			Ok((blinds, blinded_elements))
		},
	)?;

	let blinded_elements = BlindedElement::new_batch_alloc(blinded_elements);

	Ok(BatchAllocBlindResult {
		blinds,
		blinded_elements,
	})
}

/// Corresponds to
/// [`Finalize()` in RFC 9497 § 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7).
///
/// # Errors
///
/// Returns [`Error::InputLength`] if a given input exceeds a length of
/// [`u16::MAX`].
#[expect(single_use_lifetimes, reason = "false-positive")]
pub(crate) fn batch_finalize<'evaluation_elements, CS, const N: usize>(
	inputs: &[&[&[u8]]; N],
	blinds: [NonZeroScalar<CS>; N],
	evaluation_elements: impl ExactSizeIterator<Item = &'evaluation_elements NonIdentityElement<CS>>,
	info: Option<Info<'_>>,
) -> Result<[Output<CS::Hash>; N]>
where
	[Output<CS::Hash>; N]:
		AssocArraySize<Size: ArraySize<ArrayType<Output<CS::Hash>> = [Output<CS::Hash>; N]>>,
	CS: CipherSuite,
{
	debug_assert_eq!(N, evaluation_elements.len(), "found unequal item length");

	let inverted_blinds = CS::Group::scalar_batch_invert(blinds);
	let n = inverted_blinds
		.into_iter()
		.zip(evaluation_elements)
		.map(|(inverted_blind, evaluation_element)| inverted_blind * evaluation_element)
		.collect_array::<N>();
	let unblinded_elements = CS::Group::non_identity_element_batch_to_repr(&n);

	let mut outputs = internal_finalize::<CS>(inputs.iter().copied(), &unblinded_elements, info);
	// Using `Iterator::collect()` can panic!
	let outputs = ArrayN::<_, N>::try_from_fn(|_| {
		outputs
			.next()
			.expect("should have the same number of items")
	})?;

	Ok(outputs.0)
}

/// Corresponds to
/// [`Finalize()` in RFC 9497 § 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7).
///
/// # Errors
///
/// Returns [`Error::InputLength`] if a given input exceeds a length of
/// [`u16::MAX`].
#[cfg(feature = "alloc")]
#[expect(single_use_lifetimes, reason = "false-positive")]
pub(crate) fn batch_alloc_finalize<'inputs, 'evaluation_elements, CS>(
	inputs: impl ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
	blinds: Vec<NonZeroScalar<CS>>,
	evaluation_elements: impl ExactSizeIterator<Item = &'evaluation_elements NonIdentityElement<CS>>,
	info: Option<Info<'_>>,
) -> Result<Vec<Output<CS::Hash>>>
where
	CS: CipherSuite,
{
	debug_assert_eq!(inputs.len(), blinds.len(), "found unequal item length");
	debug_assert_eq!(
		inputs.len(),
		evaluation_elements.len(),
		"found unequal item length"
	);

	let inverted_blinds = CS::Group::scalar_batch_alloc_invert(blinds);
	let n: Vec<_> = inverted_blinds
		.into_iter()
		.zip(evaluation_elements)
		.map(|(inverted_blind, evaluation_element)| inverted_blind * evaluation_element)
		.collect();
	let unblinded_elements = CS::Group::non_identity_element_batch_alloc_to_repr(&n);

	internal_finalize::<CS>(inputs, &unblinded_elements, info).collect()
}

/// Corresponds to
/// [`Finalize()` in RFC 9497 § 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7).
///
/// # Errors
///
/// Returns [`Error::InputLength`] if a given input exceeds a length of
/// [`u16::MAX`].
fn internal_finalize<'inputs, CS: CipherSuite>(
	inputs: impl ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
	unblinded_elements: &[Array<u8, ElementLength<CS>>],
	info: Option<Info<'_>>,
) -> impl Iterator<Item = Result<Output<CS::Hash>>> {
	debug_assert_eq!(
		inputs.len(),
		unblinded_elements.len(),
		"found unequal item length"
	);

	inputs
		.zip(unblinded_elements)
		.map(move |(input, unblinded_element)| {
			let mut hash = CS::Hash::default()
				.chain(input.i2osp_length().ok_or(Error::InputLength)?)
				.chain_iter(input.iter().copied());

			if let Some(info) = info {
				hash.update(&info.i2osp);
				hash.update(info.info);
			}

			Ok(hash
				.chain(CS::I2OSP_ELEMENT_LEN)
				.chain(unblinded_element)
				.chain(b"Finalize")
				.finalize_fixed())
		})
}

/// Corresponds to
/// [`Evaluate()` in RFC 9497 § 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-9).
///
/// # Errors
///
/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
///   [`Group`](CipherSuite::Group) and [`ExpandMsg`](CipherSuite::ExpandMsg)
///   are incompatible.
/// - [`Error::InvalidInput`] if a given input can never produce a valid output.
/// - [`Error::InputLength`] if a given input exceeds a length of [`u16::MAX`].
pub(crate) fn batch_evaluate<CS, const N: usize>(
	mode: Mode,
	secret_key: NonZeroScalar<CS>,
	inputs: &[&[&[u8]]; N],
	info: Option<Info<'_>>,
) -> Result<[Output<CS::Hash>; N]>
where
	[NonIdentityElement<CS>; N]: AssocArraySize<
		Size: ArraySize<ArrayType<NonIdentityElement<CS>> = [NonIdentityElement<CS>; N]>,
	>,
	[Output<CS::Hash>; N]:
		AssocArraySize<Size: ArraySize<ArrayType<Output<CS::Hash>> = [Output<CS::Hash>; N]>>,
	CS: CipherSuite,
{
	let evaluation_elements = ArrayN::try_from_fn(|index| {
		#[expect(clippy::indexing_slicing, reason = "`N` matches")]
		let input = inputs[index];

		let input_element = CS::hash_to_curve(mode, input)?;
		Ok(secret_key * &input_element)
	})?
	.0;
	let issued_elements = CS::Group::non_identity_element_batch_to_repr(&evaluation_elements);

	let mut outputs = internal_evaluate::<CS>(inputs, &issued_elements, info);

	// Using `Iterator::collect()` can panic!
	let outputs = ArrayN::<_, N>::try_from_fn(|_| {
		outputs
			.next()
			.expect("should have the same number of items")
	})?;

	Ok(outputs.0)
}

/// Corresponds to
/// [`Evaluate()` in RFC 9497 § 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-9).
///
/// # Errors
///
/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
///   [`Group`](CipherSuite::Group) and [`ExpandMsg`](CipherSuite::ExpandMsg)
///   are incompatible.
/// - [`Error::InvalidInput`] if a given input can never produce a valid output.
/// - [`Error::InputLength`] if a given input exceeds a length of [`u16::MAX`].
#[cfg(feature = "alloc")]
pub(crate) fn batch_alloc_evaluate<CS: CipherSuite>(
	mode: Mode,
	secret_key: NonZeroScalar<CS>,
	inputs: &[&[&[u8]]],
	info: Option<Info<'_>>,
) -> Result<Vec<Output<CS::Hash>>> {
	let evaluation_elements = inputs
		.iter()
		.map(|input| {
			let input_element = CS::hash_to_curve(mode, input)?;
			Ok(secret_key * &input_element)
		})
		.collect::<Result<Vec<_>>>()?;
	let issued_elements = CS::Group::non_identity_element_batch_alloc_to_repr(&evaluation_elements);

	internal_evaluate::<CS>(inputs, &issued_elements, info).collect()
}

/// Corresponds to
/// [`Evaluate()` in RFC 9497 § 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-9).
///
/// # Errors
///
/// Returns [`Error::InputLength`] if a given input exceeds a length of
/// [`u16::MAX`].
fn internal_evaluate<CS: CipherSuite>(
	inputs: &[&[&[u8]]],
	issued_elements: &[Array<u8, ElementLength<CS>>],
	info: Option<Info<'_>>,
) -> impl Iterator<Item = Result<Output<CS::Hash>>> {
	inputs
		.iter()
		.zip(issued_elements)
		.map(move |(input, issued_element)| {
			let mut hash = CS::Hash::default()
				.chain(input.i2osp_length().ok_or(Error::InputLength)?)
				.chain_iter(input.iter().copied());

			if let Some(info) = info {
				hash.update(&info.i2osp);
				hash.update(info.info);
			}

			Ok(hash
				.chain(CS::I2OSP_ELEMENT_LEN)
				.chain(issued_element)
				.chain(b"Finalize")
				.finalize_fixed())
		})
}
