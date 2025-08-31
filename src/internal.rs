//! "Raw" implementation of the specification.

#![expect(non_snake_case, reason = "following the specification exactly")]

#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt::{self, Debug, Formatter};
use core::iter;
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

/// Returned by [`batch_blind()`].
pub(crate) struct BlindResult<CS: CipherSuite, const N: usize> {
	/// `blind`s.
	pub(crate) blinds: [NonZeroScalar<CS>; N],
	/// `blindedElement`s.
	pub(crate) blinded_elements: [BlindedElement<CS>; N],
}

/// Returned by [`batch_alloc_blind()`].
#[cfg(feature = "alloc")]
pub(crate) struct AllocBlindResult<CS: CipherSuite> {
	/// `blind`s.
	pub(crate) blinds: Vec<NonZeroScalar<CS>>,
	/// `blindedElement`s.
	pub(crate) blinded_elements: Vec<BlindedElement<CS>>,
}

/// Corresponds to
/// [`PrivateInput` in RFC 9497 § 1.2](https://www.rfc-editor.org/rfc/rfc9497.html#section-1.2-4).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Info<'info> {
	/// I2OSP of this `info`s length.
	i2osp: [u8; 2],
	/// The `info`.
	info: &'info [u8],
}

/// Holds a [`NonIdentityElement`] and its representation.
pub(crate) struct ElementWrapper<G: Group> {
	/// The [`NonIdentityElement`].
	element: G::NonIdentityElement,
	/// Its representation.
	repr: Array<u8, G::ElementLength>,
}

/// Returned by [`compute_composites()`].
pub(crate) struct Composites<CS: CipherSuite> {
	/// `M`. Might be half the expected value to facilitate batch serialization.
	M: Element<CS>,
	/// `Z`. Might be half the expected value to facilitate batch serialization.
	Z: Element<CS>,
}

impl<'info> Info<'info> {
	/// Creates a new [`Info`].
	///
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

	/// Returns the I2OSP of the `info`s length.
	pub(crate) const fn i2osp(&self) -> &[u8; 2] {
		&self.i2osp
	}

	/// Returns the `info`.
	pub(crate) const fn info(&self) -> &[u8] {
		self.info
	}
}

impl<G: Group> ElementWrapper<G> {
	/// Creates an [`ElementWrapper`].
	pub(crate) fn new(element: G::NonIdentityElement) -> Self {
		Self {
			element,
			repr: G::element_to_repr(&element),
		}
	}

	/// Creates an [`ElementWrapper`] from the given representation.
	///
	/// # Errors
	///
	/// Returns [`Error::FromRepr`] if deserialization fails.
	pub(crate) fn from_repr(bytes: &[u8]) -> Result<Self> {
		Self::from_array(bytes.try_into().map_err(|_| Error::FromRepr)?)
	}

	/// Creates an [`ElementWrapper`] from the given representation.
	///
	/// # Errors
	///
	/// Returns [`Error::FromRepr`] if deserialization fails.
	fn from_array(repr: Array<u8, G::ElementLength>) -> Result<Self> {
		let element = G::non_identity_element_from_repr(&repr).map_err(|_| Error::FromRepr)?;

		Ok(Self { element, repr })
	}

	/// Creates a fixed-sized array of [`ElementWrapper`]s from multiplying the
	/// given elements and scalars.
	pub(crate) fn new_batch<const N: usize>(
		elements_and_scalars: impl Iterator<Item = (G::NonIdentityElement, G::NonZeroScalar)>,
	) -> [Self; N] {
		let elements = elements_and_scalars
			.map(|(element, scalar)| non_zero_maybe_halve::<G>(&scalar, N) * &element)
			.collect_array::<N>();
		non_identity_batch_maybe_double_to_repr::<G, N>(&elements)
			.into_iter()
			.zip(elements)
			.map(|(repr, element)| Self {
				element: maybe_double::<G>(&element, N),
				repr,
			})
			.collect_array()
	}

	/// Creates a [`Vec`] of [`ElementWrapper`]s from multiplying the given
	/// elements and scalars.
	#[cfg(feature = "alloc")]
	pub(crate) fn new_batch_alloc(
		elements_and_scalars: impl ExactSizeIterator<Item = (G::NonIdentityElement, G::NonZeroScalar)>,
	) -> Vec<Self> {
		let length = elements_and_scalars.len();
		let elements: Vec<_> = elements_and_scalars
			.map(|(element, scalar)| non_zero_maybe_halve::<G>(&scalar, length) * &element)
			.collect();
		non_identity_batch_alloc_maybe_double_to_repr::<G>(&elements)
			.into_iter()
			.zip(elements)
			.map(|(repr, element)| Self {
				element: maybe_double::<G>(&element, length),
				repr,
			})
			.collect()
	}

	/// Returns the [`NonIdentityElement`].
	pub(crate) fn into_element(self) -> G::NonIdentityElement {
		self.element
	}

	/// Returns a reference to the [`NonIdentityElement`].
	pub(crate) const fn as_element(&self) -> &G::NonIdentityElement {
		&self.element
	}

	/// Returns the representation of the [`NonIdentityElement`].
	pub(crate) const fn as_repr(&self) -> &Array<u8, G::ElementLength> {
		&self.repr
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

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Clone for Composites<CS> {
	fn clone(&self) -> Self {
		*self
	}
}

impl<CS: CipherSuite> Copy for Composites<CS> {}

/// Corresponds to
/// [`GenerateProof()` in RFC 9497 § 2.2.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2.1-3).
///
/// `A` is always the generator element.
/// `C` and `D` are used to generate [`Composites`].
///
/// # Errors
///
/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
///   [`Group`](CipherSuite::Group) and [`ExpandMsg`](CipherSuite::ExpandMsg)
///   are incompatible.
/// - [`Error::Random`] if the given `rng` fails.
pub(crate) fn generate_proof<CS, R>(
	mode: Mode,
	rng: &mut R,
	k: NonZeroScalar<CS>,
	composites: Composites<CS>,
	B: &ElementWrapper<CS::Group>,
) -> Result<Proof<CS>, Error<R::Error>>
where
	CS: CipherSuite,
	R: ?Sized + TryCryptoRng,
{
	let Composites::<CS> { M, Z } = composites;

	let r = CS::Group::scalar_random(rng).map_err(Error::Random)?.into();
	// `A` is always the generator element.
	let t2 = CS::Group::scalar_mul_by_generator(&CS::Group::scalar_maybe_halve(&r));
	let t3 = r * &M;

	let c = compute_c::<CS>(mode, B, M, Z, t2, t3).map_err(Error::into_random::<R>)?;
	let s = r - &(c * k.deref());

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
pub(crate) fn verify_proof<CS>(
	mode: Mode,
	composites: Composites<CS>,
	B: &ElementWrapper<CS::Group>,
	proof: &Proof<CS>,
) -> Result<()>
where
	CS: CipherSuite,
{
	let Composites::<CS> { M, Z } = composites;
	let Proof { c, s } = proof;

	let t2 = CS::Group::lincomb(&[
		(
			CS::Group::element_generator(),
			CS::Group::scalar_maybe_halve(s),
		),
		(B.element.into(), CS::Group::scalar_maybe_halve(c)),
	]);
	let t3 = CS::Group::lincomb(&[(M, *s), (Z, *c)]);

	let expected_c = compute_c::<CS>(mode, B, M, Z, t2, t3)?;

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
/// The given [`Element`]s may be halved for the purpose of batch serialization.
///
/// # Errors
///
/// Returns [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
/// [`Group`](CipherSuite::Group) and [`ExpandMsg`](CipherSuite::ExpandMsg)
/// are incompatible.
fn compute_c<CS: CipherSuite>(
	mode: Mode,
	B: &ElementWrapper<CS::Group>,
	M: Element<CS>,
	Z: Element<CS>,
	t2: Element<CS>,
	t3: Element<CS>,
) -> Result<Scalar<CS>> {
	let Bm = &B.repr;
	let [a0, a1, a2, a3] = CS::Group::element_batch_maybe_double_to_repr(&[M, Z, t2, t3]);

	CS::hash_to_scalar(
		mode,
		&[
			&CS::I2OSP_ELEMENT_LEN,
			Bm,
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
pub(crate) fn compute_composites<'items, CS, const N: usize>(
	mode: Mode,
	k: Option<NonZeroScalar<CS>>,
	B: &ElementWrapper<CS::Group>,
	C: impl ExactSizeIterator<Item = &'items ElementWrapper<CS::Group>>,
	D: impl ExactSizeIterator<Item = &'items ElementWrapper<CS::Group>>,
) -> Result<Composites<CS>>
where
	CS: CipherSuite,
{
	debug_assert_ne!(N, 0, "found zero item length");
	debug_assert_eq!(N, C.len(), "found unequal item length");
	debug_assert_eq!(N, D.len(), "found unequal item length");
	debug_assert!(N <= u16::MAX.into(), "found overflowing item length");

	let mut Ms = [(Element::<CS>::default(), Scalar::<CS>::default()); N];
	let mut Zs = k
		.is_none()
		.then(|| [(Element::<CS>::default(), Scalar::<CS>::default()); N]);

	internal_compute_composites::<CS>(
		mode,
		N,
		B,
		C,
		D,
		&mut Ms,
		Zs.as_mut().map(<[_; N]>::as_mut_slice),
	)?;

	// We skip the initial addition to the identity point, which is a no-op.
	let M = CS::Group::lincomb(&Ms);
	let Z = k.map_or_else(
		|| CS::Group::lincomb(&Zs.expect("`Zs` must be present if `k` is not")),
		|k| k.into() * &M,
	);

	Ok(Composites { M, Z })
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
#[cfg(feature = "alloc")]
pub(crate) fn alloc_compute_composites<'items, CS>(
	mode: Mode,
	length: usize,
	k: Option<NonZeroScalar<CS>>,
	B: &ElementWrapper<CS::Group>,
	C: impl ExactSizeIterator<Item = &'items ElementWrapper<CS::Group>>,
	D: impl ExactSizeIterator<Item = &'items ElementWrapper<CS::Group>>,
) -> Result<Composites<CS>>
where
	CS: CipherSuite,
{
	debug_assert_ne!(length, 0, "found zero item length");
	debug_assert_eq!(length, C.len(), "found unequal item length");
	debug_assert_eq!(length, D.len(), "found unequal item length");
	debug_assert!(length <= u16::MAX.into(), "found overflowing item length");

	let mut Ms = vec![(Element::<CS>::default(), Scalar::<CS>::default()); length];
	let mut Zs = k
		.is_none()
		.then(|| vec![(Element::<CS>::default(), Scalar::<CS>::default()); length]);

	internal_compute_composites::<CS>(mode, length, B, C, D, &mut Ms, Zs.as_deref_mut())?;

	let M = CS::Group::alloc_lincomb(&Ms);
	let Z = k.map_or_else(
		|| CS::Group::alloc_lincomb(&Zs.expect("`Zs` must be present if `k` is not")),
		|k| k.into() * &M,
	);

	Ok(Composites { M, Z })
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
fn internal_compute_composites<'items, CS>(
	mode: Mode,
	length: usize,
	B: &ElementWrapper<CS::Group>,
	C: impl ExactSizeIterator<Item = &'items ElementWrapper<CS::Group>>,
	D: impl ExactSizeIterator<Item = &'items ElementWrapper<CS::Group>>,
	Ms: &mut [(Element<CS>, Scalar<CS>)],
	Zs: Option<&mut [(Element<CS>, Scalar<CS>)]>,
) -> Result<()>
where
	CS: CipherSuite,
{
	debug_assert_ne!(length, 0, "found zero item length");
	debug_assert_eq!(length, C.len(), "found unequal item length");
	debug_assert_eq!(length, D.len(), "found unequal item length");
	debug_assert_eq!(length, Ms.len(), "found unequal item length");

	#[expect(
		clippy::debug_assert_with_mut_call,
		reason = "`len()` must not have side-effects"
	)]
	if let Some(Zs) = &Zs {
		debug_assert_eq!(length, Zs.len(), "found unequal item length");
	}

	debug_assert!(length <= u16::MAX.into(), "found overflowing item length");

	let Bm = &B.repr;
	let seed_dst = [b"Seed-".as_slice()].concat(create_context_string::<CS>(mode));
	let seed = CS::Hash::default()
		.chain(CS::I2OSP_ELEMENT_LEN)
		.chain(Bm)
		.chain(seed_dst.i2osp_length().expect("`CS::Id` too long"))
		.chain_iter(seed_dst.into_iter())
		.finalize_fixed();

	for (i, ((Ci, M), (Di, Z))) in (0..=u16::MAX).zip(
		(C.zip(Ms)).zip(
			D.zip(
				Zs.into_iter()
					.flatten()
					.map(Some)
					.chain(iter::repeat_with(|| None)),
			),
		),
	) {
		let mut di = CS::hash_to_scalar(
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

		di = CS::Group::scalar_maybe_halve(&di);

		*M = (Ci.element.into(), di);

		if let Some(Z) = Z {
			*Z = (Di.element.into(), di);
		}
	}

	Ok(())
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
) -> Result<BlindResult<CS, N>, Error<R::Error>>
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
		input.i2osp_length().ok_or(Error::InputLength)?;

		CS::hash_to_curve(mode, input).map_err(Error::into_random::<R>)
	})?
	.0;

	let blinds = ArrayN::<_, N>::try_from_fn(|_| {
		// Moved `blind` after to fail early.
		CS::Group::scalar_random(rng).map_err(Error::Random)
	})?
	.0;

	let blinded_elements = input_elements.into_iter().zip(blinds.iter().copied());
	let blinded_elements = BlindedElement::new_batch(blinded_elements);

	Ok(BlindResult {
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
	mut inputs: impl ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
) -> Result<AllocBlindResult<CS>, Error<R::Error>>
where
	CS: CipherSuite,
	R: ?Sized + TryCryptoRng,
{
	let (blinds, blinded_elements) = inputs.try_fold(
		(Vec::new(), Vec::new()),
		|(mut blinds, mut blinded_elements), input| {
			// Fail early.
			input.i2osp_length().ok_or(Error::InputLength)?;

			let input_element = CS::hash_to_curve(mode, input).map_err(Error::into_random::<R>)?;

			// Moved `blind` after to fail early.
			let blind = CS::Group::scalar_random(rng).map_err(Error::Random)?;

			let blinded_element = (input_element, blind);

			blinds.push(blind);
			blinded_elements.push(blinded_element);

			Ok((blinds, blinded_elements))
		},
	)?;

	let blinded_elements = BlindedElement::new_batch_alloc(blinded_elements.into_iter());

	Ok(AllocBlindResult {
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
		.map(|(inverted_blind, evaluation_element)| {
			maybe_halve::<CS::Group>(&inverted_blind, N) * evaluation_element.deref()
		})
		.collect_array::<N>();
	let unblinded_elements = batch_maybe_double_to_repr::<CS::Group, N>(&n);

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
	length: usize,
	inputs: impl ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
	blinds: Vec<NonZeroScalar<CS>>,
	evaluation_elements: impl ExactSizeIterator<Item = &'evaluation_elements NonIdentityElement<CS>>,
	info: Option<Info<'_>>,
) -> Result<Vec<Output<CS::Hash>>>
where
	CS: CipherSuite,
{
	debug_assert_eq!(length, inputs.len(), "found unequal item length");
	debug_assert_eq!(length, blinds.len(), "found unequal item length");
	debug_assert_eq!(
		length,
		evaluation_elements.len(),
		"found unequal item length"
	);

	let inverted_blinds = CS::Group::scalar_batch_alloc_invert(blinds);
	let n: Vec<_> = inverted_blinds
		.into_iter()
		.zip(evaluation_elements)
		.map(|(inverted_blind, evaluation_element)| {
			non_zero_maybe_halve::<CS::Group>(&inverted_blind, length) * evaluation_element
		})
		.collect();
	let unblinded_elements = non_identity_batch_alloc_maybe_double_to_repr::<CS::Group>(&n);

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
				hash.update(info.i2osp());
				hash.update(info.info());
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
	[Element<CS>; N]: AssocArraySize<Size: ArraySize<ArrayType<Element<CS>> = [Element<CS>; N]>>,
	[Output<CS::Hash>; N]:
		AssocArraySize<Size: ArraySize<ArrayType<Output<CS::Hash>> = [Output<CS::Hash>; N]>>,
	CS: CipherSuite,
{
	let evaluation_elements = ArrayN::try_from_fn(|index| {
		#[expect(clippy::indexing_slicing, reason = "`N` matches")]
		let input = inputs[index];

		let input_element = CS::hash_to_curve(mode, input)?;
		Ok(maybe_halve::<CS::Group>(&secret_key, N) * input_element.deref())
	})?
	.0;
	let issued_elements = batch_maybe_double_to_repr::<CS::Group, N>(&evaluation_elements);

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
			Ok(non_zero_maybe_halve::<CS::Group>(&secret_key, inputs.len()) * &input_element)
		})
		.collect::<Result<Vec<_>>>()?;
	let issued_elements =
		non_identity_batch_alloc_maybe_double_to_repr::<CS::Group>(&evaluation_elements);

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
				hash.update(info.i2osp());
				hash.update(info.info());
			}

			Ok(hash
				.chain(CS::I2OSP_ELEMENT_LEN)
				.chain(issued_element)
				.chain(b"Finalize")
				.finalize_fixed())
		})
}

/// Only redirects to [`Group::non_zero_scalar_maybe_halve()`] if we intend to
/// serialize multiple scalars.
fn non_zero_maybe_halve<G: Group>(scalar: &G::NonZeroScalar, length: usize) -> G::NonZeroScalar {
	match length {
		1 => *scalar,
		_ => G::non_zero_scalar_maybe_halve(scalar),
	}
}

/// Only redirects to [`Group::scalar_maybe_halve()`] if we intend to serialize
/// multiple scalars.
fn maybe_halve<G: Group>(scalar: &G::Scalar, length: usize) -> G::Scalar {
	match length {
		1 => *scalar,
		_ => G::scalar_maybe_halve(scalar),
	}
}

/// Only redirects to [`Group::non_identity_element_maybe_double()`] if we
/// intend to serialize multiple elements.
fn maybe_double<G: Group>(element: &G::NonIdentityElement, length: usize) -> G::NonIdentityElement {
	match length {
		1 => *element,
		_ => G::non_identity_element_maybe_double(element),
	}
}

/// Only redirects to
/// [`Group::non_identity_element_batch_maybe_double_to_repr()`] if we intend to
/// serialize multiple elements.
fn non_identity_batch_maybe_double_to_repr<G: Group, const N: usize>(
	elements: &[G::NonIdentityElement; N],
) -> [Array<u8, G::ElementLength>; N] {
	match N {
		1 => elements
			.iter()
			.map(|element| G::element_to_repr(element))
			.collect_array(),
		_ => G::non_identity_element_batch_maybe_double_to_repr(elements),
	}
}

/// Only redirects to
/// [`Group::non_identity_element_batch_alloc_maybe_double_to_repr()`] if we
/// intend to serialize multiple elements.
#[cfg(feature = "alloc")]
fn non_identity_batch_alloc_maybe_double_to_repr<G: Group>(
	elements: &[G::NonIdentityElement],
) -> Vec<Array<u8, G::ElementLength>> {
	match elements.len() {
		1 => elements
			.iter()
			.map(|element| G::element_to_repr(element))
			.collect(),
		_ => G::non_identity_element_batch_alloc_maybe_double_to_repr(elements),
	}
}

/// Only redirects to [`Group::element_batch_maybe_double_to_repr()`] if we
/// intend to serialize multiple elements.
fn batch_maybe_double_to_repr<G: Group, const N: usize>(
	elements: &[G::Element; N],
) -> [Array<u8, G::ElementLength>; N] {
	match N {
		1 => elements
			.iter()
			.map(|element| G::element_to_repr(element))
			.collect_array(),
		_ => G::element_batch_maybe_double_to_repr(elements),
	}
}
