#![expect(non_snake_case, reason = "following the specification exactly")]

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::ops::Deref;

use digest::{FixedOutput, Output, OutputSizeUser, Update};
use hybrid_array::typenum::Unsigned;
use hybrid_array::{Array, ArrayN, ArraySize, AssocArraySize};
use rand_core::TryCryptoRng;

use crate::cipher_suite::{
	CipherSuite, Element, ElementLength, NonIdentityElement, NonZeroScalar, Scalar,
};
use crate::common::{BlindedElement, EvaluationElement, Mode, Proof};
use crate::error::{Error, Result};
use crate::group::{Group, InternalGroup};
use crate::key::PublicKey;
use crate::util::{CollectArray, Concat, I2osp, I2ospLength, UpdateIter};

pub(crate) struct BatchBlindResult<CS: CipherSuite, const N: usize> {
	pub(crate) blinds: [NonZeroScalar<CS>; N],
	pub(crate) blinded_elements: [BlindedElement<CS>; N],
}

#[cfg(feature = "alloc")]
pub(crate) struct BatchVecBlindResult<CS: CipherSuite> {
	pub(crate) blinds: Vec<NonZeroScalar<CS>>,
	pub(crate) blinded_elements: Vec<BlindedElement<CS>>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Info<'info> {
	i2osp: [u8; 2],
	info: &'info [u8],
}

pub(crate) struct ElementWrapper<'element, CS: CipherSuite> {
	element: &'element NonIdentityElement<CS>,
	repr: &'element Array<u8, ElementLength<CS>>,
}

struct Composites<CS: CipherSuite> {
	M: Element<CS>,
	Z: Element<CS>,
}

impl<'info> Info<'info> {
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

#[cfg(feature = "alloc")]
impl<'element, CS: CipherSuite> ElementWrapper<'element, CS> {
	pub(crate) const fn element(self) -> &'element NonIdentityElement<CS> {
		self.element
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Clone for ElementWrapper<'_, CS> {
	fn clone(&self) -> Self {
		*self
	}
}

impl<CS: CipherSuite> Copy for ElementWrapper<'_, CS> {}

impl<'element, CS: CipherSuite> From<&'element BlindedElement<CS>>
	for ElementWrapper<'element, CS>
{
	fn from(blinded_element: &'element BlindedElement<CS>) -> Self {
		Self {
			element: blinded_element.element(),
			repr: blinded_element.as_repr(),
		}
	}
}

impl<'element, CS: CipherSuite> From<&'element EvaluationElement<CS>>
	for ElementWrapper<'element, CS>
{
	fn from(evaluation_element: &'element EvaluationElement<CS>) -> Self {
		Self {
			element: evaluation_element.element(),
			repr: evaluation_element.as_repr(),
		}
	}
}

impl<'element, CS: CipherSuite> From<&'element PublicKey<CS::Group>>
	for ElementWrapper<'element, CS>
{
	fn from(public_key: &'element PublicKey<CS::Group>) -> Self {
		Self {
			element: public_key.as_element(),
			repr: public_key.as_repr(),
		}
	}
}

// `A` is alway the generator element.
// `GenerateProof`
// https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2.1-3
pub(crate) fn generate_proof<'items, CS, R>(
	mode: Mode,
	rng: &mut R,
	k: NonZeroScalar<CS>,
	B: ElementWrapper<'items, CS>,
	C: impl ExactSizeIterator<Item = ElementWrapper<'items, CS>>,
	D: impl ExactSizeIterator<Item = ElementWrapper<'items, CS>>,
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
	let t2 = CS::Group::non_zero_scalar_mul_by_generator(&r);
	let t3 = r.into() * &M;

	let c = compute_c::<CS>(mode, (*B.element).into(), M, Z, t2.into(), t3)
		.map_err(Error::into_random::<R>)?;
	let s = r.into() - &(c * k.deref());

	Ok(Proof { c, s })
}

// `VerifyProof`
// https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2.2-2
pub(crate) fn verify_proof<'items, CS>(
	mode: Mode,
	B: ElementWrapper<'items, CS>,
	C: impl ExactSizeIterator<Item = ElementWrapper<'items, CS>>,
	D: impl ExactSizeIterator<Item = ElementWrapper<'items, CS>>,
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

	let t2 = CS::Group::lincomb([
		(CS::Group::element_generator(), *s),
		((*B.element).into(), *c),
	]);
	let t3 = CS::Group::lincomb([(M, *s), (Z, *c)]);

	let expected_c = compute_c::<CS>(mode, (*B.element).into(), M, Z, t2, t3)?;

	if &expected_c == c {
		Ok(())
	} else {
		Err(Error::Proof)
	}
}

// Shared code between `GenerateProof` and `VerifyProof`
// https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2.1-3
// https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2.2-2
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

// `ComputeComposites` and `ComputeCompositesFast`
// https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2.1-5
// https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2.2-4
fn compute_composites<'items, CS>(
	mode: Mode,
	k: Option<NonZeroScalar<CS>>,
	B: ElementWrapper<'_, CS>,
	C: impl ExactSizeIterator<Item = ElementWrapper<'items, CS>>,
	D: impl ExactSizeIterator<Item = ElementWrapper<'items, CS>>,
) -> Result<Composites<CS>>
where
	CS: CipherSuite,
{
	debug_assert_ne!(C.len(), 0, "found zero item length");
	debug_assert_eq!(C.len(), D.len(), "found unequal item length");
	debug_assert!(C.len() <= u16::MAX.into(), "found overflowing item length");

	let Bm = B.repr;
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
				Ci.repr,
				&CS::I2OSP_ELEMENT_LEN,
				Di.repr,
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

// `CreateContextString`
// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.1-5
pub(crate) fn create_context_string<CS: CipherSuite>(mode: Mode) -> [&'static [u8]; 4] {
	[b"OPRFV1-", mode.i2osp(), b"-", &CS::ID]
}

// `Blind`.
// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-2
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

// `Blind`.
// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-2
#[cfg(feature = "alloc")]
pub(crate) fn batch_vec_blind<'inputs, CS, R>(
	mode: Mode,
	rng: &mut R,
	mut inputs: impl Iterator<Item = &'inputs [&'inputs [u8]]>,
) -> Result<BatchVecBlindResult<CS>, Error<R::Error>>
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

	let blinded_elements = BlindedElement::new_batch_vec(blinded_elements);

	Ok(BatchVecBlindResult {
		blinds,
		blinded_elements,
	})
}

// `Finalize`
// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7
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

// `Finalize`
// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7
#[cfg(feature = "alloc")]
#[expect(single_use_lifetimes, reason = "false-positive")]
pub(crate) fn batch_vec_finalize<'inputs, 'evaluation_elements, CS>(
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

	let inverted_blinds = CS::Group::scalar_batch_vec_invert(blinds);
	let n: Vec<_> = inverted_blinds
		.into_iter()
		.zip(evaluation_elements)
		.map(|(inverted_blind, evaluation_element)| inverted_blind * evaluation_element)
		.collect();
	let unblinded_elements = CS::Group::non_identity_element_batch_vec_to_repr(&n);

	internal_finalize::<CS>(inputs, &unblinded_elements, info).collect()
}

// `Finalize`
// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7
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

// `Evaluate`
// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-9
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

// `Evaluate`
// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-9
#[cfg(feature = "alloc")]
pub(crate) fn batch_vec_evaluate<CS: CipherSuite>(
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
	let issued_elements = CS::Group::non_identity_element_batch_vec_to_repr(&evaluation_elements);

	internal_evaluate::<CS>(inputs, &issued_elements, info).collect()
}

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
