#![expect(non_snake_case, reason = "following the specification exactly")]

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::ops::Deref;
use core::{array, iter};

use digest::{FixedOutput, Output, OutputSizeUser, Update};
use hybrid_array::{ArrayN, ArraySize, AssocArraySize};
use rand_core::TryCryptoRng;
use typenum::Unsigned;

use crate::EvaluationElement;
use crate::ciphersuite::{CipherSuite, Element, NonIdentityElement, NonZeroScalar, Scalar};
use crate::common::{BlindedElement, Mode, Proof};
use crate::error::{Error, Result};
use crate::group::{Group, InternalGroup};
use crate::util::{Concat, I2osp, I2ospLength, UpdateIter};

pub(crate) struct BlindResult<CS: CipherSuite> {
	pub(crate) blind: NonZeroScalar<CS>,
	pub(crate) blinded_element: BlindedElement<CS>,
}

pub(crate) trait Blind<CS: CipherSuite> {
	fn get_blind(&self) -> NonZeroScalar<CS>;
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Info<'info> {
	i2osp: [u8; 2],
	info: &'info [u8],
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

// `A` is alway the generator element.
// `GenerateProof`
// https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2.1-3
pub(crate) fn generate_proof<'elements, CS, R, CI, DI>(
	mode: Mode,
	rng: &mut R,
	k: NonZeroScalar<CS>,
	B: &NonIdentityElement<CS>,
	C: CI,
	D: DI,
) -> Result<Proof<CS>, Error<R::Error>>
where
	CS: CipherSuite,
	R: TryCryptoRng,
	CI: ExactSizeIterator<Item = &'elements NonIdentityElement<CS>>,
	DI: ExactSizeIterator<Item = &'elements NonIdentityElement<CS>>,
{
	let Composites::<CS> { M, Z } =
		compute_composites(mode, Some(k), B, C, D).map_err(Error::into_random::<R>)?;

	let r = CS::Group::random_scalar(rng).map_err(Error::Random)?;
	let t2 = CS::Group::non_zero_scalar_mul_by_generator(&r);
	let t3 = r.into() * &M;

	let c = compute_c::<CS>(mode, B, &M, &Z, &t2, &t3);
	let s = r.into() - &(c * k.deref());

	Ok(Proof { c, s })
}

// `VerifyProof`
// https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2.2-2
pub(crate) fn verify_proof<'elements, CS, CI, DI>(
	mode: Mode,
	B: NonIdentityElement<CS>,
	C: CI,
	D: DI,
	proof: &Proof<CS>,
) -> Result<()>
where
	CS: CipherSuite,
	CI: ExactSizeIterator<Item = &'elements NonIdentityElement<CS>>,
	DI: ExactSizeIterator<Item = &'elements NonIdentityElement<CS>>,
{
	let Composites::<CS> { M, Z } = compute_composites(mode, None, &B, C, D)?;
	let Proof { c, s } = proof;

	let t2 = CS::Group::lincomb([(CS::Group::generator_element(), *s), (B.into(), *c)]);
	let t3 = CS::Group::lincomb([(M, *s), (Z, *c)]);

	let expected_c = compute_c::<CS>(mode, &B, &M, &Z, &t2, &t3);

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
	B: &Element<CS>,
	M: &Element<CS>,
	Z: &Element<CS>,
	t2: &Element<CS>,
	t3: &Element<CS>,
) -> Scalar<CS> {
	let Bm = CS::Group::serialize_element(B);
	let a0 = CS::Group::serialize_element(M);
	let a1 = CS::Group::serialize_element(Z);
	let a2 = CS::Group::serialize_element(t2);
	let a3 = CS::Group::serialize_element(t3);

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
fn compute_composites<'elements, CS, CI, DI>(
	mode: Mode,
	k: Option<NonZeroScalar<CS>>,
	B: &NonIdentityElement<CS>,
	C: CI,
	D: DI,
) -> Result<Composites<CS>>
where
	CS: CipherSuite,
	CI: ExactSizeIterator<Item = &'elements NonIdentityElement<CS>>,
	DI: ExactSizeIterator<Item = &'elements NonIdentityElement<CS>>,
{
	let m = C.len();

	if m == 0 || m != D.len() || m > u16::MAX.into() {
		return Err(Error::Batch);
	}

	let Bm = CS::Group::serialize_element(B);
	let seed_dst = [b"Seed-".as_slice()].concat(create_context_string::<CS>(mode));
	let seed = CS::Hash::default()
		.chain(CS::I2OSP_ELEMENT_LEN)
		.chain(Bm)
		.chain(seed_dst.i2osp_length().expect("`CS::Id` too long"))
		.chain_iter(seed_dst.into_iter())
		.finalize_fixed();

	let mut M = CS::Group::identity_element();
	let mut Z = CS::Group::identity_element();

	for (i, (Ci, Di)) in (0..=u16::MAX).zip(C.zip(D)) {
		let di = CS::hash_to_scalar(
			mode,
			&[
				&<CS::Hash as OutputSizeUser>::OutputSize::U16.i2osp(),
				&seed,
				&i.i2osp(),
				&CS::I2OSP_ELEMENT_LEN,
				&CS::Group::serialize_element(Ci),
				&CS::I2OSP_ELEMENT_LEN,
				&CS::Group::serialize_element(Di),
				b"Composite",
			],
			None,
		);

		M = di * Ci.deref() + &M;

		if k.is_none() {
			Z = di * Di.deref() + &Z;
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
pub(crate) fn blind<CS: CipherSuite, R: TryCryptoRng>(
	mode: Mode,
	rng: &mut R,
	input: &[&[u8]],
) -> Result<BlindResult<CS>, Error<R::Error>> {
	// Fail early.
	let _ = input.i2osp_length().ok_or(Error::InputLength)?;

	let input_element = CS::hash_to_group(mode, input).ok_or(Error::InvalidInput)?;

	// Moved `blind` after to fail early.
	let blind = CS::Group::random_scalar(rng).map_err(Error::Random)?;

	let blinded_element = blind * &input_element;

	Ok(BlindResult {
		blind,
		blinded_element: BlindedElement(blinded_element),
	})
}

// `Finalize`
// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7
pub(crate) fn finalize<CS: CipherSuite>(
	input: &[&[u8]],
	blind: &NonZeroScalar<CS>,
	evaluation_element: &EvaluationElement<CS>,
	info: Option<Info<'_>>,
) -> Result<Output<CS::Hash>> {
	let output: ArrayN<_, 1> = internal_finalize(
		iter::once(input),
		iter::once(CS::Group::scalar_invert(blind).into()),
		iter::once(evaluation_element),
		info,
	)
	.collect();
	let [output] = output.into();

	output
}

// `Finalize`
// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7
#[expect(single_use_lifetimes, reason = "false-positive")]
#[cfg(feature = "alloc")]
pub(crate) fn batch_finalize<'inputs, 'blinds, 'evaluation_elements, CS, T>(
	inputs: impl ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
	blinds: impl ExactSizeIterator<Item = &'blinds T>,
	evaluation_elements: impl ExactSizeIterator<Item = &'evaluation_elements EvaluationElement<CS>>,
	info: Option<Info<'_>>,
) -> Result<Vec<Output<CS::Hash>>>
where
	CS: CipherSuite,
	T: 'static + Blind<CS>,
{
	let input_length = inputs.len();

	if input_length == 0
		|| input_length != blinds.len()
		|| input_length != evaluation_elements.len()
	{
		return Err(Error::Batch);
	}

	let scalars: Vec<_> = blinds.map(|blind| blind.get_blind().into()).collect();
	let inverted_scalars = CS::Group::scalar_batch_invert(scalars).unwrap();

	internal_finalize(
		inputs,
		inverted_scalars.into_iter(),
		evaluation_elements,
		info,
	)
	.collect()
}

// `Finalize`
// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7
#[expect(single_use_lifetimes, reason = "false-positive")]
pub(crate) fn batch_finalize_fixed<'inputs, 'evaluation_elements, const N: usize, CS, T>(
	inputs: impl ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
	blinds: &[T; N],
	evaluation_elements: impl ExactSizeIterator<Item = &'evaluation_elements EvaluationElement<CS>>,
	info: Option<Info<'_>>,
) -> Result<[Output<CS::Hash>; N]>
where
	[Output<CS::Hash>; N]:
		AssocArraySize<Size: ArraySize<ArrayType<Output<CS::Hash>> = [Output<CS::Hash>; N]>>,
	CS: CipherSuite,
	T: Blind<CS>,
{
	if N == 0 || N != inputs.len() || N != evaluation_elements.len() {
		return Err(Error::Batch);
	}

	let scalars: [_; N] = array::from_fn(|index| {
		blinds
			.get(index)
			.expect("arrays should be the same length")
			.get_blind()
			.into()
	});
	let inverted_scalars = CS::Group::scalar_batch_invert_fixed(scalars).unwrap();

	let mut outputs = internal_finalize(
		inputs,
		inverted_scalars.into_iter(),
		evaluation_elements,
		info,
	);
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
#[expect(single_use_lifetimes, reason = "false-positive")]
fn internal_finalize<'inputs, 'evaluation_elements, CS: CipherSuite>(
	inputs: impl ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
	inverted_blinds: impl ExactSizeIterator<Item = Scalar<CS>>,
	evaluation_elements: impl ExactSizeIterator<Item = &'evaluation_elements EvaluationElement<CS>>,
	info: Option<Info<'_>>,
) -> impl Iterator<Item = Result<Output<CS::Hash>>> {
	debug_assert!(
		inputs.len() != 0
			&& inputs.len() == inverted_blinds.len()
			&& inputs.len() == evaluation_elements.len(),
		"found unequal item length"
	);

	inputs.zip(inverted_blinds).zip(evaluation_elements).map(
		move |((input, inverted_blind), evaluation_element)| {
			// Scalar inversion is done beforehand.
			let n = inverted_blind * evaluation_element.0.deref();
			let unblinded_element = CS::Group::serialize_element(&n);

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
		},
	)
}

// `Evaluate`
// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-9
pub(crate) fn evaluate<CS: CipherSuite>(
	mode: Mode,
	secret_key: NonZeroScalar<CS>,
	input: &[&[u8]],
	info: Option<Info<'_>>,
) -> Result<Output<CS::Hash>> {
	let input_element = CS::hash_to_group(mode, input).ok_or(Error::InvalidInput)?;
	let evaluation_element = secret_key * &input_element;
	let issued_element = CS::Group::serialize_element(&evaluation_element);

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
}
