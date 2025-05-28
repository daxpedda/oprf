#![expect(non_snake_case, reason = "following the specification exactly")]

use core::ops::Deref;

use digest::{FixedOutput, Output, OutputSizeUser, Update};
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

#[derive(Clone, Copy, Debug)]
#[expect(
	unnameable_types,
	reason = "exposed to make the type alias work in public"
)]
pub struct Info<'info> {
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
	let n = CS::Group::scalar_invert(blind) * &evaluation_element.0;
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
