//! POPRF implementation as per
//! [RFC 9497 § 3.3.3](https://www.rfc-editor.org/rfc/rfc9497.html#name-poprf-protocol).

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::array;
use core::fmt::{self, Debug, Formatter};

#[cfg(feature = "serde")]
use ::serde::ser::SerializeStruct;
#[cfg(feature = "serde")]
use ::serde::{Deserialize, Deserializer, Serialize, Serializer};
use digest::Output;
use hybrid_array::{ArraySize, AssocArraySize};
use rand_core::TryCryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cipher_suite::{CipherSuite, Element, NonIdentityElement, NonZeroScalar};
#[cfg(feature = "alloc")]
use crate::common::BatchAllocBlindEvaluateResult;
use crate::common::{
	BatchBlindEvaluateResult, BlindEvaluateResult, BlindedElement, EvaluationElement, Mode, Proof,
};
use crate::error::{Error, Result};
use crate::group::{CipherSuiteExt, Group};
#[cfg(feature = "alloc")]
use crate::internal::AllocBlindResult;
#[cfg(feature = "serde")]
use crate::internal::ElementWithRepr;
use crate::internal::{self, BlindResult, Info};
#[cfg(feature = "serde")]
use crate::key::SecretKey;
use crate::key::{KeyPair, PublicKey};
#[cfg(feature = "serde")]
use crate::serde;
use crate::util::CollectArray;

/// POPRF client.
///
/// See [RFC 9497 § 3.3.3](https://www.rfc-editor.org/rfc/rfc9497.html#name-poprf-protocol).
pub struct PoprfClient<Cs: CipherSuite> {
	/// `blind`.
	blind: NonZeroScalar<Cs>,
	/// `blindedElement`.
	blinded_element: BlindedElement<Cs>,
}

impl<Cs: CipherSuite> PoprfClient<Cs> {
	/// Blinds the provided `input`.
	///
	/// Corresponds to
	/// [`Blind()` in RFC 9497 § 3.3.3](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-2).
	///
	/// # Errors
	///
	/// - [`Error::InputLength`] if the provided `input` exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInput`] if the provided `input` can never produce a
	///   valid [`BlindedElement`].
	/// - [`Error::Random`] if the provided `rng` fails.
	pub fn blind<R>(rng: &mut R, input: &[&[u8]]) -> Result<PoprfBlindResult<Cs>, Error<R::Error>>
	where
		R: ?Sized + TryCryptoRng,
	{
		let PoprfBatchBlindResult {
			clients: [client],
			blinded_elements: [blinded_element],
		} = Self::batch_blind(rng, &[input])?;

		Ok(PoprfBlindResult {
			client,
			blinded_element,
		})
	}

	/// Batch blinds the provided `inputs` *without allocation*.
	///
	/// It is expected that a part of the computation is as efficient as
	/// [`blind()`](Self::blind)ing a single `input`.
	///
	/// # Errors
	///
	/// - [`Error::InputLength`] if a provided input exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInput`] if a provided input can never produce a valid
	///   [`BlindedElement`].
	/// - [`Error::Random`] if the provided `rng` fails.
	pub fn batch_blind<R, const N: usize>(
		rng: &mut R,
		inputs: &[&[&[u8]]; N],
	) -> Result<PoprfBatchBlindResult<Cs, N>, Error<R::Error>>
	where
		[NonIdentityElement<Cs>; N]: AssocArraySize<
			Size: ArraySize<ArrayType<NonIdentityElement<Cs>> = [NonIdentityElement<Cs>; N]>,
		>,
		[NonZeroScalar<Cs>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<NonZeroScalar<Cs>> = [NonZeroScalar<Cs>; N]>>,
		R: ?Sized + TryCryptoRng,
	{
		let BlindResult {
			blinds,
			blinded_elements,
		} = internal::batch_blind(Mode::Poprf, rng, inputs)?;

		let clients = blinds
			.into_iter()
			.zip(&blinded_elements)
			.map(|(blind, blinded_element)| Self {
				blind,
				blinded_element: blinded_element.clone(),
			})
			.collect_array();

		Ok(PoprfBatchBlindResult {
			clients,
			blinded_elements,
		})
	}

	/// Batch blinds the provided `inputs`.
	///
	/// It is expected that a part of the computation is as efficient as
	/// [`blind()`](Self::blind)ing a single `input`.
	///
	/// # Errors
	///
	/// - [`Error::InputLength`] if a provided input exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInput`] if a provided input can never produce a valid
	///   [`BlindedElement`].
	/// - [`Error::Random`] if the provided `rng` fails.
	#[cfg(feature = "alloc")]
	pub fn batch_alloc_blind<'inputs, R, I>(
		rng: &mut R,
		inputs: I,
	) -> Result<PoprfBatchAllocBlindResult<Cs>, Error<R::Error>>
	where
		R: ?Sized + TryCryptoRng,
		I: ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
	{
		let AllocBlindResult {
			blinds,
			blinded_elements,
		} = internal::batch_alloc_blind(Mode::Poprf, rng, inputs)?;

		let clients = blinds
			.into_iter()
			.zip(&blinded_elements)
			.map(|(blind, blinded_element)| Self {
				blind,
				blinded_element: blinded_element.clone(),
			})
			.collect();

		Ok(PoprfBatchAllocBlindResult {
			clients,
			blinded_elements,
		})
	}

	/// Completes the evaluation.
	///
	/// Corresponds to
	/// [`Finalize()` in RFC 9497 § 3.3.3](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-8).
	///
	/// # Errors
	///
	/// - [`Error::InfoLength`] if the provided `info` exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::Proof`] if the [`Proof`] is invalid.
	/// - [`Error::InputLength`] if the provided `input` exceeds a length of
	///   [`u16::MAX`].
	pub fn finalize(
		&self,
		public_key: &PublicKey<Cs::Group>,
		input: &[&[u8]],
		evaluation_element: &EvaluationElement<Cs>,
		proof: &Proof<Cs>,
		info: &[u8],
	) -> Result<Output<Cs::Hash>> {
		let [output] = Self::batch_finalize(
			array::from_ref(self),
			public_key,
			&[input],
			array::from_ref(evaluation_element),
			proof,
			info,
		)?;
		Ok(output)
	}

	/// Batch completes evaluations with a combined [`Proof`] *without
	/// allocation*.
	///
	/// See [RFC 9497 § 3.3.3](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-9).
	///
	/// # Errors
	///
	/// - [`Error::Batch`] if the number of items in `clients`,`inputs` and
	///   `evaluation_elements` are zero, don't match or exceed a length of
	///   [`u16::MAX`].
	/// - [`Error::InfoLength`] if the provided `info` exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInfo`] if the provided `info` can never produce a
	///   valid output.
	/// - [`Error::Proof`] if the [`Proof`] is invalid.
	/// - [`Error::InputLength`] if the provided `input` exceeds a length of
	///   [`u16::MAX`].
	pub fn batch_finalize<const N: usize>(
		clients: &[Self; N],
		public_key: &PublicKey<Cs::Group>,
		inputs: &[&[&[u8]]; N],
		evaluation_elements: &[EvaluationElement<Cs>; N],
		proof: &Proof<Cs>,
		info: &[u8],
	) -> Result<[Output<Cs::Hash>; N]>
	where
		[Output<Cs::Hash>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Output<Cs::Hash>> = [Output<Cs::Hash>; N]>>,
	{
		if N == 0 || N > u16::MAX.into() {
			return Err(Error::Batch);
		}

		let info = Info::new(info)?;
		let tweaked_key = Self::tweaked_key(public_key, info)?;

		let c = evaluation_elements.iter().map(EvaluationElement::as_ref);
		let d = clients.iter().map(|client| client.blinded_element.as_ref());

		let composites =
			internal::compute_composites::<_, N>(Mode::Poprf, None, tweaked_key.as_ref(), c, d)?;
		internal::verify_proof(Mode::Poprf, composites, tweaked_key.as_ref(), proof)?;

		let blinds = clients.iter().map(|client| client.blind).collect_array();
		let evaluation_elements = evaluation_elements
			.iter()
			.map(EvaluationElement::as_element);

		internal::batch_finalize::<Cs, N>(inputs, blinds, evaluation_elements, Some(info))
	}

	/// Batch completes evaluations with a combined [`Proof`].
	///
	/// See [RFC 9497 § 3.3.3](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-9).
	///
	/// # Errors
	///
	/// - [`Error::Batch`] if the number of items in `clients`,`inputs` and
	///   `evaluation_elements` are zero, don't match or exceed a length of
	///   [`u16::MAX`].
	/// - [`Error::InfoLength`] if the provided `info` exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInfo`] if the provided `info` can never produce a
	///   valid output.
	/// - [`Error::Proof`] if the [`Proof`] is invalid.
	/// - [`Error::InputLength`] if the provided `input` exceeds a length of
	///   [`u16::MAX`].
	#[cfg(feature = "alloc")]
	pub fn batch_alloc_finalize<'clients, 'inputs, 'evaluation_elements, Ic, Ii, Iee>(
		clients: Ic,
		public_key: &PublicKey<Cs::Group>,
		inputs: Ii,
		evaluation_elements: Iee,
		proof: &Proof<Cs>,
		info: &[u8],
	) -> Result<Vec<Output<Cs::Hash>>>
	where
		Ic: ExactSizeIterator<Item = &'clients Self>,
		Ii: ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
		Iee: ExactSizeIterator<Item = &'evaluation_elements EvaluationElement<Cs>>,
	{
		let length = clients.len();

		if length == 0
			|| length != inputs.len()
			|| length != evaluation_elements.len()
			|| length > u16::MAX.into()
		{
			return Err(Error::Batch);
		}

		let info = Info::new(info)?;
		let tweaked_key = Self::tweaked_key(public_key, info)?;

		let c: Vec<_> = evaluation_elements.map(EvaluationElement::as_ref).collect();
		let (d, blinds): (Vec<_>, _) = clients
			.map(|client| (client.blinded_element.as_ref(), client.blind))
			.unzip();

		let composites = internal::alloc_compute_composites(
			Mode::Poprf,
			length,
			None,
			tweaked_key.as_ref(),
			c.iter().copied(),
			d.iter().copied(),
		)?;
		internal::verify_proof(Mode::Poprf, composites, tweaked_key.as_ref(), proof)?;

		let evaluation_elements = c.into_iter().map(ElementWithRepr::as_element);

		internal::batch_alloc_finalize::<Cs>(
			length,
			inputs,
			blinds,
			evaluation_elements,
			Some(info),
		)
	}

	/// # Errors
	///
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInfo`] if the provided `info` can never produce a
	///   valid output.
	fn tweaked_key(
		public_key: &PublicKey<Cs::Group>,
		info: Info<'_>,
	) -> Result<PublicKey<Cs::Group>> {
		let framed_info = [b"Info".as_slice(), &info.i2osp(), info.info()];
		let m = Cs::hash_to_scalar(Mode::Poprf, &framed_info, None)?;
		let t = Cs::Group::scalar_mul_by_generator(&m);
		let element = (t + public_key.as_element())
			.try_into()
			.map_err(|_| Error::InvalidInfo)?;

		Ok(PublicKey::new(element))
	}
}

/// POPRF server.
///
/// See [RFC 9497 § 3.3.3](https://www.rfc-editor.org/rfc/rfc9497.html#name-poprf-protocol).
pub struct PoprfServer<Cs: CipherSuite> {
	/// [`KeyPair`].
	key_pair: KeyPair<Cs::Group>,
	/// Cached `t`.
	t: NonZeroScalar<Cs>,
	/// Cached inverted `t`.
	t_inverted: NonZeroScalar<Cs>,
	/// Cached `tweakedKey`.
	tweaked_key: PublicKey<Cs::Group>,
}

impl<Cs: CipherSuite> PoprfServer<Cs> {
	/// Creates a new [`PoprfServer`] by generating a random [`SecretKey`].
	///
	/// # Errors
	///
	/// - [`Error::Random`] if the provided `rng` fails.
	/// - [`Error::InfoLength`] if the provided `info` exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInfoDanger`] if the provided `info` maps to the
	///   [`SecretKey`] of the server, the client can be assumed to know it and
	///   it should be replaced.
	pub fn new<R>(rng: &mut R, info: &[u8]) -> Result<Self, Error<R::Error>>
	where
		R: ?Sized + TryCryptoRng,
	{
		let key_pair = KeyPair::generate(rng).map_err(Error::Random)?;
		Self::from_key_pair(key_pair, info).map_err(Error::into_random::<R>)
	}

	/// Creates a new [`PoprfServer`] by deterministically mapping the input to
	/// a [`SecretKey`].
	///
	/// # Errors
	///
	/// - [`Error::InfoLength`] if `key_info` or `info` exceed a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::DeriveKeyPair`] if a [`SecretKey`] can never be derived from
	///   the provided input.
	/// - [`Error::InvalidInfoDanger`] if the provided `info` maps to the
	///   [`SecretKey`] of the server, the client can be assumed to know it and
	///   it should be replaced.
	pub fn from_seed(seed: &[u8; 32], key_info: &[u8], info: &[u8]) -> Result<Self> {
		let key_pair = KeyPair::derive::<Cs>(Mode::Poprf, seed, key_info)?;
		Self::from_key_pair(key_pair, info)
	}

	/// Creates a new [`PoprfServer`] from the provided [`KeyPair`].
	///
	/// # Errors
	///
	/// - [`Error::InfoLength`] if the provided `info` exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInfoDanger`] if the provided `info` maps to the
	///   [`SecretKey`] of the server, the client can be assumed to know it and
	///   it should be replaced.
	pub fn from_key_pair(key_pair: KeyPair<Cs::Group>, info: &[u8]) -> Result<Self> {
		let info = Info::new(info)?;
		let framed_info = [b"Info".as_slice(), &info.i2osp(), info.info()];
		let m = Cs::hash_to_scalar(Mode::Poprf, &framed_info, None)?;
		// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-6
		let t = (key_pair.secret_key().to_scalar().into() + &m)
			.try_into()
			.map_err(|_| Error::InvalidInfoDanger)?;
		let t_inverted = Cs::Group::scalar_invert(&t);
		let tweaked_key = Cs::Group::non_zero_scalar_mul_by_generator(&t);
		let tweaked_key = PublicKey::new(tweaked_key);

		Ok(Self {
			key_pair,
			t,
			t_inverted,
			tweaked_key,
		})
	}

	/// Returns the [`KeyPair`].
	pub const fn key_pair(&self) -> &KeyPair<Cs::Group> {
		&self.key_pair
	}

	/// Returns the [`PublicKey`].
	pub const fn public_key(&self) -> &PublicKey<Cs::Group> {
		self.key_pair.public_key()
	}

	/// Process the [`BlindedElement`].
	///
	/// Corresponds to
	/// [`BlindEvaluate()` in RFC 9497 § 3.3.3](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-4).
	///
	/// # Errors
	///
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::Random`] if the provided `rng` fails.
	pub fn blind_evaluate<R>(
		&self,
		rng: &mut R,
		blinded_element: &BlindedElement<Cs>,
	) -> Result<BlindEvaluateResult<Cs>, Error<R::Error>>
	where
		R: ?Sized + TryCryptoRng,
	{
		let BatchBlindEvaluateResult {
			evaluation_elements: [evaluation_element],
			proof,
		} = self.batch_blind_evaluate(rng, array::from_ref(blinded_element))?;

		Ok(BlindEvaluateResult {
			evaluation_element,
			proof,
		})
	}

	/// Process the [`BlindedElement`] computing a combined [`Proof`] *without
	/// allocation*.
	///
	/// See [RFC 9497 § 3.3.3](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-5).
	///
	/// # Errors
	///
	/// - [`Error::Batch`] if the number of items in `blinded_elements` is zero
	///   or exceed a length of [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::Random`] if the provided `rng` fails.
	pub fn batch_blind_evaluate<R, const N: usize>(
		&self,
		rng: &mut R,
		blinded_elements: &[BlindedElement<Cs>; N],
	) -> Result<BatchBlindEvaluateResult<Cs, N>, Error<R::Error>>
	where
		R: ?Sized + TryCryptoRng,
	{
		if blinded_elements.is_empty() || blinded_elements.len() > u16::MAX.into() {
			return Err(Error::Batch);
		}

		let evaluation_elements = EvaluationElement::new_batch(
			blinded_elements
				.iter()
				.map(|blinded_element| (*blinded_element.as_element(), self.t_inverted)),
		);
		let c = evaluation_elements.iter().map(EvaluationElement::as_ref);
		let d = blinded_elements.iter().map(BlindedElement::as_ref);

		let composites = internal::compute_composites::<_, N>(
			Mode::Poprf,
			Some(self.t),
			self.tweaked_key.as_ref(),
			c,
			d,
		)
		.map_err(Error::into_random::<R>)?;
		let proof = internal::generate_proof(
			Mode::Poprf,
			rng,
			self.t,
			composites,
			self.tweaked_key.as_ref(),
		)?;

		Ok(BatchBlindEvaluateResult {
			evaluation_elements,
			proof,
		})
	}

	/// Process the [`BlindedElement`] computing a combined [`Proof`].
	///
	/// See [RFC 9497 § 3.3.3](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-5).
	///
	/// # Errors
	///
	/// - [`Error::Batch`] if the number of items in `blinded_elements` is zero
	///   or exceed a length of [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::Random`] if the provided `rng` fails.
	#[cfg(feature = "alloc")]
	pub fn batch_alloc_blind_evaluate<'blinded_elements, R, I>(
		&self,
		rng: &mut R,
		blinded_elements: I,
	) -> Result<BatchAllocBlindEvaluateResult<Cs>, Error<R::Error>>
	where
		R: ?Sized + TryCryptoRng,
		I: ExactSizeIterator<Item = &'blinded_elements BlindedElement<Cs>>,
	{
		let blinded_elements_length = blinded_elements.len();

		if blinded_elements_length == 0 || blinded_elements_length > u16::MAX.into() {
			return Err(Error::Batch);
		}

		let d: Vec<_> = blinded_elements.map(BlindedElement::as_ref).collect();
		let evaluation_elements = EvaluationElement::new_batch_alloc(
			d.iter()
				.map(|element| (*element.as_element(), self.t_inverted)),
		);
		let c = evaluation_elements.iter().map(EvaluationElement::as_ref);

		let composites = internal::alloc_compute_composites(
			Mode::Poprf,
			blinded_elements_length,
			Some(self.t),
			self.tweaked_key.as_ref(),
			c.into_iter(),
			d.into_iter(),
		)
		.map_err(Error::into_random::<R>)?;
		let proof = internal::generate_proof(
			Mode::Poprf,
			rng,
			self.t,
			composites,
			self.tweaked_key.as_ref(),
		)?;

		Ok(BatchAllocBlindEvaluateResult {
			evaluation_elements,
			proof,
		})
	}

	/// Completes the evaluation.
	///
	/// Corresponds to
	/// [`Evaluate()` in RFC 9497 § 3.3.3](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-11).
	///
	/// # Errors
	///
	/// - [`Error::InfoLength`] if the provided `info` exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInput`] if the provided `input` can never produce a
	///   valid output.
	/// - [`Error::InputLength`] if the provided `input` exceeds a length of
	///   [`u16::MAX`].
	pub fn evaluate(&self, input: &[&[u8]], info: &[u8]) -> Result<Output<Cs::Hash>> {
		let [output] = self.batch_evaluate(&[input], info)?;
		Ok(output)
	}

	/// Batch Completes evaluations *without allocation*.
	///
	/// It is expected that a part of the computation is as efficient as
	/// [`evaluate()`](Self::evaluate)ing a single `input`.
	///
	/// # Errors
	///
	/// - [`Error::InfoLength`] if the provided `info` exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInput`] if a provided input can never produce a valid
	///   output.
	/// - [`Error::InputLength`] if a provided input exceeds a length of
	///   [`u16::MAX`].
	pub fn batch_evaluate<const N: usize>(
		&self,
		inputs: &[&[&[u8]]; N],
		info: &[u8],
	) -> Result<[Output<Cs::Hash>; N]>
	where
		[Element<Cs>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Element<Cs>> = [Element<Cs>; N]>>,
		[Output<Cs::Hash>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Output<Cs::Hash>> = [Output<Cs::Hash>; N]>>,
	{
		internal::batch_evaluate::<Cs, N>(
			Mode::Poprf,
			self.t_inverted,
			inputs,
			Some(Info::new(info)?),
		)
	}

	/// Batch Completes evaluations.
	///
	/// It is expected that a part of the computation is as efficient as
	/// [`evaluate()`](Self::evaluate)ing a single `input`.
	///
	/// # Errors
	///
	/// - [`Error::InfoLength`] if the provided `info` exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInput`] if a provided input can never produce a valid
	///   output.
	/// - [`Error::InputLength`] if a provided input exceeds a length of
	///   [`u16::MAX`].
	#[cfg(feature = "alloc")]
	pub fn batch_alloc_evaluate(
		&self,
		inputs: &[&[&[u8]]],
		info: &[u8],
	) -> Result<Vec<Output<Cs::Hash>>> {
		internal::batch_alloc_evaluate::<Cs>(
			Mode::Poprf,
			self.t_inverted,
			inputs,
			Some(Info::new(info)?),
		)
	}
}

/// Returned from [`PoprfClient::blind()`].
pub struct PoprfBlindResult<Cs: CipherSuite> {
	/// The [`PoprfClient`].
	pub client: PoprfClient<Cs>,
	/// The [`BlindedElement`].
	pub blinded_element: BlindedElement<Cs>,
}

/// Returned from [`PoprfClient::batch_blind()`].
pub struct PoprfBatchBlindResult<Cs: CipherSuite, const N: usize> {
	/// The [`PoprfClient`]s.
	pub clients: [PoprfClient<Cs>; N],
	/// The [`BlindedElement`]s each corresponding to a [`PoprfClient`] in
	/// order.
	pub blinded_elements: [BlindedElement<Cs>; N],
}

/// Returned from [`PoprfClient::batch_alloc_blind()`].
#[cfg(feature = "alloc")]
pub struct PoprfBatchAllocBlindResult<Cs: CipherSuite> {
	/// The [`PoprfClient`]s.
	pub clients: Vec<PoprfClient<Cs>>,
	/// The [`BlindedElement`]s each corresponding to a [`PoprfClient`] in
	/// order.
	pub blinded_elements: Vec<BlindedElement<Cs>>,
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Clone for PoprfClient<Cs> {
	fn clone(&self) -> Self {
		Self {
			blind: self.blind,
			blinded_element: self.blinded_element.clone(),
		}
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Debug for PoprfClient<Cs> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfClient")
			.field("blind", &self.blind)
			.field("blinded_element", &self.blinded_element)
			.finish()
	}
}

#[cfg(feature = "serde")]
impl<'de, Cs> Deserialize<'de> for PoprfClient<Cs>
where
	Cs: CipherSuite,
	NonZeroScalar<Cs>: Deserialize<'de>,
{
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		let (blind, wrapper): (_, ElementWithRepr<Cs::Group>) =
			serde::struct_2(deserializer, "PoprfClient", &["blind", "blinded_element"])?;
		let blinded_element = BlindedElement::from(wrapper);

		Ok(Self {
			blind,
			blinded_element,
		})
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Drop for PoprfClient<Cs> {
	fn drop(&mut self) {
		self.blind.zeroize();
	}
}

impl<Cs: CipherSuite> Eq for PoprfClient<Cs> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> PartialEq for PoprfClient<Cs> {
	fn eq(&self, other: &Self) -> bool {
		self.blind.eq(&other.blind) && self.blinded_element.eq(&other.blinded_element)
	}
}

#[cfg(feature = "serde")]
impl<Cs> Serialize for PoprfClient<Cs>
where
	Cs: CipherSuite,
	NonZeroScalar<Cs>: Serialize,
{
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let mut state = serializer.serialize_struct("PoprfClient", 2)?;
		state.serialize_field("blind", &self.blind)?;
		state.serialize_field("blinded_element", self.blinded_element.as_ref())?;
		state.end()
	}
}

impl<Cs: CipherSuite> ZeroizeOnDrop for PoprfClient<Cs> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Clone for PoprfServer<Cs> {
	fn clone(&self) -> Self {
		Self {
			key_pair: self.key_pair.clone(),
			t: self.t,
			t_inverted: self.t_inverted,
			tweaked_key: self.tweaked_key.clone(),
		}
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Debug for PoprfServer<Cs> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfServer")
			.field("key_pair", &self.key_pair)
			.field("t", &self.t)
			.field("t_inverted", &self.t_inverted)
			.field("tweaked_key", &self.tweaked_key)
			.finish()
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Drop for PoprfServer<Cs> {
	fn drop(&mut self) {
		self.t.zeroize();
		self.t_inverted.zeroize();
	}
}

#[cfg(feature = "serde")]
impl<'de, Cs> Deserialize<'de> for PoprfServer<Cs>
where
	Cs: CipherSuite,
	NonZeroScalar<Cs>: Deserialize<'de>,
{
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		let (scalar, t) = serde::struct_2(deserializer, "PoprfServer", &["secret_key", "t"])?;
		let secret_key = SecretKey::new(scalar);
		let key_pair = KeyPair::from_secret_key(secret_key);
		let t_inverted = Cs::Group::scalar_invert(&t);
		let tweaked_key = Cs::Group::non_zero_scalar_mul_by_generator(&t);
		let tweaked_key = PublicKey::new(tweaked_key);

		Ok(Self {
			key_pair,
			t,
			t_inverted,
			tweaked_key,
		})
	}
}

impl<Cs: CipherSuite> Eq for PoprfServer<Cs> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> PartialEq for PoprfServer<Cs> {
	fn eq(&self, other: &Self) -> bool {
		self.key_pair.eq(&other.key_pair) & self.t.eq(&other.t)
	}
}

#[cfg(feature = "serde")]
impl<Cs> Serialize for PoprfServer<Cs>
where
	Cs: CipherSuite,
	NonZeroScalar<Cs>: Serialize,
{
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let mut state = serializer.serialize_struct("PoprfServer", 2)?;
		state.serialize_field("secret_key", &self.key_pair.secret_key().as_scalar())?;
		state.serialize_field("t", &self.t)?;
		state.end()
	}
}

impl<Cs: CipherSuite> ZeroizeOnDrop for PoprfServer<Cs> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Debug for PoprfBlindResult<Cs> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfBlindResult")
			.field("client", &self.client)
			.field("blinded_element", &self.blinded_element)
			.finish()
	}
}

impl<Cs: CipherSuite> ZeroizeOnDrop for PoprfBlindResult<Cs> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite, const N: usize> Debug for PoprfBatchBlindResult<Cs, N> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfBatchBlindResult")
			.field("clients", &self.clients)
			.field("blinded_elements", &self.blinded_elements)
			.finish()
	}
}

impl<Cs: CipherSuite, const N: usize> ZeroizeOnDrop for PoprfBatchBlindResult<Cs, N> {}

#[cfg(feature = "alloc")]
#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Debug for PoprfBatchAllocBlindResult<Cs> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfBatchAllocBlindResult")
			.field("clients", &self.clients)
			.field("blinded_elements", &self.blinded_elements)
			.finish()
	}
}

#[cfg(feature = "alloc")]
impl<Cs: CipherSuite> ZeroizeOnDrop for PoprfBatchAllocBlindResult<Cs> {}
