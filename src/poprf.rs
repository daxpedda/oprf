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
use crate::group::{Group, InternalGroup};
#[cfg(feature = "alloc")]
use crate::internal::AllocBlindResult;
#[cfg(feature = "serde")]
use crate::internal::ElementWrapper;
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
pub struct PoprfClient<CS: CipherSuite> {
	/// `blind`.
	blind: NonZeroScalar<CS>,
	/// `blindedElement`.
	blinded_element: BlindedElement<CS>,
}

impl<CS: CipherSuite> PoprfClient<CS> {
	/// Blinds the given `input`.
	///
	/// Corresponds to
	/// [`Blind()` in RFC 9497 § 3.3.3](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-2).
	///
	/// # Errors
	///
	/// - [`Error::InputLength`] if the given `input` exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInput`] if the given `input` can never produce a valid
	///   [`BlindedElement`].
	/// - [`Error::Random`] if the given `rng` fails.
	pub fn blind<R>(rng: &mut R, input: &[&[u8]]) -> Result<PoprfBlindResult<CS>, Error<R::Error>>
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

	/// Batch blinds the given `inputs` *without allocation*.
	///
	/// It is expected that a part of the computation is as efficient as
	/// [`blind()`](Self::blind)ing a single `input`.
	///
	/// # Errors
	///
	/// - [`Error::InputLength`] if a given input exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInput`] if a given input can never produce a valid
	///   [`BlindedElement`].
	/// - [`Error::Random`] if the given `rng` fails.
	pub fn batch_blind<R, const N: usize>(
		rng: &mut R,
		inputs: &[&[&[u8]]; N],
	) -> Result<PoprfBatchBlindResult<CS, N>, Error<R::Error>>
	where
		[NonIdentityElement<CS>; N]: AssocArraySize<
			Size: ArraySize<ArrayType<NonIdentityElement<CS>> = [NonIdentityElement<CS>; N]>,
		>,
		[NonZeroScalar<CS>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<NonZeroScalar<CS>> = [NonZeroScalar<CS>; N]>>,
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

	/// Batch blinds the given `inputs`.
	///
	/// It is expected that a part of the computation is as efficient as
	/// [`blind()`](Self::blind)ing a single `input`.
	///
	/// # Errors
	///
	/// - [`Error::InputLength`] if a given input exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInput`] if a given input can never produce a valid
	///   [`BlindedElement`].
	/// - [`Error::Random`] if the given `rng` fails.
	#[cfg(feature = "alloc")]
	pub fn batch_alloc_blind<'inputs, R, I>(
		rng: &mut R,
		inputs: I,
	) -> Result<PoprfBatchAllocBlindResult<CS>, Error<R::Error>>
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
	/// - [`Error::InfoLength`] if the given `info` exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::Proof`] if the [`Proof`] is invalid.
	/// - [`Error::InputLength`] if the given `input` exceeds a length of
	///   [`u16::MAX`].
	pub fn finalize(
		&self,
		public_key: &PublicKey<CS::Group>,
		input: &[&[u8]],
		evaluation_element: &EvaluationElement<CS>,
		proof: &Proof<CS>,
		info: &[u8],
	) -> Result<Output<CS::Hash>> {
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
	/// - [`Error::InfoLength`] if the given `info` exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInfo`] if the given `info` can never produce a valid
	///   output.
	/// - [`Error::Proof`] if the [`Proof`] is invalid.
	/// - [`Error::InputLength`] if the given `input` exceeds a length of
	///   [`u16::MAX`].
	pub fn batch_finalize<const N: usize>(
		clients: &[Self; N],
		public_key: &PublicKey<CS::Group>,
		inputs: &[&[&[u8]]; N],
		evaluation_elements: &[EvaluationElement<CS>; N],
		proof: &Proof<CS>,
		info: &[u8],
	) -> Result<[Output<CS::Hash>; N]>
	where
		[Output<CS::Hash>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Output<CS::Hash>> = [Output<CS::Hash>; N]>>,
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

		internal::batch_finalize::<CS, N>(inputs, blinds, evaluation_elements, Some(info))
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
	/// - [`Error::InfoLength`] if the given `info` exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInfo`] if the given `info` can never produce a valid
	///   output.
	/// - [`Error::Proof`] if the [`Proof`] is invalid.
	/// - [`Error::InputLength`] if the given `input` exceeds a length of
	///   [`u16::MAX`].
	#[cfg(feature = "alloc")]
	pub fn batch_alloc_finalize<'clients, 'inputs, 'evaluation_elements, IC, II, IEE>(
		clients: IC,
		public_key: &PublicKey<CS::Group>,
		inputs: II,
		evaluation_elements: IEE,
		proof: &Proof<CS>,
		info: &[u8],
	) -> Result<Vec<Output<CS::Hash>>>
	where
		IC: ExactSizeIterator<Item = &'clients Self>,
		II: ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
		IEE: ExactSizeIterator<Item = &'evaluation_elements EvaluationElement<CS>>,
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

		let evaluation_elements = c.into_iter().map(ElementWrapper::as_element);

		internal::batch_alloc_finalize::<CS>(
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
	/// - [`Error::InvalidInfo`] if the given `info` can never produce a valid
	///   output.
	fn tweaked_key(
		public_key: &PublicKey<CS::Group>,
		info: Info<'_>,
	) -> Result<PublicKey<CS::Group>> {
		let framed_info = [b"Info".as_slice(), info.i2osp(), info.info()];
		let m = CS::hash_to_scalar(Mode::Poprf, &framed_info, None)?;
		let t = CS::Group::scalar_mul_by_generator(&m);
		let element = (t + public_key.as_element())
			.try_into()
			.map_err(|_| Error::InvalidInfo)?;

		Ok(PublicKey::new(element))
	}
}

/// POPRF server.
///
/// See [RFC 9497 § 3.3.3](https://www.rfc-editor.org/rfc/rfc9497.html#name-poprf-protocol).
pub struct PoprfServer<CS: CipherSuite> {
	/// [`KeyPair`].
	key_pair: KeyPair<CS::Group>,
	/// Cached `t`.
	t: NonZeroScalar<CS>,
	/// Cached inverted `t`.
	t_inverted: NonZeroScalar<CS>,
	/// Cached `tweakedKey`.
	tweaked_key: PublicKey<CS::Group>,
}

impl<CS: CipherSuite> PoprfServer<CS> {
	/// Creates a new [`PoprfServer`] by generating a random [`SecretKey`].
	///
	/// # Errors
	///
	/// - [`Error::Random`] if the given `rng` fails.
	/// - [`Error::InfoLength`] if the given `info` exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInfoDanger`] if the given `info` maps to the
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
	///   the given input.
	/// - [`Error::InvalidInfoDanger`] if the given `info` maps to the
	///   [`SecretKey`] of the server, the client can be assumed to know it and
	///   it should be replaced.
	pub fn from_seed(seed: &[u8; 32], key_info: &[u8], info: &[u8]) -> Result<Self> {
		let key_pair = KeyPair::derive::<CS>(Mode::Poprf, seed, key_info)?;
		Self::from_key_pair(key_pair, info)
	}

	/// Creates a new [`PoprfServer`] from the given [`KeyPair`].
	///
	/// # Errors
	///
	/// - [`Error::InfoLength`] if the given `info` exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInfoDanger`] if the given `info` maps to the
	///   [`SecretKey`] of the server, the client can be assumed to know it and
	///   it should be replaced.
	pub fn from_key_pair(key_pair: KeyPair<CS::Group>, info: &[u8]) -> Result<Self> {
		let info = Info::new(info)?;
		let framed_info = [b"Info".as_slice(), info.i2osp(), info.info()];
		let m = CS::hash_to_scalar(Mode::Poprf, &framed_info, None)?;
		// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-6
		let t = (key_pair.secret_key().to_scalar().into() + &m)
			.try_into()
			.map_err(|_| Error::InvalidInfoDanger)?;
		let t_inverted = CS::Group::scalar_invert(&t);
		let tweaked_key = CS::Group::non_zero_scalar_mul_by_generator(&t);
		let tweaked_key = PublicKey::new(tweaked_key);

		Ok(Self {
			key_pair,
			t,
			t_inverted,
			tweaked_key,
		})
	}

	/// Returns the [`KeyPair`].
	pub const fn key_pair(&self) -> &KeyPair<CS::Group> {
		&self.key_pair
	}

	/// Returns the [`PublicKey`].
	pub const fn public_key(&self) -> &PublicKey<CS::Group> {
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
	/// - [`Error::Random`] if the given `rng` fails.
	pub fn blind_evaluate<R>(
		&self,
		rng: &mut R,
		blinded_element: &BlindedElement<CS>,
	) -> Result<BlindEvaluateResult<CS>, Error<R::Error>>
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
	/// - [`Error::Random`] if the given `rng` fails.
	pub fn batch_blind_evaluate<R, const N: usize>(
		&self,
		rng: &mut R,
		blinded_elements: &[BlindedElement<CS>; N],
	) -> Result<BatchBlindEvaluateResult<CS, N>, Error<R::Error>>
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
	/// - [`Error::Random`] if the given `rng` fails.
	#[cfg(feature = "alloc")]
	pub fn batch_alloc_blind_evaluate<'blinded_elements, R, I>(
		&self,
		rng: &mut R,
		blinded_elements: I,
	) -> Result<BatchAllocBlindEvaluateResult<CS>, Error<R::Error>>
	where
		R: ?Sized + TryCryptoRng,
		I: ExactSizeIterator<Item = &'blinded_elements BlindedElement<CS>>,
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
	/// - [`Error::InfoLength`] if the given `info` exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInput`] if the given `input` can never produce a valid
	///   output.
	/// - [`Error::InputLength`] if the given `input` exceeds a length of
	///   [`u16::MAX`].
	pub fn evaluate(&self, input: &[&[u8]], info: &[u8]) -> Result<Output<CS::Hash>> {
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
	/// - [`Error::InfoLength`] if the given `info` exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInput`] if a given input can never produce a valid
	///   output.
	/// - [`Error::InputLength`] if a given input exceeds a length of
	///   [`u16::MAX`].
	pub fn batch_evaluate<const N: usize>(
		&self,
		inputs: &[&[&[u8]]; N],
		info: &[u8],
	) -> Result<[Output<CS::Hash>; N]>
	where
		[Element<CS>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Element<CS>> = [Element<CS>; N]>>,
		[Output<CS::Hash>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Output<CS::Hash>> = [Output<CS::Hash>; N]>>,
	{
		internal::batch_evaluate::<CS, N>(
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
	/// - [`Error::InfoLength`] if the given `info` exceeds a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInput`] if a given input can never produce a valid
	///   output.
	/// - [`Error::InputLength`] if a given input exceeds a length of
	///   [`u16::MAX`].
	#[cfg(feature = "alloc")]
	pub fn batch_alloc_evaluate(
		&self,
		inputs: &[&[&[u8]]],
		info: &[u8],
	) -> Result<Vec<Output<CS::Hash>>> {
		internal::batch_alloc_evaluate::<CS>(
			Mode::Poprf,
			self.t_inverted,
			inputs,
			Some(Info::new(info)?),
		)
	}
}

/// Returned from [`PoprfClient::blind()`].
pub struct PoprfBlindResult<CS: CipherSuite> {
	/// The [`PoprfClient`].
	pub client: PoprfClient<CS>,
	/// The [`BlindedElement`].
	pub blinded_element: BlindedElement<CS>,
}

/// Returned from [`PoprfClient::batch_blind()`].
pub struct PoprfBatchBlindResult<CS: CipherSuite, const N: usize> {
	/// The [`PoprfClient`]s.
	pub clients: [PoprfClient<CS>; N],
	/// The [`BlindedElement`]s each corresponding to a [`PoprfClient`] in
	/// order.
	pub blinded_elements: [BlindedElement<CS>; N],
}

/// Returned from [`PoprfClient::batch_alloc_blind()`].
#[cfg(feature = "alloc")]
pub struct PoprfBatchAllocBlindResult<CS: CipherSuite> {
	/// The [`PoprfClient`]s.
	pub clients: Vec<PoprfClient<CS>>,
	/// The [`BlindedElement`]s each corresponding to a [`PoprfClient`] in
	/// order.
	pub blinded_elements: Vec<BlindedElement<CS>>,
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Clone for PoprfClient<CS> {
	fn clone(&self) -> Self {
		Self {
			blind: self.blind,
			blinded_element: self.blinded_element.clone(),
		}
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for PoprfClient<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfClient")
			.field("blind", &self.blind)
			.field("blinded_element", &self.blinded_element)
			.finish()
	}
}

#[cfg(feature = "serde")]
impl<'de, CS> Deserialize<'de> for PoprfClient<CS>
where
	CS: CipherSuite,
	NonZeroScalar<CS>: Deserialize<'de>,
{
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		let (blind, wrapper): (_, ElementWrapper<CS::Group>) =
			serde::struct_2(deserializer, "PoprfClient", &["blind", "blinded_element"])?;
		let blinded_element = BlindedElement::from(wrapper);

		Ok(Self {
			blind,
			blinded_element,
		})
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Drop for PoprfClient<CS> {
	fn drop(&mut self) {
		self.blind.zeroize();
	}
}

impl<CS: CipherSuite> Eq for PoprfClient<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> PartialEq for PoprfClient<CS> {
	fn eq(&self, other: &Self) -> bool {
		self.blind.eq(&other.blind) && self.blinded_element.eq(&other.blinded_element)
	}
}

#[cfg(feature = "serde")]
impl<CS> Serialize for PoprfClient<CS>
where
	CS: CipherSuite,
	NonZeroScalar<CS>: Serialize,
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

impl<CS: CipherSuite> ZeroizeOnDrop for PoprfClient<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Clone for PoprfServer<CS> {
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
impl<CS: CipherSuite> Debug for PoprfServer<CS> {
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
impl<CS: CipherSuite> Drop for PoprfServer<CS> {
	fn drop(&mut self) {
		self.t.zeroize();
		self.t_inverted.zeroize();
	}
}

#[cfg(feature = "serde")]
impl<'de, CS> Deserialize<'de> for PoprfServer<CS>
where
	CS: CipherSuite,
	NonZeroScalar<CS>: Deserialize<'de>,
{
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		let (scalar, t) = serde::struct_2(deserializer, "PoprfServer", &["secret_key", "t"])?;
		let secret_key = SecretKey::new(scalar);
		let key_pair = KeyPair::from_secret_key(secret_key);
		let t_inverted = CS::Group::scalar_invert(&t);
		let tweaked_key = CS::Group::non_zero_scalar_mul_by_generator(&t);
		let tweaked_key = PublicKey::new(tweaked_key);

		Ok(Self {
			key_pair,
			t,
			t_inverted,
			tweaked_key,
		})
	}
}

impl<CS: CipherSuite> Eq for PoprfServer<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> PartialEq for PoprfServer<CS> {
	fn eq(&self, other: &Self) -> bool {
		self.key_pair.eq(&other.key_pair) & self.t.eq(&other.t)
	}
}

#[cfg(feature = "serde")]
impl<CS> Serialize for PoprfServer<CS>
where
	CS: CipherSuite,
	NonZeroScalar<CS>: Serialize,
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

impl<CS: CipherSuite> ZeroizeOnDrop for PoprfServer<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for PoprfBlindResult<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfBlindResult")
			.field("client", &self.client)
			.field("blinded_element", &self.blinded_element)
			.finish()
	}
}

impl<CS: CipherSuite> ZeroizeOnDrop for PoprfBlindResult<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite, const N: usize> Debug for PoprfBatchBlindResult<CS, N> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfBatchBlindResult")
			.field("clients", &self.clients)
			.field("blinded_elements", &self.blinded_elements)
			.finish()
	}
}

impl<CS: CipherSuite, const N: usize> ZeroizeOnDrop for PoprfBatchBlindResult<CS, N> {}

#[cfg(feature = "alloc")]
#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for PoprfBatchAllocBlindResult<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfBatchAllocBlindResult")
			.field("clients", &self.clients)
			.field("blinded_elements", &self.blinded_elements)
			.finish()
	}
}

#[cfg(feature = "alloc")]
impl<CS: CipherSuite> ZeroizeOnDrop for PoprfBatchAllocBlindResult<CS> {}
