//! VOPRF implementation as per
//! [RFC 9497 § 3.3.2](https://www.rfc-editor.org/rfc/rfc9497.html#name-voprf-protocol).

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
#[cfg(feature = "alloc")]
use crate::internal::BatchAllocBlindResult;
#[cfg(feature = "serde")]
use crate::internal::ElementWrapper;
use crate::internal::{self, BatchBlindResult};
#[cfg(feature = "serde")]
use crate::key::SecretKey;
use crate::key::{KeyPair, PublicKey};
#[cfg(feature = "serde")]
use crate::serde;
use crate::util::CollectArray;

/// VOPRF client.
///
/// See [RFC 9497 § 3.3.2](https://www.rfc-editor.org/rfc/rfc9497.html#name-voprf-protocol).
pub struct VoprfClient<CS: CipherSuite> {
	blind: NonZeroScalar<CS>,
	blinded_element: BlindedElement<CS>,
}

impl<CS: CipherSuite> VoprfClient<CS> {
	/// Blinds the given `input`.
	///
	/// Corresponds to
	/// [`Blind()` in RFC 9497 § 3.3.2](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-2).
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
	pub fn blind<R>(rng: &mut R, input: &[&[u8]]) -> Result<VoprfBlindResult<CS>, Error<R::Error>>
	where
		R: ?Sized + TryCryptoRng,
	{
		let VoprfBatchBlindResult {
			clients: [client],
			blinded_elements: [blinded_element],
		} = Self::batch_blind(rng, &[input])?;

		Ok(VoprfBlindResult {
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
	) -> Result<VoprfBatchBlindResult<CS, N>, Error<R::Error>>
	where
		[NonIdentityElement<CS>; N]: AssocArraySize<
			Size: ArraySize<ArrayType<NonIdentityElement<CS>> = [NonIdentityElement<CS>; N]>,
		>,
		[NonZeroScalar<CS>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<NonZeroScalar<CS>> = [NonZeroScalar<CS>; N]>>,
		R: ?Sized + TryCryptoRng,
	{
		let BatchBlindResult {
			blinds,
			blinded_elements,
		} = internal::batch_blind(Mode::Voprf, rng, inputs)?;

		let clients = blinds
			.into_iter()
			.zip(&blinded_elements)
			.map(|(blind, blinded_element)| Self {
				blind,
				blinded_element: blinded_element.clone(),
			})
			.collect_array();

		Ok(VoprfBatchBlindResult {
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
	) -> Result<VoprfBatchAllocBlindResult<CS>, Error<R::Error>>
	where
		R: ?Sized + TryCryptoRng,
		I: Iterator<Item = &'inputs [&'inputs [u8]]>,
	{
		let BatchAllocBlindResult {
			blinds,
			blinded_elements,
		} = internal::batch_alloc_blind(Mode::Voprf, rng, inputs)?;

		let clients = blinds
			.into_iter()
			.zip(&blinded_elements)
			.map(|(blind, blinded_element)| Self {
				blind,
				blinded_element: blinded_element.clone(),
			})
			.collect();

		Ok(VoprfBatchAllocBlindResult {
			clients,
			blinded_elements,
		})
	}

	/// Completes the evaluation.
	///
	/// Corresponds to
	/// [`Finalize()` in RFC 9497 § 3.3.2](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-5).
	///
	/// # Errors
	///
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
	) -> Result<Output<CS::Hash>> {
		let [output] = Self::batch_finalize(
			array::from_ref(self),
			public_key,
			&[input],
			array::from_ref(evaluation_element),
			proof,
		)?;
		Ok(output)
	}

	/// Batch completes evaluations with a combined [`Proof`] *without
	/// allocation*.
	///
	/// See [RFC 9497 § 3.3.2](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-6).
	///
	/// # Errors
	///
	/// - [`Error::Batch`] if the number of items in `clients`,`inputs` and
	///   `evaluation_elements` are zero, don't match or exceed a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::Proof`] if the [`Proof`] is invalid.
	/// - [`Error::InputLength`] if the given `input` exceeds a length of
	///   [`u16::MAX`].
	pub fn batch_finalize<const N: usize>(
		clients: &[Self; N],
		public_key: &PublicKey<CS::Group>,
		inputs: &[&[&[u8]]; N],
		evaluation_elements: &[EvaluationElement<CS>; N],
		proof: &Proof<CS>,
	) -> Result<[Output<CS::Hash>; N]>
	where
		[Output<CS::Hash>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Output<CS::Hash>> = [Output<CS::Hash>; N]>>,
	{
		if N == 0 || N > u16::MAX.into() {
			return Err(Error::Batch);
		}

		let c = clients.iter().map(|client| client.blinded_element.as_ref());
		let d = evaluation_elements.iter().map(EvaluationElement::as_ref);

		let composites =
			internal::compute_composites::<_, N>(Mode::Voprf, None, public_key.as_ref(), c, d)?;
		internal::verify_proof(Mode::Voprf, composites, public_key.as_ref(), proof)?;

		let blinds = clients.iter().map(|client| client.blind).collect_array();
		let evaluation_elements = evaluation_elements
			.iter()
			.map(EvaluationElement::as_element);

		internal::batch_finalize::<CS, N>(inputs, blinds, evaluation_elements, None)
	}

	/// Batch completes evaluations with a combined [`Proof`].
	///
	/// See [RFC 9497 § 3.3.2](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-6).
	///
	/// # Errors
	///
	/// - [`Error::Batch`] if the number of items in `clients`,`inputs` and
	///   `evaluation_elements` are zero, don't match or exceed a length of
	///   [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
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
	) -> Result<Vec<Output<CS::Hash>>>
	where
		IC: ExactSizeIterator<Item = &'clients Self>,
		II: ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
		IEE: ExactSizeIterator<Item = &'evaluation_elements EvaluationElement<CS>>,
	{
		let clients_len = clients.len();

		if clients_len == 0
			|| clients_len != inputs.len()
			|| clients_len != evaluation_elements.len()
			|| clients_len > u16::MAX.into()
		{
			return Err(Error::Batch);
		}

		let (c, blinds): (Vec<_>, _) = clients
			.map(|client| (client.blinded_element.as_ref(), client.blind))
			.unzip();
		let d: Vec<_> = evaluation_elements.map(EvaluationElement::as_ref).collect();

		let composites = internal::alloc_compute_composites(
			Mode::Voprf,
			clients_len,
			None,
			public_key.as_ref(),
			c.into_iter(),
			d.iter().copied(),
		)?;
		internal::verify_proof(Mode::Voprf, composites, public_key.as_ref(), proof)?;

		let evaluation_elements = d.into_iter().map(ElementWrapper::as_element);

		internal::batch_alloc_finalize::<CS>(inputs, blinds, evaluation_elements, None)
	}
}

/// VOPRF server.
///
/// See [RFC 9497 § 3.3.2](https://www.rfc-editor.org/rfc/rfc9497.html#name-voprf-protocol).
pub struct VoprfServer<CS: CipherSuite> {
	key_pair: KeyPair<CS::Group>,
}

impl<CS: CipherSuite> VoprfServer<CS> {
	/// Creates a new [`VoprfServer`] by generating a random [`SecretKey`].
	///
	/// # Errors
	///
	/// Returns [`Error::Random`] if the given `rng` fails.
	pub fn new<R>(rng: &mut R) -> Result<Self, R::Error>
	where
		R: ?Sized + TryCryptoRng,
	{
		Ok(Self {
			key_pair: KeyPair::generate(rng)?,
		})
	}

	/// Creates a new [`VoprfServer`] by deterministically mapping the input to
	/// a [`SecretKey`].
	///
	/// # Errors
	///
	/// - [`Error::InfoLength`] if `info` exceeds a length of [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::DeriveKeyPair`] if a [`SecretKey`] can never be derived from
	///   the given input.
	pub fn from_seed(seed: &[u8; 32], info: &[u8]) -> Result<Self> {
		Ok(Self {
			key_pair: KeyPair::derive::<CS>(Mode::Voprf, seed, info)?,
		})
	}

	/// Creates a new [`VoprfServer`] from the given [`KeyPair`].
	#[must_use]
	pub const fn from_key_pair(key_pair: KeyPair<CS::Group>) -> Self {
		Self { key_pair }
	}

	/// Returns the [`KeyPair`].
	#[must_use]
	pub const fn key_pair(&self) -> &KeyPair<CS::Group> {
		&self.key_pair
	}

	/// Returns the [`PublicKey`].
	#[must_use]
	pub const fn public_key(&self) -> &PublicKey<CS::Group> {
		self.key_pair.public_key()
	}

	/// Process the [`BlindedElement`].
	///
	/// Corresponds to
	/// [`BlindEvaluate()` in RFC 9497 § 3.3.2](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-2).
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
	/// See [RFC 9497 § 3.3.2](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-3).
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

		let evaluation_elements =
			EvaluationElement::new_batch(blinded_elements.iter().map(|blinded_element| {
				(
					*blinded_element.as_element(),
					self.key_pair.secret_key().to_scalar(),
				)
			}));
		let c = blinded_elements.iter().map(BlindedElement::as_ref);
		let d = evaluation_elements.iter().map(EvaluationElement::as_ref);

		let composites = internal::compute_composites::<_, N>(
			Mode::Voprf,
			Some(self.key_pair.secret_key().to_scalar()),
			self.key_pair.public_key().as_ref(),
			c.into_iter(),
			d.into_iter(),
		)
		.map_err(Error::into_random::<R>)?;
		let proof = internal::generate_proof(
			Mode::Voprf,
			rng,
			self.key_pair.secret_key().to_scalar(),
			composites,
			self.key_pair.public_key().as_ref(),
		)?;

		Ok(BatchBlindEvaluateResult {
			evaluation_elements,
			proof,
		})
	}

	/// Process the [`BlindedElement`] computing a combined [`Proof`].
	///
	/// See [RFC 9497 § 3.3.2](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-3).
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

		let c: Vec<_> = blinded_elements.map(BlindedElement::as_ref).collect();
		let evaluation_elements = EvaluationElement::new_batch_alloc(c.iter().map(|element| {
			(
				*element.as_element(),
				self.key_pair.secret_key().to_scalar(),
			)
		}));
		let d = evaluation_elements.iter().map(EvaluationElement::as_ref);

		let composites = internal::alloc_compute_composites(
			Mode::Voprf,
			blinded_elements_length,
			Some(self.key_pair.secret_key().to_scalar()),
			self.key_pair.public_key().as_ref(),
			c.into_iter(),
			d,
		)
		.map_err(Error::into_random::<R>)?;
		let proof = internal::generate_proof(
			Mode::Voprf,
			rng,
			self.key_pair.secret_key().to_scalar(),
			composites,
			self.key_pair.public_key().as_ref(),
		)?;

		Ok(BatchAllocBlindEvaluateResult {
			evaluation_elements,
			proof,
		})
	}

	/// Completes the evaluation.
	///
	/// Corresponds to
	/// [`Evaluate()` in RFC 9497 § 3.3.2](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-7).
	///
	/// # Errors
	///
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInput`] if the given `input` can never produce a valid
	///   output.
	/// - [`Error::InputLength`] if the given `input` exceeds a length of
	///   [`u16::MAX`].
	pub fn evaluate(&self, input: &[&[u8]]) -> Result<Output<CS::Hash>> {
		let [output] = self.batch_evaluate(&[input])?;
		Ok(output)
	}

	/// Batch Completes evaluations *without allocation*.
	///
	/// It is expected that a part of the computation is as efficient as
	/// [`evaluate()`](Self::evaluate)ing a single `input`.
	///
	/// # Errors
	///
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
	) -> Result<[Output<CS::Hash>; N]>
	where
		[Element<CS>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Element<CS>> = [Element<CS>; N]>>,
		[Output<CS::Hash>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Output<CS::Hash>> = [Output<CS::Hash>; N]>>,
	{
		internal::batch_evaluate::<CS, N>(
			Mode::Voprf,
			self.key_pair.secret_key().to_scalar(),
			inputs,
			None,
		)
	}

	/// Batch Completes evaluations.
	///
	/// It is expected that a part of the computation is as efficient as
	/// [`evaluate()`](Self::evaluate)ing a single `input`.
	///
	/// # Errors
	///
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::InvalidInput`] if a given input can never produce a valid
	///   output.
	/// - [`Error::InputLength`] if a given input exceeds a length of
	///   [`u16::MAX`].
	#[cfg(feature = "alloc")]
	pub fn batch_alloc_evaluate(&self, inputs: &[&[&[u8]]]) -> Result<Vec<Output<CS::Hash>>> {
		internal::batch_alloc_evaluate::<CS>(
			Mode::Voprf,
			self.key_pair.secret_key().to_scalar(),
			inputs,
			None,
		)
	}
}

/// Returned from [`VoprfClient::blind()`].
pub struct VoprfBlindResult<CS: CipherSuite> {
	/// The [`VoprfClient`].
	pub client: VoprfClient<CS>,
	/// The [`BlindedElement`].
	pub blinded_element: BlindedElement<CS>,
}

/// Returned from [`VoprfClient::batch_blind()`].
pub struct VoprfBatchBlindResult<CS: CipherSuite, const N: usize> {
	/// The [`VoprfClient`]s.
	pub clients: [VoprfClient<CS>; N],
	/// The [`BlindedElement`]s each corresponding to a [`VoprfClient`] in
	/// order.
	pub blinded_elements: [BlindedElement<CS>; N],
}

/// Returned from [`VoprfClient::batch_alloc_blind()`].
#[cfg(feature = "alloc")]
pub struct VoprfBatchAllocBlindResult<CS: CipherSuite> {
	/// The [`VoprfClient`]s.
	pub clients: Vec<VoprfClient<CS>>,
	/// The [`BlindedElement`]s each corresponding to a [`VoprfClient`] in
	/// order.
	pub blinded_elements: Vec<BlindedElement<CS>>,
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Clone for VoprfClient<CS> {
	fn clone(&self) -> Self {
		Self {
			blind: self.blind,
			blinded_element: self.blinded_element.clone(),
		}
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for VoprfClient<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("VoprfClient")
			.field("blind", &self.blind)
			.field("blinded_element", &self.blinded_element)
			.finish()
	}
}

#[cfg(feature = "serde")]
impl<'de, CS> Deserialize<'de> for VoprfClient<CS>
where
	CS: CipherSuite,
	NonZeroScalar<CS>: Deserialize<'de>,
{
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		let (blind, wrapper): (_, ElementWrapper<CS::Group>) =
			serde::struct_2(deserializer, "VoprfClient", &["blind", "blinded_element"])?;
		let blinded_element = BlindedElement::from(wrapper);

		Ok(Self {
			blind,
			blinded_element,
		})
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Drop for VoprfClient<CS> {
	fn drop(&mut self) {
		self.blind.zeroize();
	}
}

impl<CS: CipherSuite> Eq for VoprfClient<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> PartialEq for VoprfClient<CS> {
	fn eq(&self, other: &Self) -> bool {
		self.blind.eq(&other.blind) && self.blinded_element.eq(&other.blinded_element)
	}
}

#[cfg(feature = "serde")]
impl<CS> Serialize for VoprfClient<CS>
where
	CS: CipherSuite,
	NonZeroScalar<CS>: Serialize,
{
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let mut state = serializer.serialize_struct("VoprfClient", 2)?;
		state.serialize_field("blind", &self.blind)?;
		state.serialize_field("blinded_element", self.blinded_element.as_ref())?;
		state.end()
	}
}

impl<CS: CipherSuite> ZeroizeOnDrop for VoprfClient<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Clone for VoprfServer<CS> {
	fn clone(&self) -> Self {
		Self {
			key_pair: self.key_pair.clone(),
		}
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for VoprfServer<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("VoprfServer")
			.field("key_pair", &self.key_pair)
			.finish()
	}
}

#[cfg(feature = "serde")]
impl<'de, CS> Deserialize<'de> for VoprfServer<CS>
where
	CS: CipherSuite,
	NonZeroScalar<CS>: Deserialize<'de>,
{
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		serde::newtype_struct(deserializer, "VoprfServer")
			.map(SecretKey::from_scalar)
			.map(KeyPair::from_secret_key)
			.map(|key_pair| Self { key_pair })
	}
}

impl<CS: CipherSuite> Eq for VoprfServer<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> PartialEq for VoprfServer<CS> {
	fn eq(&self, other: &Self) -> bool {
		self.key_pair.eq(&other.key_pair)
	}
}

#[cfg(feature = "serde")]
impl<CS> Serialize for VoprfServer<CS>
where
	CS: CipherSuite,
	NonZeroScalar<CS>: Serialize,
{
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_newtype_struct("VoprfServer", self.key_pair.secret_key().as_scalar())
	}
}

impl<CS: CipherSuite> ZeroizeOnDrop for VoprfServer<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for VoprfBlindResult<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("VoprfBlindResult")
			.field("client", &self.client)
			.field("blinded_element", &self.blinded_element)
			.finish()
	}
}

impl<CS: CipherSuite> ZeroizeOnDrop for VoprfBlindResult<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite, const N: usize> Debug for VoprfBatchBlindResult<CS, N> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("VoprfBatchBlindResult")
			.field("clients", &self.clients)
			.field("blinded_elements", &self.blinded_elements)
			.finish()
	}
}

impl<CS: CipherSuite, const N: usize> ZeroizeOnDrop for VoprfBatchBlindResult<CS, N> {}

#[cfg(feature = "alloc")]
#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for VoprfBatchAllocBlindResult<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("VoprfBatchAllocBlindResult")
			.field("clients", &self.clients)
			.field("blinded_elements", &self.blinded_elements)
			.finish()
	}
}

#[cfg(feature = "alloc")]
impl<CS: CipherSuite> ZeroizeOnDrop for VoprfBatchAllocBlindResult<CS> {}
