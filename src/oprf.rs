//! OPRF implementation as per
//! [RFC 9497 § 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#name-oprf-protocol).

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::array;
use core::fmt::{self, Debug, Formatter};

#[cfg(feature = "serde")]
use ::serde::{Deserialize, Deserializer, Serialize, Serializer};
use digest::Output;
use hybrid_array::{ArraySize, AssocArraySize};
use rand_core::TryCryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cipher_suite::{CipherSuite, Element, NonIdentityElement, NonZeroScalar};
use crate::common::{BlindedElement, EvaluationElement, Mode};
use crate::error::{Error, Result};
#[cfg(feature = "alloc")]
use crate::internal::AllocBlindResult;
use crate::internal::{self, BlindResult};
use crate::key::SecretKey;
#[cfg(feature = "serde")]
use crate::serde;
use crate::util::CollectArray;

/// OPRF client.
///
/// See [RFC 9497 § 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#name-oprf-protocol).
pub struct OprfClient<Cs: CipherSuite> {
	/// `blind`.
	blind: NonZeroScalar<Cs>,
}

impl<Cs: CipherSuite> OprfClient<Cs> {
	/// Blinds the given `input`.
	///
	/// Corresponds to
	/// [`Blind()` in RFC 9497 § 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-2).
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
	pub fn blind<R>(rng: &mut R, input: &[&[u8]]) -> Result<OprfBlindResult<Cs>, Error<R::Error>>
	where
		R: ?Sized + TryCryptoRng,
	{
		let OprfBatchBlindResult {
			clients: [client],
			blinded_elements: [blinded_element],
		} = Self::batch_blind(rng, &[input])?;

		Ok(OprfBlindResult {
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
	) -> Result<OprfBatchBlindResult<Cs, N>, Error<R::Error>>
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
		} = internal::batch_blind(Mode::Oprf, rng, inputs)?;

		let clients = blinds
			.into_iter()
			.map(|blind| Self { blind })
			.collect_array();

		Ok(OprfBatchBlindResult {
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
	) -> Result<OprfBatchAllocBlindResult<Cs>, Error<R::Error>>
	where
		R: ?Sized + TryCryptoRng,
		I: ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
	{
		let AllocBlindResult {
			blinds,
			blinded_elements,
		} = internal::batch_alloc_blind(Mode::Oprf, rng, inputs)?;

		let clients = blinds.into_iter().map(|blind| Self { blind }).collect();

		Ok(OprfBatchAllocBlindResult {
			clients,
			blinded_elements,
		})
	}

	/// Completes the evaluation.
	///
	/// Corresponds to
	/// [`Finalize()` in RFC 9497 § 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7).
	///
	/// # Errors
	///
	/// Returns [`Error::InputLength`] if the given `input` exceeds a length of
	/// [`u16::MAX`].
	pub fn finalize(
		&self,
		input: &[&[u8]],
		evaluation_element: &EvaluationElement<Cs>,
	) -> Result<Output<Cs::Hash>> {
		let [output] = Self::batch_finalize(
			array::from_ref(self),
			&[input],
			array::from_ref(evaluation_element),
		)?;
		Ok(output)
	}

	/// Batch completes evaluations *without allocation*.
	///
	/// It is expected that a part of the computation is as efficient as
	/// [`finalize()`](Self::finalize)ing a single [`EvaluationElement`].
	///
	/// # Errors
	///
	/// Returns [`Error::InputLength`] if a given input exceeds a length of
	/// [`u16::MAX`].
	pub fn batch_finalize<const N: usize>(
		clients: &[Self; N],
		inputs: &[&[&[u8]]; N],
		evaluation_elements: &[EvaluationElement<Cs>; N],
	) -> Result<[Output<Cs::Hash>; N]>
	where
		[Output<Cs::Hash>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Output<Cs::Hash>> = [Output<Cs::Hash>; N]>>,
	{
		let blinds = clients.iter().map(|client| client.blind).collect_array();
		let evaluation_elements = evaluation_elements
			.iter()
			.map(EvaluationElement::as_element);

		internal::batch_finalize::<Cs, N>(inputs, blinds, evaluation_elements, None)
	}

	/// Batch completes evaluations.
	///
	/// It is expected that a part of the computation is as efficient as
	/// [`finalize()`](Self::finalize)ing a single [`EvaluationElement`].
	///
	/// # Errors
	///
	/// - [`Error::Batch`] if the number of items in `clients`,`inputs` and
	///   `evaluation_elements` don't match.
	/// - [`Error::InputLength`] if a given input exceeds a length of
	///   [`u16::MAX`].
	#[cfg(feature = "alloc")]
	pub fn batch_alloc_finalize<'clients, 'inputs, 'evaluation_elements, Ic, Ii, Iee>(
		clients: Ic,
		inputs: Ii,
		evaluation_elements: Iee,
	) -> Result<Vec<Output<Cs::Hash>>>
	where
		Ic: ExactSizeIterator<Item = &'clients Self>,
		Ii: ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
		Iee: ExactSizeIterator<Item = &'evaluation_elements EvaluationElement<Cs>>,
	{
		let length = clients.len();

		if length != inputs.len() || length != evaluation_elements.len() {
			return Err(Error::Batch);
		}

		let blinds = clients.map(|client| client.blind).collect();
		let evaluation_elements = evaluation_elements.map(EvaluationElement::as_element);

		internal::batch_alloc_finalize::<Cs>(length, inputs, blinds, evaluation_elements, None)
	}
}

/// OPRF server.
///
/// See [RFC 9497 § 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#name-oprf-protocol).
pub struct OprfServer<Cs: CipherSuite> {
	/// [`SecretKey`].
	secret_key: SecretKey<Cs::Group>,
}

impl<Cs: CipherSuite> OprfServer<Cs> {
	/// Creates a new [`OprfServer`] by generating a random [`SecretKey`].
	///
	/// # Errors
	///
	/// Returns [`Error::Random`] if the given `rng` fails.
	pub fn new<R>(rng: &mut R) -> Result<Self, R::Error>
	where
		R: ?Sized + TryCryptoRng,
	{
		Ok(Self {
			secret_key: SecretKey::generate(rng)?,
		})
	}

	/// Creates a new [`OprfServer`] by deterministically mapping the input to a
	/// [`SecretKey`].
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
			secret_key: SecretKey::derive::<Cs>(Mode::Oprf, seed, info)?,
		})
	}

	/// Creates a new [`OprfServer`] from the given [`SecretKey`].
	#[must_use]
	pub const fn from_key(secret_key: SecretKey<Cs::Group>) -> Self {
		Self { secret_key }
	}

	/// Returns the [`SecretKey`].
	#[must_use]
	pub const fn secret_key(&self) -> &SecretKey<Cs::Group> {
		&self.secret_key
	}

	/// Process the [`BlindedElement`].
	///
	/// Corresponds to
	/// [`BlindEvaluate()` in RFC 9497 § 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-4).
	#[must_use]
	pub fn blind_evaluate(&self, blinded_element: &BlindedElement<Cs>) -> EvaluationElement<Cs> {
		let [evaluation_element] = self.batch_blind_evaluate(array::from_ref(blinded_element));
		evaluation_element
	}

	/// Batch process the [`BlindedElement`]s *without allocation*.
	///
	/// It is expected that a part of the computation is as efficient as
	/// [`blind_evaluate()`](Self::blind_evaluate)ing a single
	/// [`BlindedElement`].
	#[must_use]
	pub fn batch_blind_evaluate<const N: usize>(
		&self,
		blinded_elements: &[BlindedElement<Cs>; N],
	) -> [EvaluationElement<Cs>; N] {
		let elements_and_scalars = blinded_elements
			.iter()
			.map(|blinded_element| (*blinded_element.as_element(), self.secret_key.to_scalar()));
		EvaluationElement::new_batch(elements_and_scalars)
	}

	/// Batch process the [`BlindedElement`]s.
	///
	/// It is expected that a part of the computation is as efficient as
	/// [`blind_evaluate()`](Self::blind_evaluate)ing a single
	/// [`BlindedElement`].
	#[must_use]
	#[cfg(feature = "alloc")]
	pub fn batch_alloc_blind_evaluate<'blinded_elements, I>(
		&self,
		blinded_elements: I,
	) -> Vec<EvaluationElement<Cs>>
	where
		I: ExactSizeIterator<Item = &'blinded_elements BlindedElement<Cs>>,
	{
		let elements_and_scalars = blinded_elements
			.map(|blinded_element| (*blinded_element.as_element(), self.secret_key.to_scalar()));
		EvaluationElement::new_batch_alloc(elements_and_scalars)
	}

	/// Completes the evaluation.
	///
	/// Corresponds to
	/// [`Evaluate()` in RFC 9497 § 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-9).
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
	pub fn evaluate(&self, input: &[&[u8]]) -> Result<Output<Cs::Hash>> {
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
	) -> Result<[Output<Cs::Hash>; N]>
	where
		[Element<Cs>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Element<Cs>> = [Element<Cs>; N]>>,
		[Output<Cs::Hash>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Output<Cs::Hash>> = [Output<Cs::Hash>; N]>>,
	{
		internal::batch_evaluate::<Cs, N>(Mode::Oprf, self.secret_key.to_scalar(), inputs, None)
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
	pub fn batch_alloc_evaluate(&self, inputs: &[&[&[u8]]]) -> Result<Vec<Output<Cs::Hash>>> {
		internal::batch_alloc_evaluate::<Cs>(Mode::Oprf, self.secret_key.to_scalar(), inputs, None)
	}
}

/// Returned from [`OprfClient::blind()`].
pub struct OprfBlindResult<Cs: CipherSuite> {
	/// The [`OprfClient`].
	pub client: OprfClient<Cs>,
	/// The [`BlindedElement`].
	pub blinded_element: BlindedElement<Cs>,
}

/// Returned from [`OprfClient::batch_blind()`].
pub struct OprfBatchBlindResult<Cs: CipherSuite, const N: usize> {
	/// The [`OprfClient`]s.
	pub clients: [OprfClient<Cs>; N],
	/// The [`BlindedElement`]s each corresponding to a [`OprfClient`] in order.
	pub blinded_elements: [BlindedElement<Cs>; N],
}

/// Returned from [`OprfClient::batch_alloc_blind()`].
#[cfg(feature = "alloc")]
pub struct OprfBatchAllocBlindResult<Cs: CipherSuite> {
	/// The [`OprfClient`]s.
	pub clients: Vec<OprfClient<Cs>>,
	/// The [`BlindedElement`]s each corresponding to a [`OprfClient`] in order.
	pub blinded_elements: Vec<BlindedElement<Cs>>,
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Clone for OprfClient<Cs> {
	fn clone(&self) -> Self {
		Self { blind: self.blind }
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Debug for OprfClient<Cs> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("OprfClient")
			.field("blind", &self.blind)
			.finish()
	}
}

#[cfg(feature = "serde")]
impl<'de, Cs> Deserialize<'de> for OprfClient<Cs>
where
	Cs: CipherSuite,
	NonZeroScalar<Cs>: Deserialize<'de>,
{
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		serde::newtype_struct(deserializer, "OprfClient").map(|blind| Self { blind })
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Drop for OprfClient<Cs> {
	fn drop(&mut self) {
		self.blind.zeroize();
	}
}

impl<Cs: CipherSuite> Eq for OprfClient<Cs> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> PartialEq for OprfClient<Cs> {
	fn eq(&self, other: &Self) -> bool {
		self.blind.eq(&other.blind)
	}
}

#[cfg(feature = "serde")]
impl<Cs> Serialize for OprfClient<Cs>
where
	Cs: CipherSuite,
	NonZeroScalar<Cs>: Serialize,
{
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_newtype_struct("OprfClient", &self.blind)
	}
}

impl<Cs: CipherSuite> ZeroizeOnDrop for OprfClient<Cs> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Clone for OprfServer<Cs> {
	fn clone(&self) -> Self {
		Self {
			secret_key: self.secret_key.clone(),
		}
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Debug for OprfServer<Cs> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("OprfServer")
			.field("secret_key", &self.secret_key)
			.finish()
	}
}

#[cfg(feature = "serde")]
impl<'de, Cs> Deserialize<'de> for OprfServer<Cs>
where
	Cs: CipherSuite,
	NonZeroScalar<Cs>: Deserialize<'de>,
{
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		serde::newtype_struct(deserializer, "OprfServer")
			.map(SecretKey::new)
			.map(|secret_key| Self { secret_key })
	}
}

impl<Cs: CipherSuite> Eq for OprfServer<Cs> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> PartialEq for OprfServer<Cs> {
	fn eq(&self, other: &Self) -> bool {
		self.secret_key.eq(&other.secret_key)
	}
}

#[cfg(feature = "serde")]
impl<Cs> Serialize for OprfServer<Cs>
where
	Cs: CipherSuite,
	NonZeroScalar<Cs>: Serialize,
{
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_newtype_struct("OprfServer", self.secret_key.as_scalar())
	}
}

impl<Cs: CipherSuite> ZeroizeOnDrop for OprfServer<Cs> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Debug for OprfBlindResult<Cs> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("OprfBlindResult")
			.field("client", &self.client)
			.field("blinded_element", &self.blinded_element)
			.finish()
	}
}

impl<Cs: CipherSuite> ZeroizeOnDrop for OprfBlindResult<Cs> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite, const N: usize> Debug for OprfBatchBlindResult<Cs, N> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("OprfBatchBlindResult")
			.field("clients", &self.clients)
			.field("blinded_elements", &self.blinded_elements)
			.finish()
	}
}

impl<Cs: CipherSuite, const N: usize> ZeroizeOnDrop for OprfBatchBlindResult<Cs, N> {}

#[cfg(feature = "alloc")]
#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Debug for OprfBatchAllocBlindResult<Cs> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("OprfBatchAllocBlindResult")
			.field("clients", &self.clients)
			.field("blinded_elements", &self.blinded_elements)
			.finish()
	}
}

#[cfg(feature = "alloc")]
impl<Cs: CipherSuite> ZeroizeOnDrop for OprfBatchAllocBlindResult<Cs> {}
