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

use crate::cipher_suite::{CipherSuite, NonIdentityElement, NonZeroScalar};
use crate::common::{BlindedElement, EvaluationElement, Mode};
use crate::error::{Error, Result};
#[cfg(feature = "alloc")]
use crate::internal::BatchVecBlindResult;
use crate::internal::{self, BatchBlindResult};
use crate::key::SecretKey;
#[cfg(feature = "serde")]
use crate::serde;
use crate::util::CollectArray;

pub struct OprfClient<CS: CipherSuite> {
	blind: NonZeroScalar<CS>,
}

impl<CS: CipherSuite> OprfClient<CS> {
	// `Blind`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-2
	pub fn blind<R>(rng: &mut R, input: &[&[u8]]) -> Result<OprfBlindResult<CS>, Error<R::Error>>
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

	// `Blind`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-2
	pub fn batch_blind<R, const N: usize>(
		rng: &mut R,
		inputs: &[&[&[u8]]; N],
	) -> Result<OprfBatchBlindResult<CS, N>, Error<R::Error>>
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

	// `Blind`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-2
	#[cfg(feature = "alloc")]
	pub fn batch_vec_blind<'inputs, R, I>(
		rng: &mut R,
		inputs: I,
	) -> Result<OprfBatchVecBlindResult<CS>, Error<R::Error>>
	where
		R: ?Sized + TryCryptoRng,
		I: Iterator<Item = &'inputs [&'inputs [u8]]>,
	{
		let BatchVecBlindResult {
			blinds,
			blinded_elements,
		} = internal::batch_vec_blind(Mode::Oprf, rng, inputs)?;

		let clients = blinds.into_iter().map(|blind| Self { blind }).collect();

		Ok(OprfBatchVecBlindResult {
			clients,
			blinded_elements,
		})
	}

	// `Finalize`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7
	pub fn finalize(
		&self,
		input: &[&[u8]],
		evaluation_element: &EvaluationElement<CS>,
	) -> Result<Output<CS::Hash>> {
		let [output] = Self::batch_finalize(
			array::from_ref(self),
			&[input],
			array::from_ref(evaluation_element),
		)?;
		Ok(output)
	}

	// `Finalize`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7
	pub fn batch_finalize<const N: usize>(
		clients: &[Self; N],
		inputs: &[&[&[u8]]; N],
		evaluation_elements: &[EvaluationElement<CS>; N],
	) -> Result<[Output<CS::Hash>; N]>
	where
		[Output<CS::Hash>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Output<CS::Hash>> = [Output<CS::Hash>; N]>>,
	{
		let blinds = clients.iter().map(|client| client.blind).collect_array();
		let evaluation_elements = evaluation_elements
			.iter()
			.map(EvaluationElement::as_element);

		internal::batch_finalize::<CS, N>(inputs, blinds, evaluation_elements, None)
	}

	// `Finalize`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7
	#[cfg(feature = "alloc")]
	pub fn batch_vec_finalize<'clients, 'inputs, 'evaluation_elements, IC, II, IEE>(
		clients: IC,
		inputs: II,
		evaluation_elements: IEE,
	) -> Result<Vec<Output<CS::Hash>>>
	where
		IC: ExactSizeIterator<Item = &'clients Self>,
		II: ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
		IEE: ExactSizeIterator<Item = &'evaluation_elements EvaluationElement<CS>>,
	{
		let clients_len = clients.len();

		if clients_len != inputs.len() || clients_len != evaluation_elements.len() {
			return Err(Error::Batch);
		}

		let blinds = clients.map(|client| client.blind).collect();
		let evaluation_elements = evaluation_elements.map(EvaluationElement::as_element);

		internal::batch_vec_finalize::<CS>(inputs, blinds, evaluation_elements, None)
	}
}

pub struct OprfServer<CS: CipherSuite> {
	secret_key: SecretKey<CS::Group>,
}

impl<CS: CipherSuite> OprfServer<CS> {
	pub fn new<R>(rng: &mut R) -> Result<Self, R::Error>
	where
		R: ?Sized + TryCryptoRng,
	{
		Ok(Self {
			secret_key: SecretKey::generate(rng)?,
		})
	}

	pub fn from_seed(seed: &[u8; 32], info: &[u8]) -> Result<Self> {
		Ok(Self {
			secret_key: SecretKey::derive::<CS>(Mode::Oprf, seed, info)?,
		})
	}

	pub const fn from_key(secret_key: SecretKey<CS::Group>) -> Self {
		Self { secret_key }
	}

	pub const fn secret_key(&self) -> &SecretKey<CS::Group> {
		&self.secret_key
	}

	// `BlindEvaluate`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-4
	#[must_use]
	pub fn blind_evaluate(&self, blinded_element: &BlindedElement<CS>) -> EvaluationElement<CS> {
		let [evaluation_element] = self.batch_blind_evaluate(array::from_ref(blinded_element));
		evaluation_element
	}

	// `BlindEvaluate`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-4
	#[must_use]
	pub fn batch_blind_evaluate<const N: usize>(
		&self,
		blinded_elements: &[BlindedElement<CS>; N],
	) -> [EvaluationElement<CS>; N] {
		let elements = blinded_elements
			.iter()
			.map(|blinded_element| self.secret_key.to_scalar() * blinded_element.as_element())
			.collect_array();
		EvaluationElement::new_batch(&elements)
	}

	// `BlindEvaluate`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-4
	#[must_use]
	#[cfg(feature = "alloc")]
	pub fn batch_vec_blind_evaluate<'blinded_elements, I>(
		&self,
		blinded_elements: I,
	) -> Vec<EvaluationElement<CS>>
	where
		I: Iterator<Item = &'blinded_elements BlindedElement<CS>>,
	{
		let elements: Vec<_> = blinded_elements
			.map(|blinded_element| self.secret_key.to_scalar() * blinded_element.as_element())
			.collect();
		EvaluationElement::new_batch_vec(elements)
	}

	// `Evaluate`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-9
	pub fn evaluate(&self, input: &[&[u8]]) -> Result<Output<CS::Hash>> {
		let [output] = self.batch_evaluate(&[input])?;
		Ok(output)
	}

	// `Evaluate`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-9
	pub fn batch_evaluate<const N: usize>(
		&self,
		inputs: &[&[&[u8]]; N],
	) -> Result<[Output<CS::Hash>; N]>
	where
		[NonIdentityElement<CS>; N]: AssocArraySize<
			Size: ArraySize<ArrayType<NonIdentityElement<CS>> = [NonIdentityElement<CS>; N]>,
		>,
		[Output<CS::Hash>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Output<CS::Hash>> = [Output<CS::Hash>; N]>>,
	{
		internal::batch_evaluate::<CS, N>(Mode::Oprf, self.secret_key.to_scalar(), inputs, None)
	}

	// `Evaluate`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-9
	#[cfg(feature = "alloc")]
	pub fn batch_vec_evaluate(&self, inputs: &[&[&[u8]]]) -> Result<Vec<Output<CS::Hash>>> {
		internal::batch_vec_evaluate::<CS>(Mode::Oprf, self.secret_key.to_scalar(), inputs, None)
	}
}

pub struct OprfBlindResult<CS: CipherSuite> {
	pub client: OprfClient<CS>,
	pub blinded_element: BlindedElement<CS>,
}

pub struct OprfBatchBlindResult<CS: CipherSuite, const N: usize> {
	pub clients: [OprfClient<CS>; N],
	pub blinded_elements: [BlindedElement<CS>; N],
}

#[cfg(feature = "alloc")]
pub struct OprfBatchVecBlindResult<CS: CipherSuite> {
	pub clients: Vec<OprfClient<CS>>,
	pub blinded_elements: Vec<BlindedElement<CS>>,
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Clone for OprfClient<CS> {
	fn clone(&self) -> Self {
		Self { blind: self.blind }
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for OprfClient<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("OprfClient")
			.field("blind", &self.blind)
			.finish()
	}
}

#[cfg(feature = "serde")]
impl<'de, CS> Deserialize<'de> for OprfClient<CS>
where
	CS: CipherSuite,
	NonZeroScalar<CS>: Deserialize<'de>,
{
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		serde::newtype_struct(deserializer, "OprfClient").map(|blind| Self { blind })
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Drop for OprfClient<CS> {
	fn drop(&mut self) {
		self.blind.zeroize();
	}
}

impl<CS: CipherSuite> Eq for OprfClient<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> PartialEq for OprfClient<CS> {
	fn eq(&self, other: &Self) -> bool {
		self.blind.eq(&other.blind)
	}
}

#[cfg(feature = "serde")]
impl<CS> Serialize for OprfClient<CS>
where
	CS: CipherSuite,
	NonZeroScalar<CS>: Serialize,
{
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_newtype_struct("OprfClient", &self.blind)
	}
}

impl<CS: CipherSuite> ZeroizeOnDrop for OprfClient<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Clone for OprfServer<CS> {
	fn clone(&self) -> Self {
		Self {
			secret_key: self.secret_key.clone(),
		}
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for OprfServer<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("OprfServer")
			.field("secret_key", &self.secret_key)
			.finish()
	}
}

#[cfg(feature = "serde")]
impl<'de, CS> Deserialize<'de> for OprfServer<CS>
where
	CS: CipherSuite,
	NonZeroScalar<CS>: Deserialize<'de>,
{
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		serde::newtype_struct(deserializer, "OprfServer")
			.map(SecretKey::from_scalar)
			.map(|secret_key| Self { secret_key })
	}
}

impl<CS: CipherSuite> Eq for OprfServer<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> PartialEq for OprfServer<CS> {
	fn eq(&self, other: &Self) -> bool {
		self.secret_key.eq(&other.secret_key)
	}
}

#[cfg(feature = "serde")]
impl<CS> Serialize for OprfServer<CS>
where
	CS: CipherSuite,
	NonZeroScalar<CS>: Serialize,
{
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_newtype_struct("OprfServer", self.secret_key.as_scalar())
	}
}

impl<CS: CipherSuite> ZeroizeOnDrop for OprfServer<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for OprfBlindResult<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("OprfBlindResult")
			.field("client", &self.client)
			.field("blinded_element", &self.blinded_element)
			.finish()
	}
}

impl<CS: CipherSuite> ZeroizeOnDrop for OprfBlindResult<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite, const N: usize> Debug for OprfBatchBlindResult<CS, N> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("OprfBatchBlindResult")
			.field("clients", &self.clients)
			.field("blinded_elements", &self.blinded_elements)
			.finish()
	}
}

impl<CS: CipherSuite, const N: usize> ZeroizeOnDrop for OprfBatchBlindResult<CS, N> {}

#[cfg(feature = "alloc")]
#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for OprfBatchVecBlindResult<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("OprfBatchVecBlindResult")
			.field("clients", &self.clients)
			.field("blinded_elements", &self.blinded_elements)
			.finish()
	}
}

#[cfg(feature = "alloc")]
impl<CS: CipherSuite> ZeroizeOnDrop for OprfBatchVecBlindResult<CS> {}
