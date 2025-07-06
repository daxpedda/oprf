#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::array;
use core::fmt::{self, Debug, Formatter};

#[cfg(feature = "serde")]
use ::serde::de::Error as _;
#[cfg(feature = "serde")]
use ::serde::ser::SerializeStruct;
#[cfg(feature = "serde")]
use ::serde::{Deserialize, Deserializer, Serialize, Serializer};
use digest::Output;
use hybrid_array::{ArraySize, AssocArraySize};
use rand_core::TryCryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "serde")]
use crate::cipher_suite::ElementLength;
use crate::cipher_suite::{CipherSuite, NonIdentityElement, NonZeroScalar};
#[cfg(feature = "alloc")]
use crate::common::BatchVecBlindEvaluateResult;
use crate::common::{
	BatchBlindEvaluateResult, BlindEvaluateResult, BlindedElement, EvaluationElement, Mode, Proof,
};
use crate::error::{Error, Result};
use crate::group::{Group, InternalGroup};
#[cfg(feature = "alloc")]
use crate::internal::BatchVecBlindResult;
use crate::internal::{self, BatchBlindResult, ElementWrapper, Info};
#[cfg(feature = "serde")]
use crate::key::SecretKey;
use crate::key::{KeyPair, PublicKey};
#[cfg(feature = "serde")]
use crate::serde::{self, DeserializeWrapper, SerializeWrapper};
use crate::util::CollectArray;

pub struct PoprfClient<CS: CipherSuite> {
	blind: NonZeroScalar<CS>,
	blinded_element: BlindedElement<CS>,
}

impl<CS: CipherSuite> PoprfClient<CS> {
	// `Blind`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-2
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

	// `Blind`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-2
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
		let BatchBlindResult {
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

	// `Blind`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-2
	#[cfg(feature = "alloc")]
	pub fn batch_vec_blind<'inputs, R, I>(
		rng: &mut R,
		inputs: I,
	) -> Result<PoprfBatchVecBlindResult<CS>, Error<R::Error>>
	where
		R: ?Sized + TryCryptoRng,
		I: Iterator<Item = &'inputs [&'inputs [u8]]>,
	{
		let BatchVecBlindResult {
			blinds,
			blinded_elements,
		} = internal::batch_vec_blind(Mode::Poprf, rng, inputs)?;

		let clients = blinds
			.into_iter()
			.zip(&blinded_elements)
			.map(|(blind, blinded_element)| Self {
				blind,
				blinded_element: blinded_element.clone(),
			})
			.collect();

		Ok(PoprfBatchVecBlindResult {
			clients,
			blinded_elements,
		})
	}

	// `Finalize`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-8
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

	// `Finalize`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-8
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-9
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

		let c = evaluation_elements.iter().map(ElementWrapper::from);
		let d = clients
			.iter()
			.map(|client| ElementWrapper::from(&client.blinded_element));

		internal::verify_proof(Mode::Poprf, ElementWrapper::from(&tweaked_key), c, d, proof)?;

		let blinds = clients.iter().map(|client| client.blind).collect_array();
		let evaluation_elements = evaluation_elements.iter().map(EvaluationElement::element);

		internal::batch_finalize::<CS, N>(inputs, blinds, evaluation_elements, Some(info))
	}

	// `Finalize`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-8
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-9
	#[cfg(feature = "alloc")]
	pub fn batch_vec_finalize<'clients, 'inputs, 'evaluation_elements, IC, II, IEE>(
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
		let clients_len = clients.len();

		if clients_len == 0
			|| clients_len != inputs.len()
			|| clients_len != evaluation_elements.len()
			|| clients_len > u16::MAX.into()
		{
			return Err(Error::Batch);
		}

		let info = Info::new(info)?;
		let tweaked_key = Self::tweaked_key(public_key, info)?;

		let c: Vec<_> = evaluation_elements.map(ElementWrapper::from).collect();
		let (d, blinds): (Vec<_>, _) = clients
			.map(|client| (ElementWrapper::from(&client.blinded_element), client.blind))
			.unzip();

		internal::verify_proof(
			Mode::Poprf,
			ElementWrapper::from(&tweaked_key),
			c.iter().copied(),
			d.into_iter(),
			proof,
		)?;

		let evaluation_elements = c.into_iter().map(ElementWrapper::element);

		internal::batch_vec_finalize::<CS>(inputs, blinds, evaluation_elements, Some(info))
	}

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

		Ok(PublicKey::from_element(element))
	}
}

pub struct PoprfServer<CS: CipherSuite> {
	key_pair: KeyPair<CS::Group>,
	t: NonZeroScalar<CS>,
	t_inverted: NonZeroScalar<CS>,
	tweaked_key: PublicKey<CS::Group>,
}

impl<CS: CipherSuite> PoprfServer<CS> {
	pub fn new<R>(rng: &mut R, info: &[u8]) -> Result<Self, Error<R::Error>>
	where
		R: ?Sized + TryCryptoRng,
	{
		let key_pair = KeyPair::generate(rng).map_err(Error::Random)?;
		Self::from_key_pair(key_pair, info).map_err(Error::into_random::<R>)
	}

	pub fn from_seed(seed: &[u8; 32], key_info: &[u8], info: &[u8]) -> Result<Self> {
		let key_pair = KeyPair::derive::<CS>(Mode::Poprf, seed, key_info)?;
		Self::from_key_pair(key_pair, info)
	}

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
		let tweaked_key = PublicKey::from_element(tweaked_key);

		Ok(Self {
			key_pair,
			t,
			t_inverted,
			tweaked_key,
		})
	}

	pub const fn key_pair(&self) -> &KeyPair<CS::Group> {
		&self.key_pair
	}

	pub const fn public_key(&self) -> &PublicKey<CS::Group> {
		self.key_pair.public_key()
	}

	// `BlindEvaluate`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-4
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

	// `BlindEvaluate` batched
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-4
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-5
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
			&blinded_elements
				.iter()
				.map(|blinded_element| self.t_inverted * blinded_element.element())
				.collect_array(),
		);
		let c = evaluation_elements.iter().map(ElementWrapper::from);
		let d = blinded_elements.iter().map(ElementWrapper::from);

		let proof = internal::generate_proof(
			Mode::Poprf,
			rng,
			self.t,
			ElementWrapper::from(&self.tweaked_key),
			c,
			d,
		)?;

		Ok(BatchBlindEvaluateResult {
			evaluation_elements,
			proof,
		})
	}

	// `BlindEvaluate` batched
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-4
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-5
	#[cfg(feature = "alloc")]
	pub fn batch_vec_blind_evaluate<'blinded_elements, R, I>(
		&self,
		rng: &mut R,
		blinded_elements: I,
	) -> Result<BatchVecBlindEvaluateResult<CS>, Error<R::Error>>
	where
		R: ?Sized + TryCryptoRng,
		I: ExactSizeIterator<Item = &'blinded_elements BlindedElement<CS>>,
	{
		let blinded_elements_length = blinded_elements.len();

		if blinded_elements_length == 0 || blinded_elements_length > u16::MAX.into() {
			return Err(Error::Batch);
		}

		let d: Vec<_> = blinded_elements.map(ElementWrapper::from).collect();
		let evaluation_elements = EvaluationElement::new_batch_vec(
			d.iter()
				.map(|element| self.t_inverted * element.element())
				.collect(),
		);
		let c = evaluation_elements.iter().map(ElementWrapper::from);

		let proof = internal::generate_proof(
			Mode::Poprf,
			rng,
			self.t,
			ElementWrapper::from(&self.tweaked_key),
			c.into_iter(),
			d.into_iter(),
		)?;

		Ok(BatchVecBlindEvaluateResult {
			evaluation_elements,
			proof,
		})
	}

	// `Evaluate`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-11
	pub fn evaluate(&self, input: &[&[u8]], info: &[u8]) -> Result<Output<CS::Hash>> {
		let [output] = self.batch_evaluate(&[input], info)?;
		Ok(output)
	}

	// `Evaluate`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-7
	pub fn batch_evaluate<const N: usize>(
		&self,
		inputs: &[&[&[u8]]; N],
		info: &[u8],
	) -> Result<[Output<CS::Hash>; N]>
	where
		[NonIdentityElement<CS>; N]: AssocArraySize<
			Size: ArraySize<ArrayType<NonIdentityElement<CS>> = [NonIdentityElement<CS>; N]>,
		>,
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

	// `Evaluate`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-7
	#[cfg(feature = "alloc")]
	pub fn batch_vec_evaluate(
		&self,
		inputs: &[&[&[u8]]],
		info: &[u8],
	) -> Result<Vec<Output<CS::Hash>>> {
		internal::batch_vec_evaluate::<CS>(
			Mode::Poprf,
			self.t_inverted,
			inputs,
			Some(Info::new(info)?),
		)
	}
}

pub struct PoprfBlindResult<CS: CipherSuite> {
	pub client: PoprfClient<CS>,
	pub blinded_element: BlindedElement<CS>,
}

pub struct PoprfBatchBlindResult<CS: CipherSuite, const N: usize> {
	pub clients: [PoprfClient<CS>; N],
	pub blinded_elements: [BlindedElement<CS>; N],
}

#[cfg(feature = "alloc")]
pub struct PoprfBatchVecBlindResult<CS: CipherSuite> {
	pub clients: Vec<PoprfClient<CS>>,
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
		let (blind, DeserializeWrapper::<ElementLength<CS>>(blinded_element)) =
			serde::struct_2(deserializer, "PoprfClient", &["blind", "blinded_element"])?;
		let blinded_element =
			BlindedElement::from_array(blinded_element).map_err(D::Error::custom)?;

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
		state.serialize_field(
			"blinded_element",
			&SerializeWrapper(self.blinded_element.as_repr()),
		)?;
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
		let secret_key = SecretKey::from_scalar(scalar);
		let key_pair = KeyPair::from_secret_key(secret_key);
		let t_inverted = CS::Group::scalar_invert(&t);
		let tweaked_key = CS::Group::non_zero_scalar_mul_by_generator(&t);
		let tweaked_key = PublicKey::from_element(tweaked_key);

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
impl<CS: CipherSuite> Debug for PoprfBatchVecBlindResult<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfBatchVecBlindResult")
			.field("clients", &self.clients)
			.field("blinded_elements", &self.blinded_elements)
			.finish()
	}
}

#[cfg(feature = "alloc")]
impl<CS: CipherSuite> ZeroizeOnDrop for PoprfBatchVecBlindResult<CS> {}
