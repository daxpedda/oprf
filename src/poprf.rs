#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt::{self, Debug, Formatter};
use core::ops::Deref;
use core::{array, iter};

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
use crate::ciphersuite::ElementLength;
use crate::ciphersuite::{CipherSuite, NonIdentityElement, NonZeroScalar};
use crate::common::{BlindedElement, EvaluationElement, Mode, Proof};
use crate::error::{Error, Result};
use crate::group::{Group, InternalGroup};
use crate::internal::{self, BlindResult, ElementWrapper, Info};
#[cfg(any(feature = "serde", test))]
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
	pub fn blind<R: TryCryptoRng>(
		rng: &mut R,
		input: &[&[u8]],
	) -> Result<PoprfBlindResult<CS>, Error<R::Error>> {
		let BlindResult {
			blind,
			blinded_element,
		} = internal::blind(Mode::Poprf, rng, input)?;

		Ok(PoprfBlindResult {
			client: Self {
				blind,
				blinded_element: blinded_element.clone(),
			},
			blinded_element,
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
		let [output] = Self::batch_finalize_fixed(
			array::from_ref(self),
			public_key,
			iter::once(input),
			array::from_ref(evaluation_element),
			proof,
			info,
		)?;
		Ok(output)
	}

	// `Finalize`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-8
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-9
	#[cfg(feature = "alloc")]
	pub fn batch_finalize<'clients, 'inputs, 'evaluation_elements, IC, II, IEE>(
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
			.map(|client| {
				(
					ElementWrapper::from(&client.blinded_element),
					client.blind.into(),
				)
			})
			.unzip();

		internal::verify_proof(
			Mode::Poprf,
			ElementWrapper::from(&tweaked_key),
			c.iter().copied(),
			d.into_iter(),
			proof,
		)?;

		let evaluation_elements = c.into_iter().map(|element| element.element().deref());

		internal::batch_finalize::<CS>(inputs, blinds, evaluation_elements, Some(info))
	}

	// `Finalize`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-8
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-9
	pub fn batch_finalize_fixed<'inputs, I, const N: usize>(
		clients: &[Self; N],
		public_key: &PublicKey<CS::Group>,
		inputs: I,
		evaluation_elements: &[EvaluationElement<CS>; N],
		proof: &Proof<CS>,
		info: &[u8],
	) -> Result<[Output<CS::Hash>; N]>
	where
		[Output<CS::Hash>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Output<CS::Hash>> = [Output<CS::Hash>; N]>>,
		I: ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
	{
		if N == 0 || N != inputs.len() || N > u16::MAX.into() {
			return Err(Error::Batch);
		}

		let info = Info::new(info)?;
		let tweaked_key = Self::tweaked_key(public_key, info)?;

		let c = evaluation_elements.iter().map(ElementWrapper::from);
		let d = clients
			.iter()
			.map(|client| ElementWrapper::from(&client.blinded_element));

		internal::verify_proof(Mode::Poprf, ElementWrapper::from(&tweaked_key), c, d, proof)?;

		let blinds = clients
			.iter()
			.map(|client| client.blind.into())
			.collect_array();
		let evaluation_elements = evaluation_elements
			.iter()
			.map(|evaluation_element| evaluation_element.element().deref());

		internal::batch_finalize_fixed::<N, CS>(inputs, blinds, evaluation_elements, Some(info))
	}

	fn tweaked_key(
		public_key: &PublicKey<CS::Group>,
		info: Info<'_>,
	) -> Result<PublicKey<CS::Group>> {
		let framed_info = [b"Info".as_slice(), info.i2osp(), info.info()];
		let m = CS::hash_to_scalar(Mode::Poprf, &framed_info, None);
		let t = CS::Group::scalar_mul_by_generator(&m);
		let element = (t + public_key.as_point())
			.try_into()
			.map_err(|_| Error::InvalidInfo)?;

		Ok(PublicKey::from_point(element))
	}
}

pub struct PoprfServer<CS: CipherSuite> {
	key_pair: KeyPair<CS::Group>,
	t: NonZeroScalar<CS>,
	t_inverted: NonZeroScalar<CS>,
	tweaked_key: PublicKey<CS::Group>,
}

impl<CS: CipherSuite> PoprfServer<CS> {
	pub fn new<R: TryCryptoRng>(rng: &mut R, info: &[u8]) -> Result<Self, Error<R::Error>> {
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
		let m = CS::hash_to_scalar(Mode::Poprf, &framed_info, None);
		// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-6
		let t = (key_pair.secret_key().to_scalar().into() + &m)
			.try_into()
			.map_err(|_| Error::InvalidInfoDanger)?;
		let t_inverted = CS::Group::scalar_invert(&t);
		let tweaked_key = CS::Group::non_zero_scalar_mul_by_generator(&t);
		let tweaked_key = PublicKey::from_point(tweaked_key);

		Ok(Self {
			key_pair,
			t,
			t_inverted,
			tweaked_key,
		})
	}

	pub const fn public_key(&self) -> &PublicKey<CS::Group> {
		self.key_pair.public_key()
	}

	#[cfg(test)]
	pub(crate) const fn secret_key(&self) -> &SecretKey<CS::Group> {
		self.key_pair.secret_key()
	}

	// `BlindEvaluate`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-4
	pub fn blind_evaluate<R: TryCryptoRng>(
		&self,
		rng: &mut R,
		blinded_element: &BlindedElement<CS>,
	) -> Result<PoprfBlindEvaluateResult<CS>, Error<R::Error>> {
		let PoprfBatchBlindEvaluateFixedResult {
			evaluation_elements: [evaluation_element],
			proof,
		} = self.batch_blind_evaluate_fixed(rng, array::from_ref(blinded_element))?;

		Ok(PoprfBlindEvaluateResult {
			evaluation_element,
			proof,
		})
	}

	// `BlindEvaluate` batched
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-4
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-5
	#[cfg(feature = "alloc")]
	pub fn batch_blind_evaluate<'blinded_elements, R, I>(
		&self,
		rng: &mut R,
		blinded_elements: I,
	) -> Result<PoprfBatchBlindEvaluateResult<CS>, Error<R::Error>>
	where
		R: TryCryptoRng,
		I: ExactSizeIterator<Item = &'blinded_elements BlindedElement<CS>>,
	{
		let blinded_elements_length = blinded_elements.len();

		if blinded_elements_length == 0 || blinded_elements_length > u16::MAX.into() {
			return Err(Error::Batch);
		}

		let d: Vec<_> = blinded_elements.map(ElementWrapper::from).collect();
		let evaluation_elements = EvaluationElement::new_batch(
			d.iter().map(|element| self.t_inverted * element.element()),
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

		Ok(PoprfBatchBlindEvaluateResult {
			evaluation_elements,
			proof,
		})
	}

	// `BlindEvaluate` batched
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-4
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-5
	pub fn batch_blind_evaluate_fixed<R, const N: usize>(
		&self,
		rng: &mut R,
		blinded_elements: &[BlindedElement<CS>; N],
	) -> Result<PoprfBatchBlindEvaluateFixedResult<CS, N>, Error<R::Error>>
	where
		R: TryCryptoRng,
	{
		if blinded_elements.is_empty() || blinded_elements.len() > u16::MAX.into() {
			return Err(Error::Batch);
		}

		let evaluation_elements = EvaluationElement::new_batch_fixed(
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

		Ok(PoprfBatchBlindEvaluateFixedResult {
			evaluation_elements,
			proof,
		})
	}

	// `Evaluate`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-11
	pub fn evaluate(&self, input: &[&[u8]], info: &[u8]) -> Result<Output<CS::Hash>> {
		internal::evaluate::<CS>(Mode::Poprf, self.t_inverted, input, Some(Info::new(info)?))
	}
}

pub struct PoprfBlindResult<CS: CipherSuite> {
	pub client: PoprfClient<CS>,
	pub blinded_element: BlindedElement<CS>,
}

pub struct PoprfBlindEvaluateResult<CS: CipherSuite> {
	pub evaluation_element: EvaluationElement<CS>,
	pub proof: Proof<CS>,
}

#[cfg(feature = "alloc")]
pub struct PoprfBatchBlindEvaluateResult<CS: CipherSuite> {
	pub evaluation_elements: Vec<EvaluationElement<CS>>,
	pub proof: Proof<CS>,
}

pub struct PoprfBatchBlindEvaluateFixedResult<CS: CipherSuite, const N: usize> {
	pub evaluation_elements: [EvaluationElement<CS>; N],
	pub proof: Proof<CS>,
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
	NonIdentityElement<CS>: Deserialize<'de>,
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
	NonIdentityElement<CS>: Serialize,
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
		let tweaked_key = PublicKey::from_point(tweaked_key);

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
impl<CS: CipherSuite> Debug for PoprfBlindEvaluateResult<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfBlindEvaluateResult")
			.field("evaluation_element", &self.evaluation_element)
			.field("proof", &self.proof)
			.finish()
	}
}

impl<CS: CipherSuite> ZeroizeOnDrop for PoprfBlindEvaluateResult<CS> {}

#[cfg(feature = "alloc")]
#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for PoprfBatchBlindEvaluateResult<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfBatchBlindEvaluateResult")
			.field("evaluation_elements", &self.evaluation_elements)
			.field("proof", &self.proof)
			.finish()
	}
}

#[cfg(feature = "alloc")]
impl<CS: CipherSuite> ZeroizeOnDrop for PoprfBatchBlindEvaluateResult<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite, const N: usize> Debug for PoprfBatchBlindEvaluateFixedResult<CS, N> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfBatchBlindEvaluateFixedResult")
			.field("evaluation_elements", &self.evaluation_elements)
			.field("proof", &self.proof)
			.finish()
	}
}

impl<CS: CipherSuite, const N: usize> ZeroizeOnDrop for PoprfBatchBlindEvaluateFixedResult<CS, N> {}
