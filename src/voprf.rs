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
use crate::ciphersuite::{CipherSuite, NonZeroScalar};
use crate::common::{BlindedElement, EvaluationElement, Mode, Proof};
use crate::error::{Error, Result};
use crate::internal::{self, BlindResult, ElementWrapper};
#[cfg(any(feature = "serde", test))]
use crate::key::SecretKey;
use crate::key::{KeyPair, PublicKey};
#[cfg(feature = "serde")]
use crate::serde::{self, DeserializeWrapper, SerializeWrapper};
use crate::util::CollectArray;

pub struct VoprfClient<CS: CipherSuite> {
	blind: NonZeroScalar<CS>,
	blinded_element: BlindedElement<CS>,
}

impl<CS: CipherSuite> VoprfClient<CS> {
	// `Blind`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-1
	pub fn blind<R: TryCryptoRng>(
		rng: &mut R,
		input: &[&[u8]],
	) -> Result<VoprfBlindResult<CS>, Error<R::Error>> {
		let BlindResult {
			blind,
			blinded_element,
		} = internal::blind(Mode::Voprf, rng, input)?;

		Ok(VoprfBlindResult {
			client: Self {
				blind,
				blinded_element: blinded_element.clone(),
			},
			blinded_element,
		})
	}

	// `Finalize`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-5
	pub fn finalize(
		&self,
		public_key: &PublicKey<CS::Group>,
		input: &[&[u8]],
		evaluation_element: &EvaluationElement<CS>,
		proof: &Proof<CS>,
	) -> Result<Output<CS::Hash>> {
		let [output] = Self::batch_finalize_fixed(
			array::from_ref(self),
			public_key,
			iter::once(input),
			array::from_ref(evaluation_element),
			proof,
		)?;
		Ok(output)
	}

	// `Finalize`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-5
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-6
	#[cfg(feature = "alloc")]
	pub fn batch_finalize<'clients, 'inputs, 'evaluation_elements, IC, II, IEE>(
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
			.map(|client| {
				(
					ElementWrapper::from(&client.blinded_element),
					client.blind.into(),
				)
			})
			.unzip();
		let d: Vec<_> = evaluation_elements.map(ElementWrapper::from).collect();

		internal::verify_proof(
			Mode::Voprf,
			public_key.into(),
			c.into_iter(),
			d.iter().copied(),
			proof,
		)?;

		let evaluation_elements = d.into_iter().map(|element| element.element().deref());

		internal::batch_finalize::<CS>(inputs, blinds, evaluation_elements, None)
	}

	// `Finalize`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-5
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-6
	pub fn batch_finalize_fixed<'inputs, I, const N: usize>(
		clients: &[Self; N],
		public_key: &PublicKey<CS::Group>,
		inputs: I,
		evaluation_elements: &[EvaluationElement<CS>; N],
		proof: &Proof<CS>,
	) -> Result<[Output<CS::Hash>; N]>
	where
		[Output<CS::Hash>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Output<CS::Hash>> = [Output<CS::Hash>; N]>>,
		I: ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
	{
		if N == 0 || N != inputs.len() || N > u16::MAX.into() {
			return Err(Error::Batch);
		}

		let c = clients
			.iter()
			.map(|client| ElementWrapper::from(&client.blinded_element));
		let d = evaluation_elements.iter().map(ElementWrapper::from);

		internal::verify_proof(Mode::Voprf, public_key.into(), c, d, proof)?;

		let blinds = clients
			.iter()
			.map(|client| client.blind.into())
			.collect_array();
		let evaluation_elements = evaluation_elements
			.iter()
			.map(|evaluation_element| evaluation_element.element().deref());

		internal::batch_finalize_fixed::<N, CS>(inputs, blinds, evaluation_elements, None)
	}
}

pub struct VoprfServer<CS: CipherSuite> {
	key_pair: KeyPair<CS::Group>,
}

impl<CS: CipherSuite> VoprfServer<CS> {
	pub fn new<R: TryCryptoRng>(rng: &mut R) -> Result<Self, R::Error> {
		Ok(Self {
			key_pair: KeyPair::generate(rng)?,
		})
	}

	pub fn from_seed(seed: &[u8; 32], info: &[u8]) -> Result<Self> {
		Ok(Self {
			key_pair: KeyPair::derive::<CS>(Mode::Voprf, seed, info)?,
		})
	}

	pub const fn from_key_pair(key_pair: KeyPair<CS::Group>) -> Self {
		Self { key_pair }
	}

	#[cfg(test)]
	pub(crate) const fn secret_key(&self) -> &SecretKey<CS::Group> {
		self.key_pair.secret_key()
	}

	pub const fn public_key(&self) -> &PublicKey<CS::Group> {
		self.key_pair.public_key()
	}

	// `BlindEvaluate`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-2
	pub fn blind_evaluate<R: TryCryptoRng>(
		&self,
		rng: &mut R,
		blinded_element: &BlindedElement<CS>,
	) -> Result<VoprfBlindEvaluateResult<CS>, Error<R::Error>> {
		let VoprfBatchBlindEvaluateFixedResult {
			evaluation_elements: [evaluation_element],
			proof,
		} = self.batch_blind_evaluate_fixed(rng, array::from_ref(blinded_element))?;

		Ok(VoprfBlindEvaluateResult {
			evaluation_element,
			proof,
		})
	}

	// `BlindEvaluate` batched
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-2
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-3
	#[cfg(feature = "alloc")]
	pub fn batch_blind_evaluate<'blinded_elements, R, I>(
		&self,
		rng: &mut R,
		blinded_elements: I,
	) -> Result<VoprfBatchBlindEvaluateResult<CS>, Error<R::Error>>
	where
		R: TryCryptoRng,
		I: ExactSizeIterator<Item = &'blinded_elements BlindedElement<CS>>,
	{
		let blinded_elements_length = blinded_elements.len();

		if blinded_elements_length == 0 || blinded_elements_length > u16::MAX.into() {
			return Err(Error::Batch);
		}

		let c: Vec<_> = blinded_elements.map(ElementWrapper::from).collect();
		let evaluation_elements = EvaluationElement::new_batch(
			c.iter()
				.map(|element| self.key_pair.secret_key().to_scalar() * element.element()),
		);
		let d = evaluation_elements.iter().map(ElementWrapper::from);

		let proof = internal::generate_proof(
			Mode::Voprf,
			rng,
			self.key_pair.secret_key().to_scalar(),
			self.key_pair.public_key().into(),
			c.into_iter(),
			d,
		)?;

		Ok(VoprfBatchBlindEvaluateResult {
			evaluation_elements,
			proof,
		})
	}

	// `BlindEvaluate` batched
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-2
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-3
	pub fn batch_blind_evaluate_fixed<R, const N: usize>(
		&self,
		rng: &mut R,
		blinded_elements: &[BlindedElement<CS>; N],
	) -> Result<VoprfBatchBlindEvaluateFixedResult<CS, N>, Error<R::Error>>
	where
		R: TryCryptoRng,
	{
		if blinded_elements.is_empty() || blinded_elements.len() > u16::MAX.into() {
			return Err(Error::Batch);
		}

		let evaluation_elements = EvaluationElement::new_batch_fixed(
			&blinded_elements
				.iter()
				.map(|blinded_element| {
					self.key_pair.secret_key().to_scalar() * blinded_element.element()
				})
				.collect_array(),
		);
		let c = blinded_elements.iter().map(ElementWrapper::from);
		let d = evaluation_elements.iter().map(ElementWrapper::from);

		let proof = internal::generate_proof(
			Mode::Voprf,
			rng,
			self.key_pair.secret_key().to_scalar(),
			self.key_pair.public_key().into(),
			c,
			d,
		)?;

		Ok(VoprfBatchBlindEvaluateFixedResult {
			evaluation_elements,
			proof,
		})
	}

	// `Evaluate`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-7
	pub fn evaluate(&self, input: &[&[u8]]) -> Result<Output<CS::Hash>> {
		internal::evaluate::<CS>(
			Mode::Voprf,
			self.key_pair.secret_key().to_scalar(),
			input,
			None,
		)
	}
}

pub struct VoprfBlindResult<CS: CipherSuite> {
	pub client: VoprfClient<CS>,
	pub blinded_element: BlindedElement<CS>,
}

pub struct VoprfBlindEvaluateResult<CS: CipherSuite> {
	pub evaluation_element: EvaluationElement<CS>,
	pub proof: Proof<CS>,
}

#[cfg(feature = "alloc")]
pub struct VoprfBatchBlindEvaluateResult<CS: CipherSuite> {
	pub evaluation_elements: Vec<EvaluationElement<CS>>,
	pub proof: Proof<CS>,
}

pub struct VoprfBatchBlindEvaluateFixedResult<CS: CipherSuite, const N: usize> {
	pub evaluation_elements: [EvaluationElement<CS>; N],
	pub proof: Proof<CS>,
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
		let (blind, DeserializeWrapper::<ElementLength<CS>>(blinded_element)) =
			serde::struct_2(deserializer, "VoprfClient", &["blind", "blinded_element"])?;
		let blinded_element =
			BlindedElement::from_array(blinded_element).map_err(D::Error::custom)?;

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
		state.serialize_field(
			"blinded_element",
			&SerializeWrapper(self.blinded_element.as_repr()),
		)?;
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
impl<CS: CipherSuite + Debug> Debug for VoprfBlindEvaluateResult<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("VoprfBlindEvaluateResult")
			.field("evaluation_element", &self.evaluation_element)
			.field("proof", &self.proof)
			.finish()
	}
}

impl<CS: CipherSuite> ZeroizeOnDrop for VoprfBlindEvaluateResult<CS> {}

#[cfg(feature = "alloc")]
#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for VoprfBatchBlindEvaluateResult<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("VoprfBatchBlindEvaluateResult")
			.field("evaluation_elements", &self.evaluation_elements)
			.field("proof", &self.proof)
			.finish()
	}
}

#[cfg(feature = "alloc")]
impl<CS: CipherSuite> ZeroizeOnDrop for VoprfBatchBlindEvaluateResult<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite, const N: usize> Debug for VoprfBatchBlindEvaluateFixedResult<CS, N> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("VoprfBatchBlindEvaluateFixedResult")
			.field("evaluation_elements", &self.evaluation_elements)
			.field("proof", &self.proof)
			.finish()
	}
}

impl<CS: CipherSuite, const N: usize> ZeroizeOnDrop for VoprfBatchBlindEvaluateFixedResult<CS, N> {}
