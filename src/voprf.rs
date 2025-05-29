#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt::{self, Debug, Formatter};
use core::iter;
use core::iter::{Map, Repeat, Zip};

use digest::Output;
use hybrid_array::{ArrayN, ArraySize, AssocArraySize};
use rand_core::TryCryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ciphersuite::{CipherSuite, NonZeroScalar};
use crate::common::{BlindedElement, EvaluationElement, Mode, PreparedElement, Proof};
use crate::error::{Error, Result};
use crate::internal::{self, Blind, BlindResult};
#[cfg(test)]
use crate::key::SecretKey;
use crate::key::{KeyPair, PublicKey};

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
		Self::internal_batch_finalize(
			iter::once(self),
			public_key,
			&iter::once(input),
			iter::once(evaluation_element),
			proof,
		)?;

		internal::finalize(input, &self.blind, evaluation_element, None)
	}

	// `Finalize`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-5
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-6
	#[cfg(feature = "alloc")]
	pub fn batch_finalize<'clients, 'inputs, 'evaluation_elements, IC, II, IEE>(
		clients: &'clients IC,
		public_key: &PublicKey<CS::Group>,
		inputs: II,
		evaluation_elements: &'evaluation_elements IEE,
		proof: &Proof<CS>,
	) -> Result<Vec<Output<CS::Hash>>>
	where
		IC: ?Sized,
		&'clients IC: IntoIterator<Item = &'clients Self, IntoIter: ExactSizeIterator>,
		II: ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
		IEE: ?Sized,
		&'evaluation_elements IEE: IntoIterator<
				Item = &'evaluation_elements EvaluationElement<CS>,
				IntoIter: ExactSizeIterator,
			>,
	{
		Self::internal_batch_finalize(
			clients.into_iter(),
			public_key,
			&inputs,
			evaluation_elements.into_iter(),
			proof,
		)?;

		internal::batch_finalize(
			inputs,
			clients.into_iter(),
			evaluation_elements.into_iter(),
			None,
		)
	}

	// `Finalize`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-5
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-6
	pub fn batch_finalize_fixed<'inputs, 'evaluation_elements, const N: usize, II, IEE>(
		clients: &[Self; N],
		public_key: &PublicKey<CS::Group>,
		inputs: II,
		evaluation_elements: &'evaluation_elements IEE,
		proof: &Proof<CS>,
	) -> Result<[Output<CS::Hash>; N]>
	where
		[Output<CS::Hash>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Output<CS::Hash>> = [Output<CS::Hash>; N]>>,
		II: ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
		IEE: ?Sized,
		&'evaluation_elements IEE: IntoIterator<
				Item = &'evaluation_elements EvaluationElement<CS>,
				IntoIter: ExactSizeIterator,
			>,
	{
		Self::internal_batch_finalize(
			clients.iter(),
			public_key,
			&inputs,
			evaluation_elements.into_iter(),
			proof,
		)?;

		internal::batch_finalize_fixed(inputs, clients, evaluation_elements.into_iter(), None)
	}

	// `Finalize`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-5
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-6
	fn internal_batch_finalize<'clients, 'inputs, 'evaluation_elements, IC, II, IEE>(
		clients: IC,
		public_key: &PublicKey<CS::Group>,
		inputs: &II,
		evaluation_elements: IEE,
		proof: &Proof<CS>,
	) -> Result<()>
	where
		IC: ExactSizeIterator<Item = &'clients Self>,
		II: ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
		IEE: ExactSizeIterator<Item = &'evaluation_elements EvaluationElement<CS>>,
	{
		let clients_iter = clients.into_iter();

		if clients_iter.len() != inputs.len() {
			return Err(Error::Batch);
		}

		internal::verify_proof(
			Mode::Voprf,
			public_key.to_point(),
			clients_iter.map(|client| &client.blinded_element.0),
			evaluation_elements.map(|evaluation_element| &evaluation_element.0),
			proof,
		)
	}
}

impl<CS: CipherSuite> Blind<CS> for VoprfClient<CS> {
	fn get_blind(&self) -> NonZeroScalar<CS> {
		self.blind
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
		let prepared_elements = self
			.prepare_batch_blind_evaluate(iter::once(blinded_element))
			.map_err(Error::into_random::<R>)?;
		let prepared_element: ArrayN<_, 1> = prepared_elements.collect();
		let prepared_element: [_; 1] = prepared_element.into();

		let VoprfFinishBatchBlindEvaluateResult {
			evaluation_elements,
			proof,
		} = self.finish_batch_blind_evaluate(rng, iter::once(blinded_element), &prepared_element)?;

		let evaluation_element: ArrayN<_, 1> = evaluation_elements.collect();
		let [evaluation_element] = evaluation_element.into();

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
		blinded_elements: &'blinded_elements I,
	) -> Result<VoprfBatchBlindEvaluateResult<CS>, Error<R::Error>>
	where
		R: TryCryptoRng,
		I: ?Sized,
		&'blinded_elements I:
			IntoIterator<Item = &'blinded_elements BlindedElement<CS>, IntoIter: ExactSizeIterator>,
	{
		let prepared_elements: Vec<_> = self
			.prepare_batch_blind_evaluate(blinded_elements.into_iter())
			.map_err(Error::into_random::<R>)?
			.collect();
		let VoprfFinishBatchBlindEvaluateResult {
			evaluation_elements,
			proof,
		} = self.finish_batch_blind_evaluate::<_, _, Vec<_>>(
			rng,
			blinded_elements.into_iter(),
			&prepared_elements,
		)?;

		Ok(VoprfBatchBlindEvaluateResult {
			evaluation_elements: evaluation_elements.collect(),
			proof,
		})
	}

	// `BlindEvaluate` batched
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-2
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-3
	pub fn prepare_batch_blind_evaluate<'blinded_elements, I>(
		&self,
		blinded_elements: I,
	) -> Result<VoprfPrepareBatchBlindEvaluateResult<CS, I>>
	where
		I: ExactSizeIterator<Item = &'blinded_elements BlindedElement<CS>>,
	{
		let length = blinded_elements.len();

		if length == 0 || length > u16::MAX.into() {
			return Err(Error::Batch);
		}

		Ok(blinded_elements
			.zip(iter::repeat(self.key_pair.secret_key().to_scalar()))
			.map(|(blinded_element, secret_key)| PreparedElement(secret_key * &blinded_element.0)))
	}

	// `BlindEvaluate` batched
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-2
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-3
	pub fn finish_batch_blind_evaluate<'blinded_elements, 'prepared_elements, R, IBE, IPE>(
		&self,
		rng: &mut R,
		blinded_elements: IBE,
		prepared_elements: &'prepared_elements IPE,
	) -> Result<
		VoprfFinishBatchBlindEvaluateResult<
			'prepared_elements,
			CS,
			<&'prepared_elements IPE as IntoIterator>::IntoIter,
		>,
		Error<R::Error>,
	>
	where
		R: TryCryptoRng,
		IBE: ExactSizeIterator<Item = &'blinded_elements BlindedElement<CS>>,
		IPE: ?Sized,
		&'prepared_elements IPE: IntoIterator<
				Item = &'prepared_elements PreparedElement<CS>,
				IntoIter: ExactSizeIterator,
			>,
	{
		let proof = internal::generate_proof(
			Mode::Voprf,
			rng,
			self.key_pair.secret_key().to_scalar(),
			self.key_pair.public_key().as_point(),
			blinded_elements.map(|blinded_element| &blinded_element.0),
			prepared_elements
				.into_iter()
				.map(|prepared_element| &prepared_element.0),
		)?;

		Ok(VoprfFinishBatchBlindEvaluateResult {
			evaluation_elements: prepared_elements
				.into_iter()
				.map(|prepared_element| EvaluationElement(prepared_element.0)),
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

pub type VoprfPrepareBatchBlindEvaluateResult<CS, I> = Map<
	Zip<I, Repeat<NonZeroScalar<CS>>>,
	fn((&BlindedElement<CS>, NonZeroScalar<CS>)) -> PreparedElement<CS>,
>;

pub struct VoprfFinishBatchBlindEvaluateResult<
	'prepared_elements,
	CS: CipherSuite,
	I: Iterator<Item = &'prepared_elements PreparedElement<CS>>,
> {
	pub evaluation_elements: VoprfFinishBatchBlindEvaluateEvaluationElements<CS, I>,
	pub proof: Proof<CS>,
}

pub type VoprfFinishBatchBlindEvaluateEvaluationElements<CS, I> =
	Map<I, fn(&PreparedElement<CS>) -> EvaluationElement<CS>>;

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

impl<CS: CipherSuite> Eq for VoprfServer<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> PartialEq for VoprfServer<CS> {
	fn eq(&self, other: &Self) -> bool {
		self.key_pair.eq(&other.key_pair)
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
impl<
	'prepared_elements,
	CS: CipherSuite,
	I: Iterator<Item = &'prepared_elements PreparedElement<CS>> + Debug,
> Debug for VoprfFinishBatchBlindEvaluateResult<'prepared_elements, CS, I>
{
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("VoprfFinishBatchBlindEvaluateResult")
			.field("evaluation_elements", &self.evaluation_elements)
			.field("proof", &self.proof)
			.finish()
	}
}
