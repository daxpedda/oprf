#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt::{self, Debug, Formatter};
use core::iter::{Map, Repeat, RepeatN, Zip};
use core::{array, iter};

use digest::Output;
use hybrid_array::ArrayN;
use rand_core::TryCryptoRng;

use crate::ciphersuite::{CipherSuite, NonZeroScalar};
use crate::common::{BlindedElement, EvaluationElement, Mode, PreparedElement, Proof};
use crate::error::{Error, Result};
use crate::group::{Group, InternalGroup};
use crate::internal::{self, BlindResult, Info};
#[cfg(test)]
use crate::key::SecretKey;
use crate::key::{KeyPair, PublicKey};

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
		let outputs: ArrayN<_, 1> = Self::batch_finalize(
			array::from_ref(self),
			public_key,
			iter::once(input),
			array::from_ref(evaluation_element),
			proof,
			info,
		)?
		.collect();
		let [output] = outputs.into();

		output
	}

	// `Finalize`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-8
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-9
	pub fn batch_finalize<'clients, 'inputs, 'evaluation_elements, 'info, IC, II, IEE>(
		clients: &'clients IC,
		public_key: &PublicKey<CS::Group>,
		inputs: II,
		evaluation_elements: &'evaluation_elements IEE,
		proof: &Proof<CS>,
		info: &'info [u8],
	) -> Result<
		PoprfBatchFinalizeResult<
			'info,
			CS,
			II,
			<&'clients IC as IntoIterator>::IntoIter,
			<&'evaluation_elements IEE as IntoIterator>::IntoIter,
		>,
	>
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
		let clients_iter = clients.into_iter();
		let clients_length = clients_iter.len();

		if clients_length != inputs.len() {
			return Err(Error::Batch);
		}

		let info = Info::new(info)?;

		let framed_info = [b"Info".as_slice(), info.i2osp(), info.info()];
		let m = CS::hash_to_scalar(Mode::Poprf, &framed_info, None);
		let t = CS::Group::scalar_mul_by_generator(&m);
		let tweaked_key = (t + public_key.as_point())
			.try_into()
			.map_err(|_| Error::InvalidInfo)?;

		internal::verify_proof(
			Mode::Poprf,
			tweaked_key,
			evaluation_elements
				.into_iter()
				.map(|evaluation_element| &evaluation_element.0),
			clients_iter.map(|client| &client.blinded_element.0),
			proof,
		)?;

		Ok(inputs
			.zip(iter::repeat_n(info, clients_length))
			.zip(clients)
			.zip(evaluation_elements)
			.map(|(((input, info), client), evaluation_element)| {
				internal::finalize(input, &client.blind, evaluation_element, Some(info))
			}))
	}
}

pub struct PoprfServer<CS: CipherSuite> {
	key_pair: KeyPair<CS::Group>,
}

impl<CS: CipherSuite> PoprfServer<CS> {
	pub fn new<R: TryCryptoRng>(rng: &mut R) -> Result<Self, R::Error> {
		Ok(Self {
			key_pair: KeyPair::generate(rng)?,
		})
	}

	pub fn from_seed(seed: &[u8; 32], info: &[u8]) -> Result<Self> {
		Ok(Self {
			key_pair: KeyPair::derive::<CS>(Mode::Poprf, seed, info)?,
		})
	}

	pub const fn from_key_pair(key_pair: KeyPair<CS::Group>) -> Self {
		Self { key_pair }
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
		info: &[u8],
	) -> Result<PoprfBlindEvaluateResult<CS>, Error<R::Error>> {
		let PoprfPrepareBatchBlindEvaluateResult {
			state,
			prepared_elements,
		} = self
			.prepare_batch_blind_evaluate(iter::once(blinded_element), info)
			.map_err(Error::into_random::<R>)?;
		let prepared_element: ArrayN<_, 1> = prepared_elements.collect();
		let prepared_element: [_; 1] = prepared_element.into();

		let PoprfFinishBatchBlindEvaluateResult {
			state,
			evaluation_elements,
			proof,
		} = self.finish_batch_blind_evaluate(
			&state,
			rng,
			iter::once(blinded_element),
			&prepared_element,
		)?;

		let evaluation_element: ArrayN<_, 1> = evaluation_elements.collect();
		let [evaluation_element] = evaluation_element.into();

		Ok(PoprfBlindEvaluateResult {
			state,
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
		blinded_elements: &'blinded_elements I,
		info: &[u8],
	) -> Result<PoprfBatchBlindEvaluateResult<CS>, Error<R::Error>>
	where
		R: TryCryptoRng,
		I: ?Sized,
		&'blinded_elements I:
			IntoIterator<Item = &'blinded_elements BlindedElement<CS>, IntoIter: ExactSizeIterator>,
	{
		let PoprfPrepareBatchBlindEvaluateResult {
			state,
			prepared_elements,
		} = self
			.prepare_batch_blind_evaluate(blinded_elements.into_iter(), info)
			.map_err(Error::into_random::<R>)?;
		let prepared_elements: Vec<_> = prepared_elements.collect();
		let PoprfFinishBatchBlindEvaluateResult {
			state,
			evaluation_elements,
			proof,
		} = self.finish_batch_blind_evaluate::<_, _, Vec<_>>(
			&state,
			rng,
			blinded_elements.into_iter(),
			&prepared_elements,
		)?;

		Ok(PoprfBatchBlindEvaluateResult {
			state,
			evaluation_elements: evaluation_elements.collect(),
			proof,
		})
	}

	// `BlindEvaluate` batched
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-4
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-5
	pub fn prepare_batch_blind_evaluate<'blinded_elements, I>(
		&self,
		blinded_elements: I,
		info: &[u8],
	) -> Result<PoprfPrepareBatchBlindEvaluateResult<'blinded_elements, CS, I>>
	where
		I: ExactSizeIterator<Item = &'blinded_elements BlindedElement<CS>>,
	{
		let length = blinded_elements.len();

		if length == 0 || length > u16::MAX.into() {
			return Err(Error::Batch);
		}

		let info = Info::new(info)?;
		let framed_info = [b"Info".as_slice(), info.i2osp(), info.info()];
		let m = CS::hash_to_scalar(Mode::Poprf, &framed_info, None);
		// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-6
		let t = (self.key_pair.secret_key().to_scalar().into() + &m)
			.try_into()
			.map_err(|_| Error::InvalidInfoDanger)?;
		let t_inverted = CS::Group::scalar_invert(&t);

		let prepared_elements = blinded_elements
			.zip(iter::repeat(t_inverted))
			.map::<_, fn((&_, _)) -> _>(|(blinded_element, t)| {
				PreparedElement(t * &blinded_element.0)
			});

		Ok(PoprfPrepareBatchBlindEvaluateResult {
			state: PoprfBatchBlindEvaluateState { t, t_inverted },
			prepared_elements,
		})
	}

	// `BlindEvaluate` batched
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-4
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-5
	pub fn finish_batch_blind_evaluate<'blinded_elements, 'prepared_elements, R, IBE, IPE>(
		&self,
		state: &PoprfBatchBlindEvaluateState<CS>,
		rng: &mut R,
		blinded_elements: IBE,
		prepared_elements: &'prepared_elements IPE,
	) -> Result<
		PoprfFinishBatchBlindEvaluateResult<
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
		let tweaked_key = CS::Group::non_zero_scalar_mul_by_generator(&state.t);

		let proof = internal::generate_proof(
			Mode::Poprf,
			rng,
			state.t,
			&tweaked_key,
			prepared_elements
				.into_iter()
				.map(|prepared_element| &prepared_element.0),
			blinded_elements.map(|blinded_element| &blinded_element.0),
		)?;

		Ok(PoprfFinishBatchBlindEvaluateResult {
			state: PoprfEvaluateState {
				t_inverted: state.t_inverted,
			},
			evaluation_elements: prepared_elements
				.into_iter()
				.map(|prepared_element| EvaluationElement(prepared_element.0)),
			proof,
		})
	}

	// `Evaluate`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.3-11
	pub fn evaluate(
		&self,
		state: &PoprfEvaluateState<CS>,
		input: &[&[u8]],
		info: &[u8],
	) -> Result<Output<CS::Hash>> {
		internal::evaluate::<CS>(Mode::Poprf, state.t_inverted, input, Some(Info::new(info)?))
	}
}

pub struct PoprfBlindResult<CS: CipherSuite> {
	pub client: PoprfClient<CS>,
	pub blinded_element: BlindedElement<CS>,
}

pub type PoprfBatchFinalizeResult<'info, CS, II, IC, IEE> = Map<
	Zip<Zip<Zip<II, RepeatN<Info<'info>>>, IC>, IEE>,
	fn(
		(
			((&[&[u8]], Info<'_>), &PoprfClient<CS>),
			&EvaluationElement<CS>,
		),
	) -> Result<Output<<CS as CipherSuite>::Hash>>,
>;

pub struct PoprfEvaluateState<CS: CipherSuite> {
	t_inverted: NonZeroScalar<CS>,
}

pub struct PoprfBlindEvaluateResult<CS: CipherSuite> {
	pub state: PoprfEvaluateState<CS>,
	pub evaluation_element: EvaluationElement<CS>,
	pub proof: Proof<CS>,
}

#[cfg(feature = "alloc")]
pub struct PoprfBatchBlindEvaluateResult<CS: CipherSuite> {
	pub state: PoprfEvaluateState<CS>,
	pub evaluation_elements: Vec<EvaluationElement<CS>>,
	pub proof: Proof<CS>,
}

pub struct PoprfPrepareBatchBlindEvaluateResult<
	'blinded_elements,
	CS: CipherSuite,
	I: Iterator<Item = &'blinded_elements BlindedElement<CS>>,
> {
	pub state: PoprfBatchBlindEvaluateState<CS>,
	pub prepared_elements: PoprfPrepareBatchBlindEvaluatePreparedElements<CS, I>,
}

pub type PoprfPrepareBatchBlindEvaluatePreparedElements<CS, I> = Map<
	Zip<I, Repeat<NonZeroScalar<CS>>>,
	fn((&BlindedElement<CS>, NonZeroScalar<CS>)) -> PreparedElement<CS>,
>;

pub struct PoprfBatchBlindEvaluateState<CS: CipherSuite> {
	t: NonZeroScalar<CS>,
	t_inverted: NonZeroScalar<CS>,
}

pub struct PoprfFinishBatchBlindEvaluateResult<
	'prepared_elements,
	CS: CipherSuite,
	I: Iterator<Item = &'prepared_elements PreparedElement<CS>>,
> {
	pub state: PoprfEvaluateState<CS>,
	pub evaluation_elements: PoprfFinishBatchBlindEvaluateEvaluationElements<CS, I>,
	pub proof: Proof<CS>,
}

pub type PoprfFinishBatchBlindEvaluateEvaluationElements<CS, I> =
	Map<I, fn(&PreparedElement<CS>) -> EvaluationElement<CS>>;

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

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Clone for PoprfServer<CS> {
	fn clone(&self) -> Self {
		Self {
			key_pair: self.key_pair.clone(),
		}
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for PoprfServer<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfServer")
			.field("key_pair", &self.key_pair)
			.finish()
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for PoprfBlindResult<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfBlindResult")
			.field("client", &self.client)
			.field("blinded_element", &self.blinded_element)
			.finish()
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for PoprfEvaluateState<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfEvaluateState")
			.field("t", &self.t_inverted)
			.finish()
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for PoprfBlindEvaluateResult<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfBlindEvaluateResult")
			.field("state", &self.state)
			.field("evaluation_element", &self.evaluation_element)
			.field("proof", &self.proof)
			.finish()
	}
}

#[cfg(feature = "alloc")]
#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for PoprfBatchBlindEvaluateResult<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfBatchBlindEvaluateResult")
			.field("state", &self.state)
			.field("evaluation_elements", &self.evaluation_elements)
			.field("proof", &self.proof)
			.finish()
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<
	'blinded_elements,
	CS: CipherSuite,
	I: Iterator<Item = &'blinded_elements BlindedElement<CS>> + Debug,
> Debug for PoprfPrepareBatchBlindEvaluateResult<'blinded_elements, CS, I>
{
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfPrepareBatchBlindEvaluateResult")
			.field("state", &self.state)
			.field("prepared_elements", &self.prepared_elements)
			.finish()
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for PoprfBatchBlindEvaluateState<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfBatchBlindEvaluateState")
			.field("t", &self.t)
			.field("t_inverted", &self.t_inverted)
			.finish()
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<
	'prepared_elements,
	CS: CipherSuite,
	I: Iterator<Item = &'prepared_elements PreparedElement<CS>> + Debug,
> Debug for PoprfFinishBatchBlindEvaluateResult<'prepared_elements, CS, I>
{
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PoprfFinishBatchBlindEvaluateResult")
			.field("state", &self.state)
			.field("evaluation_elements", &self.evaluation_elements)
			.field("proof", &self.proof)
			.finish()
	}
}
