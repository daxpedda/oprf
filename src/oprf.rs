#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt::{self, Debug, Formatter};

use digest::Output;
use hybrid_array::{ArraySize, AssocArraySize};
use rand_core::TryCryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ciphersuite::{CipherSuite, NonZeroScalar};
use crate::common::{BlindedElement, EvaluationElement, Mode};
use crate::error::{Error, Result};
use crate::internal::{self, Blind, BlindResult};
use crate::key::SecretKey;

pub struct OprfClient<CS: CipherSuite> {
	blind: NonZeroScalar<CS>,
}

impl<CS: CipherSuite> OprfClient<CS> {
	// `Blind`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-2
	pub fn blind<R: TryCryptoRng>(
		rng: &mut R,
		input: &[&[u8]],
	) -> Result<OprfBlindResult<CS>, Error<R::Error>> {
		let BlindResult {
			blind,
			blinded_element,
		} = internal::blind(Mode::Oprf, rng, input)?;

		Ok(OprfBlindResult {
			client: Self { blind },
			blinded_element,
		})
	}

	// `Finalize`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7
	pub fn finalize(
		&self,
		input: &[&[u8]],
		evaluation_element: &EvaluationElement<CS>,
	) -> Result<Output<CS::Hash>> {
		internal::finalize(input, &self.blind, evaluation_element, None)
	}

	// `Finalize`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7
	#[cfg(feature = "alloc")]
	pub fn batch_finalize<'clients, 'inputs, 'evaluation_elements, IC, II, IEE>(
		clients: IC,
		inputs: II,
		evaluation_elements: IEE,
	) -> Result<Vec<Output<CS::Hash>>>
	where
		IC: ExactSizeIterator<Item = &'clients Self>,
		II: ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
		IEE: ExactSizeIterator<Item = &'evaluation_elements EvaluationElement<CS>>,
	{
		internal::batch_finalize(inputs, clients, evaluation_elements, None)
	}

	// `Finalize`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-7
	pub fn batch_finalize_fixed<'inputs, 'evaluation_elements, const N: usize, II, IEE>(
		clients: &[Self; N],
		inputs: II,
		evaluation_elements: IEE,
	) -> Result<[Output<CS::Hash>; N]>
	where
		[Output<CS::Hash>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Output<CS::Hash>> = [Output<CS::Hash>; N]>>,
		II: ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
		IEE: ExactSizeIterator<Item = &'evaluation_elements EvaluationElement<CS>>,
	{
		internal::batch_finalize_fixed(inputs, clients, evaluation_elements, None)
	}
}

impl<CS: CipherSuite> Blind<CS> for OprfClient<CS> {
	fn get_blind(&self) -> NonZeroScalar<CS> {
		self.blind
	}
}

pub struct OprfServer<CS: CipherSuite> {
	secret_key: SecretKey<CS::Group>,
}

impl<CS: CipherSuite> OprfServer<CS> {
	pub fn new<R: TryCryptoRng>(rng: &mut R) -> Result<Self, R::Error> {
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

	#[cfg(test)]
	pub(crate) const fn secret_key(&self) -> &SecretKey<CS::Group> {
		&self.secret_key
	}

	// `BlindEvaluate`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-4
	pub fn blind_evaluate(&self, blinded_element: &BlindedElement<CS>) -> EvaluationElement<CS> {
		let evaluation_element = self.secret_key.to_scalar() * &blinded_element.0;

		EvaluationElement(evaluation_element)
	}

	// `Evaluate`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.1-9
	pub fn evaluate(&self, input: &[&[u8]]) -> Result<Output<CS::Hash>> {
		internal::evaluate::<CS>(Mode::Oprf, self.secret_key.to_scalar(), input, None)
	}
}

pub struct OprfBlindResult<CS: CipherSuite> {
	pub client: OprfClient<CS>,
	pub blinded_element: BlindedElement<CS>,
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

impl<CS: CipherSuite> Eq for OprfServer<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> PartialEq for OprfServer<CS> {
	fn eq(&self, other: &Self) -> bool {
		self.secret_key.eq(&other.secret_key)
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
