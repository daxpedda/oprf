use core::fmt::{self, Debug, Formatter};

use digest::Output;
use rand_core::TryCryptoRng;

use crate::ciphersuite::{CipherSuite, NonZeroScalar};
use crate::common::{BlindedElement, EvaluationElement, Mode};
use crate::error::{Error, Result};
use crate::internal::{self, BlindResult};
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
	pub fn batch_finalize_fixed(
		&self,
		input: &[&[u8]],
		evaluation_element: &EvaluationElement<CS>,
	) -> Result<Output<CS::Hash>> {
		internal::finalize(input, &self.blind, evaluation_element, None)
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
impl<CS: CipherSuite> Debug for OprfClient<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("OprfClient")
			.field("blind", &self.blind)
			.finish()
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

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for OprfBlindResult<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("OprfBlindResult")
			.field("client", &self.client)
			.field("blinded_element", &self.blinded_element)
			.finish()
	}
}
