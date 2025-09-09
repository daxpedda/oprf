//! Abstracts over all [`Mode`]s to reduce the amount of duplicate code in
//! tests.

#![expect(
	missing_docs,
	clippy::missing_errors_doc,
	clippy::missing_panics_doc,
	reason = "tests"
)]
#![cfg_attr(
	not(test),
	expect(clippy::missing_docs_in_private_items, reason = "tests")
)]

#[cfg(feature = "alloc")]
use std::iter;
#[cfg(feature = "alloc")]
use std::slice::SliceIndex;

use derive_where::derive_where;
use digest::Output;
use hybrid_array::{ArraySize, AssocArraySize};
use oprf::cipher_suite::CipherSuite;
#[cfg(feature = "alloc")]
use oprf::common::BatchAllocBlindEvaluateResult;
use oprf::common::{
	BatchBlindEvaluateResult, BlindEvaluateResult, BlindedElement, EvaluationElement, Mode, Proof,
};
use oprf::group::Group;
use oprf::key::{KeyPair, PublicKey, SecretKey};
#[cfg(feature = "alloc")]
use oprf::oprf::OprfBatchAllocBlindResult;
use oprf::oprf::{OprfBatchBlindResult, OprfBlindResult, OprfClient, OprfServer};
#[cfg(feature = "alloc")]
use oprf::poprf::PoprfBatchAllocBlindResult;
use oprf::poprf::{PoprfBatchBlindResult, PoprfBlindResult, PoprfClient, PoprfServer};
#[cfg(feature = "alloc")]
use oprf::voprf::VoprfBatchAllocBlindResult;
use oprf::voprf::{VoprfBatchBlindResult, VoprfBlindResult, VoprfClient, VoprfServer};
use oprf::{Error, Result};
use rand_core::{OsRng, TryRngCore};

use super::{INFO, INPUT};
use crate::rng::MockRng;

type CsGroup<Cs> = <Cs as CipherSuite>::Group;
type NonZeroScalar<Cs> = <CsGroup<Cs> as Group>::NonZeroScalar;
type NonIdentityElement<Cs> = <CsGroup<Cs> as Group>::NonIdentityElement;
type Element<Cs> = <CsGroup<Cs> as Group>::Element;

/// Wrapper around clients in all [`Mode`]s.
#[derive_where(Debug)]
enum Client<Cs: CipherSuite> {
	Oprf(OprfClient<Cs>),
	Voprf(VoprfClient<Cs>),
	Poprf(PoprfClient<Cs>),
}

/// Wrapper around clients in all [`Mode`]s and their `Blind` output.
#[derive_where(Debug)]
pub struct CommonClient<Cs: CipherSuite> {
	client: Client<Cs>,
	blinded_element: BlindedElement<Cs>,
}

/// Wrapper around multiple clients in all [`Mode`]s.
#[derive_where(Debug, Eq, PartialEq)]
enum ClientBatch<Cs: CipherSuite> {
	Oprf(Vec<OprfClient<Cs>>),
	Voprf(Vec<VoprfClient<Cs>>),
	Poprf(Vec<PoprfClient<Cs>>),
}

/// Wrapper around multiple clients in all [`Mode`]s and their `Blind` output.
#[derive_where(Debug, Eq, PartialEq)]
pub struct CommonClientBatch<Cs: CipherSuite> {
	clients: ClientBatch<Cs>,
	blinded_elements: Vec<BlindedElement<Cs>>,
}

/// Wrapper around servers in all [`Mode`]s and potentially their
/// `BlindEvaluate` [`Proof`] output.
#[derive_where(Debug, Eq, PartialEq)]
enum Server<Cs: CipherSuite> {
	Oprf(OprfServer<Cs>),
	Voprf {
		server: VoprfServer<Cs>,
		proof: Proof<Cs>,
	},
	Poprf {
		server: PoprfServer<Cs>,
		proof: Proof<Cs>,
	},
}

/// Wrapper around servers in all [`Mode`]s and their `BlindEvalaute` output.
#[derive_where(Debug)]
pub struct CommonServer<Cs: CipherSuite> {
	server: Server<Cs>,
	evaluation_element: EvaluationElement<Cs>,
}

/// Wrapper around servers in all [`Mode`]s and their batched `BlindEvalaute`
/// output.
#[derive_where(Debug, Eq, PartialEq)]
pub struct CommonServerBatch<Cs: CipherSuite> {
	server: Server<Cs>,
	evaluation_elements: Vec<EvaluationElement<Cs>>,
}

impl<Cs: CipherSuite> CommonClient<Cs> {
	#[must_use]
	pub const fn blinded_element(&self) -> &BlindedElement<Cs> {
		&self.blinded_element
	}

	#[must_use]
	pub fn blind(mode: Mode) -> Self {
		Self::blind_with(mode, None, INPUT).unwrap()
	}

	pub fn blind_with(
		mode: Mode,
		blind: Option<&[u8]>,
		input: &[&[u8]],
	) -> Result<Self, Error<<OsRng as TryRngCore>::Error>> {
		let mut rng = blind.map_or_else(MockRng::new_os_rng, MockRng::new);

		match mode {
			Mode::Oprf => {
				let OprfBlindResult {
					client,
					blinded_element,
				} = OprfClient::<Cs>::blind(&mut rng, input)?;

				Ok(Self {
					client: client.into(),
					blinded_element,
				})
			}
			Mode::Voprf => {
				let VoprfBlindResult {
					client,
					blinded_element,
				} = VoprfClient::blind(&mut rng, input)?;

				Ok(Self {
					client: client.into(),
					blinded_element,
				})
			}
			Mode::Poprf => {
				let PoprfBlindResult {
					client,
					blinded_element,
				} = PoprfClient::blind(&mut rng, input)?;

				Ok(Self {
					client: client.into(),
					blinded_element,
				})
			}
		}
	}

	#[must_use]
	pub fn batch<const N: usize>(mode: Mode) -> CommonClientBatch<Cs>
	where
		[NonIdentityElement<Cs>; N]: AssocArraySize<
			Size: ArraySize<ArrayType<NonIdentityElement<Cs>> = [NonIdentityElement<Cs>; N]>,
		>,
		[NonZeroScalar<Cs>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<NonZeroScalar<Cs>> = [NonZeroScalar<Cs>; N]>>,
	{
		Self::batch_with(mode, None, &[INPUT; N]).unwrap()
	}

	pub fn batch_with<const N: usize>(
		mode: Mode,
		blinds: Option<&[&[u8]; N]>,
		inputs: &[&[&[u8]]; N],
	) -> Result<CommonClientBatch<Cs>, Error<<OsRng as TryRngCore>::Error>>
	where
		[NonIdentityElement<Cs>; N]: AssocArraySize<
			Size: ArraySize<ArrayType<NonIdentityElement<Cs>> = [NonIdentityElement<Cs>; N]>,
		>,
		[NonZeroScalar<Cs>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<NonZeroScalar<Cs>> = [NonZeroScalar<Cs>; N]>>,
	{
		let blinds = blinds.map(|blinds| {
			assert_eq!(blinds.len(), inputs.len(), "found unequal items");
			blinds.concat()
		});
		let mut rng = blinds
			.as_ref()
			.map_or_else(MockRng::new_os_rng, |blinds| MockRng::new(blinds));

		match mode {
			Mode::Oprf => {
				let OprfBatchBlindResult {
					clients,
					blinded_elements,
				} = OprfClient::batch_blind(&mut rng, inputs)?;

				Ok(CommonClientBatch {
					clients: ClientBatch::Oprf(clients.to_vec()),
					blinded_elements: blinded_elements.to_vec(),
				})
			}
			Mode::Voprf => {
				let VoprfBatchBlindResult {
					clients,
					blinded_elements,
				} = VoprfClient::batch_blind(&mut rng, inputs)?;

				Ok(CommonClientBatch {
					clients: ClientBatch::Voprf(clients.to_vec()),
					blinded_elements: blinded_elements.to_vec(),
				})
			}
			Mode::Poprf => {
				let PoprfBatchBlindResult {
					clients,
					blinded_elements,
				} = PoprfClient::batch_blind(&mut rng, inputs)?;

				Ok(CommonClientBatch {
					clients: ClientBatch::Poprf(clients.to_vec()),
					blinded_elements: blinded_elements.to_vec(),
				})
			}
		}
	}

	#[must_use]
	#[cfg(feature = "alloc")]
	pub fn batch_alloc(mode: Mode, count: usize) -> CommonClientBatch<Cs> {
		Self::batch_alloc_with(mode, None, iter::repeat_n(INPUT, count)).unwrap()
	}

	#[cfg(feature = "alloc")]
	pub fn batch_alloc_with<'input, I>(
		mode: Mode,
		blinds: Option<&[&[u8]]>,
		inputs: I,
	) -> Result<CommonClientBatch<Cs>, Error<<OsRng as TryRngCore>::Error>>
	where
		I: ExactSizeIterator<Item = &'input [&'input [u8]]>,
	{
		let blinds = blinds.map(|blinds| {
			assert_eq!(blinds.len(), inputs.len(), "found unequal items");
			blinds.concat()
		});
		let mut rng = blinds
			.as_ref()
			.map_or_else(MockRng::new_os_rng, |blinds| MockRng::new(blinds));

		match mode {
			Mode::Oprf => {
				let OprfBatchAllocBlindResult {
					clients,
					blinded_elements,
				} = OprfClient::batch_alloc_blind(&mut rng, inputs)?;

				Ok(CommonClientBatch {
					clients: ClientBatch::Oprf(clients),
					blinded_elements,
				})
			}
			Mode::Voprf => {
				let VoprfBatchAllocBlindResult {
					clients,
					blinded_elements,
				} = VoprfClient::batch_alloc_blind(&mut rng, inputs)?;

				Ok(CommonClientBatch {
					clients: ClientBatch::Voprf(clients),
					blinded_elements,
				})
			}
			Mode::Poprf => {
				let PoprfBatchAllocBlindResult {
					clients,
					blinded_elements,
				} = PoprfClient::batch_alloc_blind(&mut rng, inputs)?;

				Ok(CommonClientBatch {
					clients: ClientBatch::Poprf(clients),
					blinded_elements,
				})
			}
		}
	}

	#[must_use]
	pub fn batch_clone(mode: Mode, count: usize) -> CommonClientBatch<Cs> {
		let Self {
			client,
			blinded_element,
		} = Self::blind(mode);

		CommonClientBatch {
			clients: match client {
				Client::Oprf(_) => panic!("OPRF doesn't have batching functionality"),
				Client::Voprf(client) => ClientBatch::Voprf(vec![client; count]),
				Client::Poprf(client) => ClientBatch::Poprf(vec![client; count]),
			},
			blinded_elements: vec![blinded_element; count],
		}
	}

	#[must_use]
	pub fn finalize(&self, server: &CommonServer<Cs>) -> Output<Cs::Hash> {
		self.finalize_with(
			server.public_key(),
			INPUT,
			&server.evaluation_element,
			server.proof(),
			INFO,
		)
		.unwrap()
	}

	pub fn finalize_with(
		&self,
		public_key: Option<&PublicKey<Cs::Group>>,
		input: &[&[u8]],
		evaluation_element: &EvaluationElement<Cs>,
		proof: Option<&Proof<Cs>>,
		info: &[u8],
	) -> Result<Output<Cs::Hash>> {
		match &self.client {
			Client::Oprf(client) => client.finalize(input, evaluation_element),
			Client::Voprf(client) => client.finalize(
				public_key.unwrap(),
				input,
				evaluation_element,
				proof.unwrap(),
			),
			Client::Poprf(client) => client.finalize(
				public_key.unwrap(),
				input,
				evaluation_element,
				proof.unwrap(),
				info,
			),
		}
	}
}

impl<Cs: CipherSuite> CommonClientBatch<Cs> {
	#[must_use]
	const fn mode(&self) -> Mode {
		match self.clients {
			ClientBatch::Oprf(_) => Mode::Oprf,
			ClientBatch::Voprf(_) => Mode::Voprf,
			ClientBatch::Poprf(_) => Mode::Poprf,
		}
	}

	#[must_use]
	pub fn blinded_elements(&self) -> &[BlindedElement<Cs>] {
		&self.blinded_elements
	}

	const fn len(&self) -> usize {
		match &self.clients {
			ClientBatch::Oprf(clients) => clients.len(),
			ClientBatch::Voprf(clients) => clients.len(),
			ClientBatch::Poprf(clients) => clients.len(),
		}
	}

	pub fn finalize<const N: usize>(&self, server: &CommonServerBatch<Cs>) -> [Output<Cs::Hash>; N]
	where
		[Output<Cs::Hash>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Output<Cs::Hash>> = [Output<Cs::Hash>; N]>>,
	{
		self.finalize_with::<N>(
			server.public_key(),
			&vec![INPUT; self.len()],
			server.evaluation_elements(),
			server.proof(),
			INFO,
		)
		.unwrap()
	}

	pub fn finalize_with<const N: usize>(
		&self,
		public_key: Option<&PublicKey<Cs::Group>>,
		inputs: &[&[&[u8]]],
		evaluation_elements: &[EvaluationElement<Cs>],
		proof: Option<&Proof<Cs>>,
		info: &[u8],
	) -> Result<[Output<Cs::Hash>; N]>
	where
		[Output<Cs::Hash>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Output<Cs::Hash>> = [Output<Cs::Hash>; N]>>,
	{
		match &self.clients {
			ClientBatch::Oprf(clients) => OprfClient::batch_finalize(
				clients[..N].try_into().unwrap(),
				inputs.try_into().unwrap(),
				evaluation_elements.try_into().unwrap(),
			),
			ClientBatch::Voprf(clients) => VoprfClient::batch_finalize(
				clients[..N].try_into().unwrap(),
				public_key.unwrap(),
				inputs.try_into().unwrap(),
				evaluation_elements.try_into().unwrap(),
				proof.unwrap(),
			),
			ClientBatch::Poprf(clients) => PoprfClient::batch_finalize(
				clients[..N].try_into().unwrap(),
				public_key.unwrap(),
				inputs.try_into().unwrap(),
				evaluation_elements.try_into().unwrap(),
				proof.unwrap(),
				info,
			),
		}
	}

	#[cfg(feature = "alloc")]
	pub fn finalize_alloc(&self, server: &CommonServerBatch<Cs>) -> Vec<Output<Cs::Hash>> {
		self.finalize_alloc_with(
			..,
			server.public_key(),
			iter::repeat_n(INPUT, self.len()),
			server.evaluation_elements.iter(),
			server.proof(),
			INFO,
		)
		.unwrap()
	}

	#[cfg(feature = "alloc")]
	pub fn finalize_alloc_with<'inputs, 'evaluation_elements, Ci, Ii, Iee>(
		&self,
		index: Ci,
		public_key: Option<&PublicKey<Cs::Group>>,
		inputs: Ii,
		evaluation_elements: Iee,
		proof: Option<&Proof<Cs>>,
		info: &[u8],
	) -> Result<Vec<Output<Cs::Hash>>>
	where
		Ci: SliceIndex<[OprfClient<Cs>], Output = [OprfClient<Cs>]>
			+ SliceIndex<[VoprfClient<Cs>], Output = [VoprfClient<Cs>]>
			+ SliceIndex<[PoprfClient<Cs>], Output = [PoprfClient<Cs>]>,
		Ii: ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
		Iee: ExactSizeIterator<Item = &'evaluation_elements EvaluationElement<Cs>>,
	{
		match &self.clients {
			ClientBatch::Oprf(clients) => OprfClient::batch_alloc_finalize(
				clients[index].iter(),
				inputs,
				evaluation_elements.into_iter(),
			),
			ClientBatch::Voprf(clients) => VoprfClient::batch_alloc_finalize(
				clients[index].iter(),
				public_key.unwrap(),
				inputs,
				evaluation_elements,
				proof.unwrap(),
			),
			ClientBatch::Poprf(clients) => PoprfClient::batch_alloc_finalize(
				clients[index].iter(),
				public_key.unwrap(),
				inputs,
				evaluation_elements,
				proof.unwrap(),
				info,
			),
		}
	}
}

impl<Cs: CipherSuite> CommonServer<Cs> {
	#[must_use]
	pub const fn secret_key(&self) -> &SecretKey<Cs::Group> {
		match &self.server {
			Server::Oprf(server) => server.secret_key(),
			Server::Voprf { server, .. } => server.key_pair().secret_key(),
			Server::Poprf { server, .. } => server.key_pair().secret_key(),
		}
	}

	#[must_use]
	pub const fn public_key(&self) -> Option<&PublicKey<Cs::Group>> {
		match &self.server {
			Server::Oprf(_) => None,
			Server::Voprf { server, .. } => Some(server.public_key()),
			Server::Poprf { server, .. } => Some(server.public_key()),
		}
	}

	#[must_use]
	pub const fn evaluation_element(&self) -> &EvaluationElement<Cs> {
		&self.evaluation_element
	}

	#[must_use]
	pub const fn proof(&self) -> Option<&Proof<Cs>> {
		match &self.server {
			Server::Oprf(_) => None,
			Server::Voprf { proof, .. } | Server::Poprf { proof, .. } => Some(proof),
		}
	}

	#[must_use]
	pub fn blind_evaluate(client: &CommonClient<Cs>) -> Self {
		let mode = match &client.client {
			Client::Oprf(_) => Mode::Oprf,
			Client::Voprf(_) => Mode::Voprf,
			Client::Poprf(_) => Mode::Poprf,
		};

		Self::blind_evaluate_with(mode, None, client.blinded_element(), None, INFO).unwrap()
	}

	pub fn blind_evaluate_with(
		mode: Mode,
		secret_key: Option<SecretKey<Cs::Group>>,
		blinded_element: &BlindedElement<Cs>,
		r: Option<&[u8]>,
		info: &[u8],
	) -> Result<Self, Error<<OsRng as TryRngCore>::Error>> {
		let mut rng = r.map_or_else(MockRng::new_os_rng, MockRng::new);

		match mode {
			Mode::Oprf => {
				let server = if let Some(secret_key) = secret_key {
					OprfServer::from_key(secret_key)
				} else {
					OprfServer::new(&mut OsRng).map_err(Error::Random)?
				};

				let evaluation_element = server.blind_evaluate(blinded_element);

				Ok(Self {
					server: Server::Oprf(server),
					evaluation_element,
				})
			}
			Mode::Voprf => {
				let server = if let Some(secret_key) = secret_key {
					VoprfServer::from_key_pair(KeyPair::from_secret_key(secret_key))
				} else {
					VoprfServer::new(&mut OsRng).map_err(Error::Random)?
				};

				let BlindEvaluateResult {
					evaluation_element,
					proof,
				} = server.blind_evaluate(&mut rng, blinded_element)?;

				Ok(Self {
					server: Server::Voprf { server, proof },
					evaluation_element,
				})
			}
			Mode::Poprf => {
				let server = if let Some(secret_key) = secret_key {
					PoprfServer::from_key_pair(KeyPair::from_secret_key(secret_key), info)
						.map_err(Error::into_random::<OsRng>)?
				} else {
					PoprfServer::new(&mut OsRng, info)?
				};

				let BlindEvaluateResult {
					evaluation_element,
					proof,
				} = server.blind_evaluate(&mut rng, blinded_element)?;

				Ok(Self {
					server: Server::Poprf { server, proof },
					evaluation_element,
				})
			}
		}
	}

	#[must_use]
	pub fn batch<const N: usize>(clients: &CommonClientBatch<Cs>) -> CommonServerBatch<Cs> {
		Self::batch_with::<N>(clients.mode(), None, &clients.blinded_elements, None, INFO).unwrap()
	}

	pub fn batch_with<const N: usize>(
		mode: Mode,
		secret_key: Option<SecretKey<Cs::Group>>,
		blinded_elements: &[BlindedElement<Cs>],
		r: Option<&[u8]>,
		info: &[u8],
	) -> Result<CommonServerBatch<Cs>, Error<<OsRng as TryRngCore>::Error>> {
		let mut rng = r.map_or_else(MockRng::new_os_rng, MockRng::new);

		match mode {
			Mode::Oprf => {
				let server = if let Some(secret_key) = secret_key {
					OprfServer::from_key(secret_key)
				} else {
					OprfServer::new(&mut OsRng).map_err(Error::Random)?
				};

				let evaluation_elements =
					server.batch_blind_evaluate::<N>(blinded_elements.try_into().unwrap());

				Ok(CommonServerBatch {
					server: Server::Oprf(server),
					evaluation_elements: evaluation_elements.to_vec(),
				})
			}
			Mode::Voprf => {
				let server = if let Some(secret_key) = secret_key {
					VoprfServer::from_key_pair(KeyPair::from_secret_key(secret_key))
				} else {
					VoprfServer::new(&mut OsRng).map_err(Error::Random)?
				};

				let BatchBlindEvaluateResult {
					evaluation_elements,
					proof,
				} = server
					.batch_blind_evaluate::<_, N>(&mut rng, blinded_elements.try_into().unwrap())?;

				Ok(CommonServerBatch {
					server: Server::Voprf { server, proof },
					evaluation_elements: evaluation_elements.to_vec(),
				})
			}
			Mode::Poprf => {
				let server = if let Some(secret_key) = secret_key {
					PoprfServer::from_key_pair(KeyPair::from_secret_key(secret_key), info)
						.map_err(Error::into_random::<OsRng>)?
				} else {
					PoprfServer::new(&mut OsRng, info)?
				};

				let BatchBlindEvaluateResult {
					evaluation_elements,
					proof,
				} = server
					.batch_blind_evaluate::<_, N>(&mut rng, blinded_elements.try_into().unwrap())?;

				Ok(CommonServerBatch {
					server: Server::Poprf { server, proof },
					evaluation_elements: evaluation_elements.to_vec(),
				})
			}
		}
	}

	#[must_use]
	#[cfg(feature = "alloc")]
	pub fn batch_alloc(clients: &CommonClientBatch<Cs>) -> CommonServerBatch<Cs> {
		Self::batch_alloc_with(clients.mode(), None, &clients.blinded_elements, None, INFO).unwrap()
	}

	#[cfg(feature = "alloc")]
	pub fn batch_alloc_with(
		mode: Mode,
		secret_key: Option<SecretKey<Cs::Group>>,
		blinded_elements: &[BlindedElement<Cs>],
		r: Option<&[u8]>,
		info: &[u8],
	) -> Result<CommonServerBatch<Cs>, Error<<OsRng as TryRngCore>::Error>> {
		let mut rng = r.map_or_else(MockRng::new_os_rng, MockRng::new);

		match mode {
			Mode::Oprf => {
				let server = if let Some(secret_key) = secret_key {
					OprfServer::from_key(secret_key)
				} else {
					OprfServer::new(&mut OsRng).map_err(Error::Random)?
				};

				let evaluation_elements =
					server.batch_alloc_blind_evaluate(blinded_elements.iter());

				Ok(CommonServerBatch {
					server: Server::Oprf(server),
					evaluation_elements,
				})
			}
			Mode::Voprf => {
				let server = if let Some(secret_key) = secret_key {
					VoprfServer::from_key_pair(KeyPair::from_secret_key(secret_key))
				} else {
					VoprfServer::new(&mut OsRng).map_err(Error::Random)?
				};

				let BatchAllocBlindEvaluateResult {
					evaluation_elements,
					proof,
				} = server.batch_alloc_blind_evaluate(&mut rng, blinded_elements.iter())?;

				Ok(CommonServerBatch {
					server: Server::Voprf { server, proof },
					evaluation_elements,
				})
			}
			Mode::Poprf => {
				let server = if let Some(secret_key) = secret_key {
					PoprfServer::from_key_pair(KeyPair::from_secret_key(secret_key), info)
						.map_err(Error::into_random::<OsRng>)?
				} else {
					PoprfServer::new(&mut OsRng, info)?
				};

				let BatchAllocBlindEvaluateResult {
					evaluation_elements,
					proof,
				} = server.batch_alloc_blind_evaluate(&mut rng, blinded_elements.iter())?;

				Ok(CommonServerBatch {
					server: Server::Poprf { server, proof },
					evaluation_elements,
				})
			}
		}
	}

	pub fn evaluate(&self) -> Output<Cs::Hash> {
		self.evaluate_with(INPUT, INFO).unwrap()
	}

	pub fn evaluate_with(&self, input: &[&[u8]], info: &[u8]) -> Result<Output<Cs::Hash>> {
		match &self.server {
			Server::Oprf(server) => server.evaluate(input),
			Server::Voprf { server, .. } => server.evaluate(input),
			Server::Poprf { server, .. } => server.evaluate(input, info),
		}
	}
}

impl<Cs: CipherSuite> CommonServerBatch<Cs> {
	#[must_use]
	pub const fn secret_key(&self) -> &SecretKey<Cs::Group> {
		match &self.server {
			Server::Oprf(server) => server.secret_key(),
			Server::Voprf { server, .. } => server.key_pair().secret_key(),
			Server::Poprf { server, .. } => server.key_pair().secret_key(),
		}
	}

	#[must_use]
	pub const fn public_key(&self) -> Option<&PublicKey<Cs::Group>> {
		match &self.server {
			Server::Oprf(_) => None,
			Server::Voprf { server, .. } => Some(server.public_key()),
			Server::Poprf { server, .. } => Some(server.public_key()),
		}
	}

	#[must_use]
	pub fn evaluation_elements(&self) -> &[EvaluationElement<Cs>] {
		&self.evaluation_elements
	}

	#[must_use]
	pub const fn proof(&self) -> Option<&Proof<Cs>> {
		match &self.server {
			Server::Oprf(_) => None,
			Server::Voprf { proof, .. } | Server::Poprf { proof, .. } => Some(proof),
		}
	}

	pub fn push(&mut self, evaluation_element: EvaluationElement<Cs>) {
		self.evaluation_elements.push(evaluation_element);
	}

	pub fn evaluate<const N: usize>(&self) -> [Output<Cs::Hash>; N]
	where
		[Element<Cs>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Element<Cs>> = [Element<Cs>; N]>>,
		[Output<Cs::Hash>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Output<Cs::Hash>> = [Output<Cs::Hash>; N]>>,
	{
		self.evaluate_with(&[INPUT; N], INFO).unwrap()
	}

	pub fn evaluate_with<const N: usize>(
		&self,
		inputs: &[&[&[u8]]],
		info: &[u8],
	) -> Result<[Output<Cs::Hash>; N]>
	where
		[Element<Cs>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Element<Cs>> = [Element<Cs>; N]>>,
		[Output<Cs::Hash>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Output<Cs::Hash>> = [Output<Cs::Hash>; N]>>,
	{
		match &self.server {
			Server::Oprf(server) => server.batch_evaluate(inputs.try_into().unwrap()),
			Server::Voprf { server, .. } => server.batch_evaluate(inputs.try_into().unwrap()),
			Server::Poprf { server, .. } => server.batch_evaluate(inputs.try_into().unwrap(), info),
		}
	}

	#[cfg(feature = "alloc")]
	pub fn evaluate_alloc(&self) -> Vec<Output<Cs::Hash>> {
		self.evaluate_alloc_with(&vec![INPUT; self.evaluation_elements.len()], INFO)
			.unwrap()
	}

	#[cfg(feature = "alloc")]
	pub fn evaluate_alloc_with(
		&self,
		inputs: &[&[&[u8]]],
		info: &[u8],
	) -> Result<Vec<Output<Cs::Hash>>> {
		match &self.server {
			Server::Oprf(server) => server.batch_alloc_evaluate(inputs),
			Server::Voprf { server, .. } => server.batch_alloc_evaluate(inputs),
			Server::Poprf { server, .. } => server.batch_alloc_evaluate(inputs, info),
		}
	}
}

impl<Cs: CipherSuite> From<OprfClient<Cs>> for Client<Cs> {
	fn from(client: OprfClient<Cs>) -> Self {
		Self::Oprf(client)
	}
}

impl<Cs: CipherSuite> From<VoprfClient<Cs>> for Client<Cs> {
	fn from(client: VoprfClient<Cs>) -> Self {
		Self::Voprf(client)
	}
}

impl<Cs: CipherSuite> From<PoprfClient<Cs>> for Client<Cs> {
	fn from(client: PoprfClient<Cs>) -> Self {
		Self::Poprf(client)
	}
}
