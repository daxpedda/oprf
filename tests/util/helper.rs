//! Abstracts over all [`Mode`]s to reduce the amount of duplicate code in
//! tests.

use std::iter;
use std::slice::SliceIndex;

use derive_where::derive_where;
use digest::Output;
use hybrid_array::{ArraySize, AssocArraySize};
use oprf::ciphersuite::CipherSuite;
use oprf::common::{BlindedElement, EvaluationElement, Mode, Proof};
use oprf::group::Group;
use oprf::key::PublicKey;
use oprf::oprf::{OprfBlindResult, OprfClient, OprfServer};
#[cfg(feature = "alloc")]
use oprf::poprf::PoprfBatchBlindEvaluateResult;
use oprf::poprf::{
	PoprfBatchBlindEvaluateFixedResult, PoprfBlindEvaluateResult, PoprfBlindResult, PoprfClient,
	PoprfServer,
};
#[cfg(feature = "alloc")]
use oprf::voprf::VoprfBatchBlindEvaluateResult;
use oprf::voprf::{
	VoprfBatchBlindEvaluateFixedResult, VoprfBlindEvaluateResult, VoprfBlindResult, VoprfClient,
	VoprfServer,
};
use oprf::{Error, Result};
use rand::TryRngCore;
use rand_core::OsRng;

use super::{INFO, INPUT};

type CsGroup<CS> = <CS as CipherSuite>::Group;
type Scalar<CS> = <CsGroup<CS> as Group>::Scalar;
type NonIdentityElement<CS> = <CsGroup<CS> as Group>::NonIdentityElement;
type Element<CS> = <CsGroup<CS> as Group>::Element;

/// Wrapper around clients in all [`Mode`]s.
#[derive_where(Debug)]
enum Client<CS: CipherSuite> {
	Oprf(OprfClient<CS>),
	Voprf(VoprfClient<CS>),
	Poprf(PoprfClient<CS>),
}

/// Wrapper around clients in all [`Mode`]s and their `Blind` output.
#[derive_where(Debug)]
pub struct HelperClient<CS: CipherSuite> {
	client: Client<CS>,
	blinded_element: BlindedElement<CS>,
}

/// Wrapper around multiple clients in all [`Mode`]s.
#[derive_where(Debug)]
enum ClientBatch<CS: CipherSuite> {
	Oprf(Vec<OprfClient<CS>>),
	Voprf(Vec<VoprfClient<CS>>),
	Poprf(Vec<PoprfClient<CS>>),
}

/// Wrapper around multiple clients in all [`Mode`]s and their `Blind` output.
#[derive_where(Debug)]
pub struct HelperClientBatch<CS: CipherSuite> {
	clients: ClientBatch<CS>,
	blinded_elements: Vec<BlindedElement<CS>>,
}

/// Wrapper around servers in all [`Mode`]s and potentially their
/// `BlindEvaluate` [`Proof`] output.
#[derive_where(Debug)]
enum Server<CS: CipherSuite> {
	Oprf(OprfServer<CS>),
	Voprf {
		server: VoprfServer<CS>,
		proof: Proof<CS>,
	},
	Poprf {
		server: PoprfServer<CS>,
		proof: Proof<CS>,
	},
}

/// Wrapper around servers in all [`Mode`]s and their `BlindEvalaute` output.
#[derive_where(Debug)]
pub struct HelperServer<CS: CipherSuite> {
	server: Server<CS>,
	evaluation_element: EvaluationElement<CS>,
}

/// Wrapper around servers in all [`Mode`]s and their batched `BlindEvalaute`
/// output.
#[derive_where(Debug)]
pub struct HelperServerBatch<CS: CipherSuite> {
	server: Server<CS>,
	evaluation_elements: Vec<EvaluationElement<CS>>,
}

impl<CS: CipherSuite> HelperClient<CS> {
	#[must_use]
	pub fn blinded_element(&self) -> &BlindedElement<CS> {
		&self.blinded_element
	}

	#[must_use]
	pub fn blind(mode: Mode) -> Self {
		Self::blind_with(mode, INPUT).unwrap()
	}

	pub fn blind_with(
		mode: Mode,
		input: &[&[u8]],
	) -> Result<Self, Error<<OsRng as TryRngCore>::Error>> {
		match mode {
			Mode::Oprf => {
				let OprfBlindResult {
					client,
					blinded_element,
				} = OprfClient::<CS>::blind(&mut OsRng, input)?;

				Ok(Self {
					client: client.into(),
					blinded_element,
				})
			}
			Mode::Voprf => {
				let VoprfBlindResult {
					client,
					blinded_element,
				} = VoprfClient::blind(&mut OsRng, input)?;

				Ok(Self {
					client: client.into(),
					blinded_element,
				})
			}
			Mode::Poprf => {
				let PoprfBlindResult {
					client,
					blinded_element,
				} = PoprfClient::blind(&mut OsRng, input)?;

				Ok(Self {
					client: client.into(),
					blinded_element,
				})
			}
		}
	}

	#[must_use]
	pub fn batch(mode: Mode, count: usize) -> HelperClientBatch<CS> {
		iter::repeat_with(|| {
			let Self {
				client,
				blinded_element,
			} = Self::blind(mode);

			(client, blinded_element)
		})
		.take(count)
		.collect()
	}

	pub fn batch_with(
		mode: Mode,
		count: usize,
		input: &[&[u8]],
	) -> Result<HelperClientBatch<CS>, Error<<OsRng as TryRngCore>::Error>> {
		iter::repeat_with(|| {
			let Self {
				client,
				blinded_element,
			} = Self::blind_with(mode, input)?;

			Ok((client, blinded_element))
		})
		.take(count)
		.collect()
	}

	#[must_use]
	pub fn batch_clone(mode: Mode, count: usize) -> HelperClientBatch<CS> {
		let Self {
			client,
			blinded_element,
		} = Self::blind(mode);

		HelperClientBatch {
			clients: match client {
				Client::Oprf(_) => panic!("OPRF doesn't have batching functionality"),
				Client::Voprf(client) => ClientBatch::Voprf(vec![client; count]),
				Client::Poprf(client) => ClientBatch::Poprf(vec![client; count]),
			},
			blinded_elements: vec![blinded_element; count],
		}
	}

	#[must_use]
	pub fn finalize(&self, server: &HelperServer<CS>) -> Output<CS::Hash> {
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
		public_key: Option<&PublicKey<CS::Group>>,
		input: &[&[u8]],
		evaluation_element: &EvaluationElement<CS>,
		proof: Option<&Proof<CS>>,
		info: &[u8],
	) -> Result<Output<CS::Hash>> {
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

impl<CS: CipherSuite> HelperClientBatch<CS> {
	#[must_use]
	fn mode(&self) -> Mode {
		match self.clients {
			ClientBatch::Oprf(_) => Mode::Oprf,
			ClientBatch::Voprf(_) => Mode::Voprf,
			ClientBatch::Poprf(_) => Mode::Poprf,
		}
	}

	#[must_use]
	pub fn blinded_elements(&self) -> &[BlindedElement<CS>] {
		&self.blinded_elements
	}

	fn len(&self) -> usize {
		match &self.clients {
			ClientBatch::Oprf(clients) => clients.len(),
			ClientBatch::Voprf(clients) => clients.len(),
			ClientBatch::Poprf(clients) => clients.len(),
		}
	}

	#[cfg(feature = "alloc")]
	pub fn finalize(&self, server: &HelperServerBatch<CS>) -> Vec<Output<CS::Hash>> {
		self.finalize_with(
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
	pub fn finalize_with<'inputs, 'evaluation_elements, CI, II, IEE>(
		&self,
		index: CI,
		public_key: Option<&PublicKey<CS::Group>>,
		inputs: II,
		evaluation_elements: IEE,
		proof: Option<&Proof<CS>>,
		info: &[u8],
	) -> Result<Vec<Output<CS::Hash>>>
	where
		CI: SliceIndex<[OprfClient<CS>], Output = [OprfClient<CS>]>
			+ SliceIndex<[VoprfClient<CS>], Output = [VoprfClient<CS>]>
			+ SliceIndex<[PoprfClient<CS>], Output = [PoprfClient<CS>]>,
		II: ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
		IEE: ExactSizeIterator<Item = &'evaluation_elements EvaluationElement<CS>>,
	{
		match &self.clients {
			ClientBatch::Oprf(clients) => OprfClient::batch_finalize(
				clients[index].iter(),
				inputs,
				evaluation_elements.into_iter(),
			),
			ClientBatch::Voprf(clients) => VoprfClient::batch_finalize(
				clients[index].iter(),
				public_key.unwrap(),
				inputs,
				evaluation_elements,
				proof.unwrap(),
			),
			ClientBatch::Poprf(clients) => PoprfClient::batch_finalize(
				clients[index].iter(),
				public_key.unwrap(),
				inputs,
				evaluation_elements,
				proof.unwrap(),
				info,
			),
		}
	}

	pub fn finalize_fixed<const N: usize>(
		&self,
		server: &HelperServerBatch<CS>,
	) -> [Output<CS::Hash>; N]
	where
		[Output<CS::Hash>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Output<CS::Hash>> = [Output<CS::Hash>; N]>>,
	{
		self.finalize_fixed_with::<N, _>(
			server.public_key(),
			iter::repeat_n(INPUT, self.len()),
			server.evaluation_elements(),
			server.proof(),
			INFO,
		)
		.unwrap()
	}

	pub fn finalize_fixed_with<'inputs, const N: usize, II>(
		&self,
		public_key: Option<&PublicKey<CS::Group>>,
		inputs: II,
		evaluation_elements: &[EvaluationElement<CS>],
		proof: Option<&Proof<CS>>,
		info: &[u8],
	) -> Result<[Output<CS::Hash>; N]>
	where
		[Output<CS::Hash>; N]:
			AssocArraySize<Size: ArraySize<ArrayType<Output<CS::Hash>> = [Output<CS::Hash>; N]>>,
		II: ExactSizeIterator<Item = &'inputs [&'inputs [u8]]>,
	{
		match &self.clients {
			ClientBatch::Oprf(clients) => OprfClient::batch_finalize_fixed(
				clients[..N].try_into().unwrap(),
				inputs,
				evaluation_elements.try_into().unwrap(),
			),
			ClientBatch::Voprf(clients) => VoprfClient::batch_finalize_fixed(
				clients[..N].try_into().unwrap(),
				public_key.unwrap(),
				inputs,
				evaluation_elements.try_into().unwrap(),
				proof.unwrap(),
			),
			ClientBatch::Poprf(clients) => PoprfClient::batch_finalize_fixed(
				clients[..N].try_into().unwrap(),
				public_key.unwrap(),
				inputs,
				evaluation_elements.try_into().unwrap(),
				proof.unwrap(),
				info,
			),
		}
	}
}

impl<CS: CipherSuite> HelperServer<CS> {
	#[must_use]
	pub fn public_key(&self) -> Option<&PublicKey<CS::Group>> {
		match &self.server {
			Server::Oprf(_) => None,
			Server::Voprf { server, .. } => Some(server.public_key()),
			Server::Poprf { server, .. } => Some(server.public_key()),
		}
	}

	#[must_use]
	pub fn evaluation_element(&self) -> &EvaluationElement<CS> {
		&self.evaluation_element
	}

	#[must_use]
	pub fn proof(&self) -> Option<&Proof<CS>> {
		match &self.server {
			Server::Oprf(_) => None,
			Server::Voprf { proof, .. } | Server::Poprf { proof, .. } => Some(proof),
		}
	}

	#[must_use]
	pub fn blind_evaluate(helper: &HelperClient<CS>) -> Self {
		Self::blind_evaluate_with(helper, INFO).unwrap()
	}

	pub fn blind_evaluate_with(
		helper: &HelperClient<CS>,
		info: &[u8],
	) -> Result<Self, Error<<OsRng as TryRngCore>::Error>> {
		match &helper.client {
			Client::Oprf(_) => {
				let server = OprfServer::new(&mut OsRng).unwrap();
				let evaluation_element = server.blind_evaluate(&helper.blinded_element);

				Ok(Self {
					server: Server::Oprf(server),
					evaluation_element,
				})
			}
			Client::Voprf(_) => {
				let server = VoprfServer::new(&mut OsRng).unwrap();
				let VoprfBlindEvaluateResult {
					evaluation_element,
					proof,
				} = server.blind_evaluate(&mut OsRng, &helper.blinded_element)?;

				Ok(Self {
					server: Server::Voprf { server, proof },
					evaluation_element,
				})
			}
			Client::Poprf(_) => {
				let server = PoprfServer::new(&mut OsRng, info)?;
				let PoprfBlindEvaluateResult {
					evaluation_element,
					proof,
				} = server.blind_evaluate(&mut OsRng, &helper.blinded_element)?;

				Ok(Self {
					server: Server::Poprf { server, proof },
					evaluation_element,
				})
			}
		}
	}

	pub fn batch_fixed<const N: usize>(clients: &HelperClientBatch<CS>) -> HelperServerBatch<CS> {
		Self::batch_fixed_with::<N>(clients.mode(), &clients.blinded_elements, INFO).unwrap()
	}

	pub fn batch_fixed_with<const N: usize>(
		mode: Mode,
		blinded_elements: &[BlindedElement<CS>],
		info: &[u8],
	) -> Result<HelperServerBatch<CS>, Error<<OsRng as TryRngCore>::Error>> {
		match mode {
			Mode::Oprf => {
				let server = OprfServer::new(&mut OsRng).unwrap();

				let evaluation_elements = blinded_elements
					.iter()
					.map(|blinded_element| server.blind_evaluate(blinded_element))
					.collect();

				Ok(HelperServerBatch {
					server: Server::Oprf(server),
					evaluation_elements,
				})
			}
			Mode::Voprf => {
				let server = VoprfServer::new(&mut OsRng).unwrap();
				let VoprfBatchBlindEvaluateFixedResult {
					evaluation_elements,
					proof,
				} = server.batch_blind_evaluate_fixed::<_, N>(
					&mut OsRng,
					blinded_elements.try_into().unwrap(),
				)?;

				Ok(HelperServerBatch {
					server: Server::Voprf { server, proof },
					evaluation_elements: evaluation_elements.to_vec(),
				})
			}
			Mode::Poprf => {
				let server = PoprfServer::new(&mut OsRng, info)?;
				let PoprfBatchBlindEvaluateFixedResult {
					evaluation_elements,
					proof,
				} = server.batch_blind_evaluate_fixed::<_, N>(
					&mut OsRng,
					blinded_elements.try_into().unwrap(),
				)?;

				Ok(HelperServerBatch {
					server: Server::Poprf { server, proof },
					evaluation_elements: evaluation_elements.to_vec(),
				})
			}
		}
	}

	#[cfg(feature = "alloc")]
	pub fn batch(clients: &HelperClientBatch<CS>) -> HelperServerBatch<CS> {
		Self::batch_with(clients.mode(), &clients.blinded_elements, INFO).unwrap()
	}

	#[cfg(feature = "alloc")]
	pub fn batch_with(
		mode: Mode,
		blinded_elements: &[BlindedElement<CS>],
		info: &[u8],
	) -> Result<HelperServerBatch<CS>, Error<<OsRng as TryRngCore>::Error>> {
		match mode {
			Mode::Oprf => {
				let server = OprfServer::new(&mut OsRng).unwrap();

				let evaluation_elements = blinded_elements
					.iter()
					.map(|blinded_element| server.blind_evaluate(blinded_element))
					.collect();

				Ok(HelperServerBatch {
					server: Server::Oprf(server),
					evaluation_elements,
				})
			}
			Mode::Voprf => {
				let server = VoprfServer::new(&mut OsRng).unwrap();
				let VoprfBatchBlindEvaluateResult {
					evaluation_elements,
					proof,
				} = server.batch_blind_evaluate(&mut OsRng, blinded_elements.iter())?;

				Ok(HelperServerBatch {
					server: Server::Voprf { server, proof },
					evaluation_elements,
				})
			}
			Mode::Poprf => {
				let server = PoprfServer::new(&mut OsRng, info)?;
				let PoprfBatchBlindEvaluateResult {
					evaluation_elements,
					proof,
				} = server.batch_blind_evaluate(&mut OsRng, blinded_elements.iter())?;

				Ok(HelperServerBatch {
					server: Server::Poprf { server, proof },
					evaluation_elements,
				})
			}
		}
	}

	pub fn evaluate(&self) -> Output<CS::Hash> {
		self.evaluate_with(INPUT, INFO).unwrap()
	}

	pub fn evaluate_with(&self, input: &[&[u8]], info: &[u8]) -> Result<Output<CS::Hash>> {
		match &self.server {
			Server::Oprf(server) => server.evaluate(input),
			Server::Voprf { server, .. } => server.evaluate(input),
			Server::Poprf { server, .. } => server.evaluate(input, info),
		}
	}
}

impl<CS: CipherSuite> HelperServerBatch<CS> {
	#[must_use]
	pub fn public_key(&self) -> Option<&PublicKey<CS::Group>> {
		match &self.server {
			Server::Oprf(_) => None,
			Server::Voprf { server, .. } => Some(server.public_key()),
			Server::Poprf { server, .. } => Some(server.public_key()),
		}
	}

	#[must_use]
	pub fn evaluation_elements(&self) -> &[EvaluationElement<CS>] {
		&self.evaluation_elements
	}

	#[must_use]
	pub fn proof(&self) -> Option<&Proof<CS>> {
		match &self.server {
			Server::Oprf(_) => None,
			Server::Voprf { proof, .. } | Server::Poprf { proof, .. } => Some(proof),
		}
	}

	pub fn push(&mut self, evaluation_element: EvaluationElement<CS>) {
		self.evaluation_elements.push(evaluation_element);
	}

	pub fn evaluate(&self) -> Output<CS::Hash> {
		self.evaluate_with(INPUT, INFO).unwrap()
	}

	pub fn evaluate_with(&self, input: &[&[u8]], info: &[u8]) -> Result<Output<CS::Hash>> {
		match &self.server {
			Server::Oprf(server) => server.evaluate(input),
			Server::Voprf { server, .. } => server.evaluate(input),
			Server::Poprf { server, .. } => server.evaluate(input, info),
		}
	}
}

impl<CS: CipherSuite> From<OprfClient<CS>> for Client<CS> {
	fn from(client: OprfClient<CS>) -> Self {
		Self::Oprf(client)
	}
}

impl<CS: CipherSuite> From<VoprfClient<CS>> for Client<CS> {
	fn from(client: VoprfClient<CS>) -> Self {
		Self::Voprf(client)
	}
}

impl<CS: CipherSuite> From<PoprfClient<CS>> for Client<CS> {
	fn from(client: PoprfClient<CS>) -> Self {
		Self::Poprf(client)
	}
}

impl<CS: CipherSuite> FromIterator<(Client<CS>, BlindedElement<CS>)> for HelperClientBatch<CS> {
	fn from_iter<T: IntoIterator<Item = (Client<CS>, BlindedElement<CS>)>>(iter: T) -> Self {
		let mut items = iter.into_iter().peekable();

		let Some((client, _)) = items.peek() else {
			return Self {
				clients: ClientBatch::Voprf(Vec::new()),
				blinded_elements: Vec::new(),
			};
		};

		match client {
			Client::Oprf(_) => {
				let (clients, blinded_elements) = items
					.map(|(client, blinded_element)| {
						let Client::Oprf(client) = client else {
							panic!("attempting to create `ClientBatch` from non-uniform clients")
						};
						(client, blinded_element)
					})
					.unzip();

				Self {
					clients: ClientBatch::Oprf(clients),
					blinded_elements,
				}
			}
			Client::Voprf(_) => {
				let (clients, blinded_elements) = items
					.map(|(client, blinded_element)| {
						let Client::Voprf(client) = client else {
							panic!("attempting to create `ClientBatch` from non-uniform clients")
						};
						(client, blinded_element)
					})
					.unzip();

				Self {
					clients: ClientBatch::Voprf(clients),
					blinded_elements,
				}
			}
			Client::Poprf(_) => {
				let (clients, blinded_elements) = items
					.map(|(client, blinded_element)| {
						let Client::Poprf(client) = client else {
							panic!("attempting to create `ClientBatch` from non-uniform clients")
						};
						(client, blinded_element)
					})
					.unzip();

				Self {
					clients: ClientBatch::Poprf(clients),
					blinded_elements,
				}
			}
		}
	}
}
