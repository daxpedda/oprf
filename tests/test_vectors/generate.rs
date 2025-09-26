use std::array;

use oprf::cipher_suite::CipherSuite;
use oprf::common::Mode;
use oprf::group::Group;
use oprf::key::{PublicKey, SecretKey};
use oprf::{Decaf448, NistP256, NistP384, NistP521, Ristretto255};
use oprf_test::common::{Client, ClientBatch, Server};
use oprf_test::{CommonClient, CommonServer, Edwards448, Edwards25519, Secp256k1};
use serde::Serialize;

use crate::parse::{Data, DataType, Proof, TestVector};

pub fn generate() -> Vec<TestVector> {
	[Mode::Oprf, Mode::Voprf, Mode::Poprf]
		.into_iter()
		.flat_map(|mode| {
			[
				cipher_suite::<Secp256k1>(mode),
				cipher_suite::<NistP256>(mode),
				cipher_suite::<NistP384>(mode),
				cipher_suite::<NistP521>(mode),
				cipher_suite::<Edwards25519>(mode),
				cipher_suite::<Ristretto255>(mode),
				cipher_suite::<Edwards448>(mode),
				cipher_suite::<Decaf448>(mode),
			]
		})
		.flatten()
		.collect()
}

fn cipher_suite<Cs>(mode: Mode) -> [TestVector; 2]
where
	Cs: CipherSuite<Group: Group<NonZeroScalar: Serialize, Scalar: Serialize>>,
{
	[basic::<Cs>(mode), batch::<Cs>(mode)]
}

fn basic<Cs>(mode: Mode) -> TestVector
where
	Cs: CipherSuite<Group: Group<NonZeroScalar: Serialize, Scalar: Serialize>>,
{
	let identifier = str::from_utf8(&Cs::ID).unwrap().to_owned();
	let seed = rand::random();
	let key_info: Vec<_> = rand::random_iter()
		.take(rand::random_range(0..128))
		.collect();

	let secret_key = SecretKey::derive::<Cs>(mode, &seed, &key_info).unwrap();
	let secret_key_json = serde_json::to_string(&secret_key).unwrap();

	let public_key = PublicKey::from_secret_key(&secret_key);
	let public_key_json = serde_json::to_string(&public_key).unwrap();

	let info = matches!(mode, Mode::Poprf).then(|| {
		rand::random_iter()
			.take(rand::random_range(0..128))
			.collect::<Vec<_>>()
	});

	let input: Vec<_> = rand::random_iter()
		.take(rand::random_range(0..128))
		.collect();

	let blind: Vec<_> =
		Cs::Group::scalar_to_repr(&Cs::Group::scalar_random(&mut rand::rng()).unwrap()).into();

	let client = CommonClient::<Cs>::blind_with(mode, Some(&blind), &[&input]).unwrap();
	let client_json = match client.client() {
		Client::Oprf(client) => serde_json::to_string(client),
		Client::Voprf(client) => serde_json::to_string(client),
		Client::Poprf(client) => serde_json::to_string(client),
	}
	.unwrap();

	let blinded_element = client.blinded_element();
	let blinded_element_json = serde_json::to_string(blinded_element).unwrap();

	let r = matches!(mode, Mode::Voprf | Mode::Poprf).then(|| {
		Cs::Group::scalar_to_repr(&Cs::Group::scalar_random(&mut rand::rng()).unwrap()).into()
	});

	let server = CommonServer::blind_evaluate_with(
		mode,
		Some(secret_key.clone()),
		blinded_element,
		r.as_deref(),
		info.as_deref(),
	)
	.unwrap();
	let server_json = match server.server() {
		Server::Oprf(server) => serde_json::to_string(server),
		Server::Voprf(server) => serde_json::to_string(server),
		Server::Poprf(server) => serde_json::to_string(server),
	}
	.unwrap();

	let evaluation_element = server.evaluation_element();
	let evaluation_element_json = serde_json::to_string(evaluation_element).unwrap();

	let proof = matches!(mode, Mode::Voprf | Mode::Poprf).then(|| {
		let proof = server.proof().unwrap();
		let json = serde_json::to_string(proof).unwrap();

		Proof {
			repr: proof.to_repr().into(),
			json,
			r: r.unwrap(),
		}
	});

	let output = server
		.evaluate_with(&[&input], info.as_deref())
		.unwrap()
		.into();

	TestVector {
		identifier,
		mode,
		seed,
		key_info,
		secret_key: secret_key.to_repr().into(),
		secret_key_json,
		public_key: public_key.as_repr().into(),
		public_key_json,
		server_json,
		info,
		proof,
		data: DataType::Basic(Data {
			input,
			client_json,
			blind,
			blinded_element: blinded_element.as_repr().into(),
			blinded_element_json,
			evaluation_element: evaluation_element.as_repr().into(),
			evaluation_element_json,
			output,
		}),
	}
}

#[expect(
	clippy::indexing_slicing,
	clippy::missing_asserts_for_indexing,
	clippy::too_many_lines,
	reason = "test"
)]
fn batch<Cs>(mode: Mode) -> TestVector
where
	Cs: CipherSuite<Group: Group<NonZeroScalar: Serialize, Scalar: Serialize>>,
{
	let identifier = str::from_utf8(&Cs::ID).unwrap().to_owned();
	let seed = rand::random();
	let key_info: Vec<_> = rand::random_iter()
		.take(rand::random_range(0..128))
		.collect();

	let secret_key = SecretKey::derive::<Cs>(mode, &seed, &key_info).unwrap();
	let secret_key_json = serde_json::to_string(&secret_key).unwrap();

	let public_key = PublicKey::from_secret_key(&secret_key);
	let public_key_json = serde_json::to_string(&public_key).unwrap();

	let info = matches!(mode, Mode::Poprf).then(|| {
		rand::random_iter()
			.take(rand::random_range(0..128))
			.collect::<Vec<_>>()
	});

	let [input_1, input_2] = array::from_fn(|_| {
		rand::random_iter()
			.take(rand::random_range(0..128))
			.collect::<Vec<_>>()
	});

	let [blind_1, blind_2] = array::from_fn(|_| {
		Vec::from(Cs::Group::scalar_to_repr(
			&Cs::Group::scalar_random(&mut rand::rng()).unwrap(),
		))
	});

	let clients = CommonClient::<Cs>::batch_with(
		mode,
		Some(&[&blind_1, &blind_2]),
		&[&[&input_1], &[&input_2]],
	)
	.unwrap();
	let [client_json_1, client_json_2] = array::from_fn(|index| {
		match clients.clients() {
			ClientBatch::Oprf(clients) => serde_json::to_string(&clients[index]),
			ClientBatch::Voprf(clients) => serde_json::to_string(&clients[index]),
			ClientBatch::Poprf(clients) => serde_json::to_string(&clients[index]),
		}
		.unwrap()
	});

	let blinded_elements = clients.blinded_elements();
	let [blinded_element_json_1, blinded_element_json_2] =
		array::from_fn(|index| serde_json::to_string(&blinded_elements[index]).unwrap());

	let r = matches!(mode, Mode::Voprf | Mode::Poprf).then(|| {
		Cs::Group::scalar_to_repr(&Cs::Group::scalar_random(&mut rand::rng()).unwrap()).into()
	});

	let server = CommonServer::batch_with::<2>(
		mode,
		Some(secret_key.clone()),
		blinded_elements,
		r.as_deref(),
		info.as_deref(),
	)
	.unwrap();
	let server_json = match server.server() {
		Server::Oprf(server) => serde_json::to_string(server),
		Server::Voprf(server) => serde_json::to_string(server),
		Server::Poprf(server) => serde_json::to_string(server),
	}
	.unwrap();

	let evaluation_elements = server.evaluation_elements();
	let [evaluation_element_json_1, evaluation_element_json_2] =
		array::from_fn(|index| serde_json::to_string(&evaluation_elements[index]).unwrap());

	let proof = matches!(mode, Mode::Voprf | Mode::Poprf).then(|| {
		let proof = server.proof().unwrap();
		let json = serde_json::to_string(proof).unwrap();

		Proof {
			repr: proof.to_repr().into(),
			json,
			r: r.unwrap(),
		}
	});

	let [output_1, output_2] = server
		.evaluate_with::<2>(&[&[&input_1], &[&input_2]], info.as_deref())
		.unwrap();

	TestVector {
		identifier,
		mode,
		seed,
		key_info,
		secret_key: secret_key.to_repr().into(),
		secret_key_json,
		public_key: public_key.as_repr().into(),
		public_key_json,
		server_json,
		info,
		proof,
		data: DataType::Batch([
			Data {
				input: input_1,
				client_json: client_json_1,
				blind: blind_1,
				blinded_element: blinded_elements[0].as_repr().into(),
				blinded_element_json: blinded_element_json_1,
				evaluation_element: evaluation_elements[0].as_repr().into(),
				evaluation_element_json: evaluation_element_json_1,
				output: output_1.into(),
			},
			Data {
				input: input_2,
				client_json: client_json_2,
				blind: blind_2,
				blinded_element: blinded_elements[1].as_repr().into(),
				blinded_element_json: blinded_element_json_2,
				evaluation_element: evaluation_elements[1].as_repr().into(),
				evaluation_element_json: evaluation_element_json_2,
				output: output_2.into(),
			},
		]),
	}
}
