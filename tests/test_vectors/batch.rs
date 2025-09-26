//! Batched test vectors test.

use core::slice;
use std::ops::Deref;

use oprf::cipher_suite::CipherSuite;
use oprf::common::{BlindedElement, EvaluationElement, Mode, Proof};
#[cfg(feature = "serde")]
use oprf::group::Group;
use oprf::key::{PublicKey, SecretKey};
#[cfg(feature = "serde")]
use oprf_test::common::ClientBatch;
#[cfg(feature = "serde")]
use oprf_test::common::Server;
use oprf_test::{CommonClient, CommonServer, test_ciphersuites};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::parse::{DataType, TEST_VECTORS};

test_ciphersuites!(test, Mode);

/// Tests non-batched test vectors.
#[expect(clippy::too_many_lines, reason = "test")]
#[cfg_attr(
	feature = "serde",
	expect(
		clippy::cognitive_complexity,
		clippy::indexing_slicing,
		reason = "test"
	)
)]
fn test<
	#[cfg(not(feature = "serde"))] Cs: CipherSuite,
	#[cfg(feature = "serde")] Cs: CipherSuite<
		Group: Group<
			NonZeroScalar: for<'de> Deserialize<'de> + Serialize,
			Scalar: for<'de> Deserialize<'de> + Serialize,
		>,
	>,
>(
	mode: Mode,
) {
	let mut tests = 0;

	for test_vector in TEST_VECTORS.iter().filter(|test_vector| {
		test_vector.identifier.as_bytes() == Cs::ID.deref() && test_vector.mode == mode
	}) {
		let DataType::Batch(data) = &test_vector.data else {
			continue;
		};

		tests += 1;

		// Secret key.
		let secret_key =
			SecretKey::derive::<Cs>(mode, &test_vector.seed, &test_vector.key_info).unwrap();

		assert_eq!(test_vector.secret_key, secret_key.to_repr().as_slice());
		assert_eq!(
			SecretKey::from_repr(&test_vector.secret_key).unwrap(),
			secret_key,
		);

		#[cfg(feature = "serde")]
		{
			assert_eq!(
				test_vector.secret_key_json,
				serde_json::to_string(&secret_key).unwrap(),
			);
			assert_eq!(
				secret_key,
				serde_json::from_str(&test_vector.secret_key_json).unwrap(),
			);
		}

		// Public key.
		let public_key = PublicKey::from_secret_key(&secret_key);

		assert_eq!(test_vector.public_key, public_key.as_repr().as_slice());
		assert_eq!(
			PublicKey::from_repr(&test_vector.public_key).unwrap(),
			public_key,
		);

		#[cfg(feature = "serde")]
		{
			assert_eq!(
				test_vector.public_key_json,
				serde_json::to_string(&public_key).unwrap(),
			);
			assert_eq!(
				public_key,
				serde_json::from_str(&test_vector.public_key_json).unwrap(),
			);
		}

		// Client.
		let clients = CommonClient::<Cs>::batch_with(
			mode,
			Some(&data.each_ref().map(|data| data.blind.as_slice())),
			&data
				.each_ref()
				.map(|data| data.input.as_slice())
				.each_ref()
				.map(slice::from_ref),
		)
		.unwrap();

		#[cfg(feature = "serde")]
		{
			for (index, data) in data.iter().enumerate() {
				match clients.clients() {
					ClientBatch::Oprf(clients) => assert_eq!(
						data.client_json,
						serde_json::to_string(&clients[index]).unwrap(),
					),
					ClientBatch::Voprf(clients) => assert_eq!(
						data.client_json,
						serde_json::to_string(&clients[index]).unwrap(),
					),
					ClientBatch::Poprf(clients) => assert_eq!(
						data.client_json,
						serde_json::to_string(&clients[index]).unwrap(),
					),
				}
			}

			for (index, data) in data.iter().enumerate() {
				match clients.clients() {
					ClientBatch::Oprf(clients) => assert_eq!(
						clients[index],
						serde_json::from_str(&data.client_json).unwrap()
					),
					ClientBatch::Voprf(clients) => assert_eq!(
						clients[index],
						serde_json::from_str(&data.client_json).unwrap()
					),
					ClientBatch::Poprf(clients) => assert_eq!(
						clients[index],
						serde_json::from_str(&data.client_json).unwrap()
					),
				}
			}
		}

		// Blind.
		for (blinded_element, data) in clients.blinded_elements().iter().zip(data) {
			assert_eq!(data.blinded_element, blinded_element.as_repr().as_slice(),);
			assert_eq!(
				&BlindedElement::from_repr(&data.blinded_element).unwrap(),
				blinded_element,
			);

			#[cfg(feature = "serde")]
			{
				assert_eq!(
					data.blinded_element_json,
					serde_json::to_string(blinded_element).unwrap(),
				);
				assert_eq!(
					blinded_element,
					&serde_json::from_str(&data.blinded_element_json).unwrap(),
				);
			}
		}

		// Server
		let server = CommonServer::batch_with::<2>(
			mode,
			Some(secret_key),
			clients.blinded_elements(),
			test_vector.proof.as_ref().map(|proof| proof.r.as_slice()),
			test_vector.info.as_deref(),
		)
		.unwrap();

		#[cfg(feature = "serde")]
		{
			let json = match server.server() {
				Server::Oprf(server) => serde_json::to_string(server),
				Server::Voprf(server) => serde_json::to_string(server),
				Server::Poprf(server) => serde_json::to_string(server),
			}
			.unwrap();
			assert_eq!(test_vector.server_json, json);
			let vector_server = match mode {
				Mode::Oprf => serde_json::from_str(&test_vector.server_json).map(Server::Oprf),
				Mode::Voprf => serde_json::from_str(&test_vector.server_json).map(Server::Voprf),
				Mode::Poprf => serde_json::from_str(&test_vector.server_json).map(Server::Poprf),
			}
			.unwrap();
			assert_eq!(server.server(), &vector_server);
		}

		// Blind evaluate.
		for (evaluation_element, data) in server.evaluation_elements().iter().zip(data) {
			assert_eq!(
				data.evaluation_element,
				evaluation_element.as_repr().as_slice(),
			);
			assert_eq!(
				&EvaluationElement::from_repr(&data.evaluation_element).unwrap(),
				evaluation_element,
			);

			#[cfg(feature = "serde")]
			{
				assert_eq!(
					data.evaluation_element_json,
					serde_json::to_string(evaluation_element).unwrap(),
				);
				assert_eq!(
					evaluation_element,
					&serde_json::from_str(&data.evaluation_element_json).unwrap(),
				);
			}
		}

		// Proof.
		if !matches!(mode, Mode::Oprf) {
			let proof = server.proof().unwrap();
			let vector_proof = test_vector.proof.as_ref().unwrap();

			assert_eq!(vector_proof.repr, proof.to_repr().as_slice());
			assert_eq!(&Proof::from_repr(&vector_proof.repr).unwrap(), proof);

			#[cfg(feature = "serde")]
			{
				assert_eq!(vector_proof.json, serde_json::to_string(proof).unwrap());
				assert_eq!(proof, &serde_json::from_str(&vector_proof.json).unwrap());
			}
		}

		// Finalize.
		let outputs = clients
			.finalize_with::<2>(
				server.public_key(),
				&data
					.each_ref()
					.map(|data| data.input.as_slice())
					.each_ref()
					.map(slice::from_ref),
				server.evaluation_elements(),
				server.proof(),
				test_vector.info.as_deref(),
			)
			.unwrap();

		for (output, data) in outputs.into_iter().zip(data) {
			assert_eq!(data.output.as_slice(), output.as_slice());
		}

		// Evaluate.
		let outputs = server
			.evaluate_with::<2>(
				&data
					.each_ref()
					.map(|data| data.input.as_slice())
					.each_ref()
					.map(slice::from_ref),
				test_vector.info.as_deref(),
			)
			.unwrap();

		for (output, data) in outputs.into_iter().zip(data) {
			assert_eq!(data.output.as_slice(), output.as_slice());
		}
	}

	assert_eq!(tests, 1);
}
