//! Non-batched test vectors test.

use std::ops::Deref;

use oprf::cipher_suite::CipherSuite;
use oprf::common::{BlindedElement, EvaluationElement, Mode, Proof};
#[cfg(feature = "serde")]
use oprf::group::Group;
use oprf::key::{PublicKey, SecretKey};
#[cfg(feature = "serde")]
use oprf_test::common::{Client, Server};
use oprf_test::{CommonClient, CommonServer, test_ciphersuites};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::parse::{DataType, TEST_VECTORS};

test_ciphersuites!(test, Mode);

/// Tests non-batched test vectors.
#[expect(clippy::too_many_lines, reason = "test")]
#[cfg_attr(
	feature = "serde",
	expect(clippy::cognitive_complexity, reason = "test")
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
		let DataType::Basic(data) = &test_vector.data else {
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
		let client =
			CommonClient::<Cs>::blind_with(mode, Some(&data.blind), &[&data.input]).unwrap();

		#[cfg(feature = "serde")]
		{
			let json = match client.client() {
				Client::Oprf(client) => serde_json::to_string(client),
				Client::Voprf(client) => serde_json::to_string(client),
				Client::Poprf(client) => serde_json::to_string(client),
			}
			.unwrap();
			assert_eq!(data.client_json, json);
			let vector_client = match mode {
				Mode::Oprf => serde_json::from_str(&data.client_json).map(Client::Oprf),
				Mode::Voprf => serde_json::from_str(&data.client_json).map(Client::Voprf),
				Mode::Poprf => serde_json::from_str(&data.client_json).map(Client::Poprf),
			}
			.unwrap();
			assert_eq!(client.client(), &vector_client);
		}

		// Blind.
		assert_eq!(
			data.blinded_element,
			client.blinded_element().as_repr().as_slice(),
		);
		assert_eq!(
			&BlindedElement::from_repr(&data.blinded_element).unwrap(),
			client.blinded_element(),
		);

		#[cfg(feature = "serde")]
		{
			assert_eq!(
				data.blinded_element_json,
				serde_json::to_string(client.blinded_element()).unwrap(),
			);
			assert_eq!(
				client.blinded_element(),
				&serde_json::from_str(&data.blinded_element_json).unwrap(),
			);
		}

		// Server
		let server = CommonServer::blind_evaluate_with(
			mode,
			Some(secret_key),
			client.blinded_element(),
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
		assert_eq!(
			data.evaluation_element,
			server.evaluation_element().as_repr().as_slice(),
		);
		assert_eq!(
			&EvaluationElement::from_repr(&data.evaluation_element).unwrap(),
			server.evaluation_element(),
		);

		#[cfg(feature = "serde")]
		{
			assert_eq!(
				data.evaluation_element_json,
				serde_json::to_string(server.evaluation_element()).unwrap(),
			);
			assert_eq!(
				server.evaluation_element(),
				&serde_json::from_str(&data.evaluation_element_json).unwrap(),
			);
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
		assert_eq!(
			data.output,
			client
				.finalize_with(
					server.public_key(),
					&[&data.input],
					server.evaluation_element(),
					server.proof(),
					test_vector.info.as_deref(),
				)
				.unwrap()
				.as_slice(),
		);

		// Evaluate.
		assert_eq!(
			data.output,
			server
				.evaluate_with(&[&data.input], test_vector.info.as_deref())
				.unwrap()
				.as_slice(),
		);
	}

	assert_eq!(tests, 1);
}
