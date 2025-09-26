//! Batched test vectors test.

use std::ops::Deref;
use std::slice;

use oprf::cipher_suite::CipherSuite;
use oprf::common::{BlindedElement, EvaluationElement, Mode, Proof};
use oprf::key::{KeyPair, PublicKey, SecretKey};
use oprf::{Decaf448, Ristretto255};
use oprf_test::{CommonClient, CommonServer, INFO, test_ciphersuites};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;

use super::parse::{TEST_VECTORS, Vector};
use crate::{KEY_INFO, SEED};

test_ciphersuites!(
	test,
	Voprf,
	[
		NistP256 as p256,
		NistP384 as p384,
		NistP521 as p521,
		Ristretto255 as ristretto255,
		Decaf448 as decaf448
	]
);
test_ciphersuites!(
	test,
	Poprf,
	[
		NistP256 as p256,
		NistP384 as p384,
		NistP521 as p521,
		Ristretto255 as ristretto255,
		Decaf448 as decaf448
	]
);

/// Tests batched test vectors.
#[expect(clippy::too_many_lines, reason = "test")]
#[cfg_attr(
	feature = "alloc",
	expect(clippy::cognitive_complexity, reason = "test")
)]
fn test<Cs: CipherSuite>(mode: Mode) {
	let mut tests = 0;

	for test_vector in TEST_VECTORS.iter().filter(|test_vector| {
		test_vector.identifier.as_bytes() == Cs::ID.deref() && test_vector.mode == mode
	}) {
		for vector in &test_vector.vectors {
			let Vector::Batch(vector) = vector else {
				continue;
			};

			tests += 1;

			let inputs = vector.inputs.each_ref().map(Vec::as_slice);
			let inputs = inputs.each_ref().map(slice::from_ref);

			let vector_proof = vector.proof.as_ref().expect("unexpected missing proof");

			// Blind.
			let clients = CommonClient::<Cs>::batch_with(
				mode,
				Some(&vector.blinds.each_ref().map(Vec::as_slice)),
				&inputs,
			)
			.unwrap();

			#[cfg(feature = "alloc")]
			{
				let alloc_clients = CommonClient::<Cs>::batch_alloc_with(
					mode,
					Some(vector.blinds.each_ref().map(Vec::as_slice).as_slice()),
					inputs.into_iter(),
				)
				.unwrap();

				assert_eq!(alloc_clients, clients);
			}

			for (blinded_element, vector_blinded_element) in clients
				.blinded_elements()
				.iter()
				.zip(&vector.blinded_elements)
			{
				assert_eq!(vector_blinded_element, blinded_element.as_repr().as_slice());
				assert_eq!(
					&BlindedElement::from_repr(vector_blinded_element).unwrap(),
					blinded_element,
				);
			}

			// Blind evaluate.
			let server = CommonServer::batch_with::<2>(
				mode,
				Some(SecretKey::derive::<Cs>(mode, &SEED, KEY_INFO).unwrap()),
				clients.blinded_elements(),
				Some(&vector_proof.r),
				Some(INFO),
			)
			.unwrap();

			let key_pair = KeyPair::derive::<Cs>(mode, &SEED, KEY_INFO).unwrap();

			assert_eq!(server.secret_key(), key_pair.secret_key());
			assert_eq!(
				test_vector.secret_key,
				key_pair.secret_key().to_repr().as_slice()
			);
			assert_eq!(
				&SecretKey::from_repr(&test_vector.secret_key).unwrap(),
				key_pair.secret_key(),
			);

			assert_eq!(key_pair.public_key(), server.public_key().unwrap());

			let vector_public_key = test_vector.public_key.as_ref().unwrap();
			assert_eq!(
				vector_public_key,
				key_pair.public_key().as_repr().as_slice(),
			);
			assert_eq!(
				&PublicKey::from_repr(vector_public_key).unwrap(),
				key_pair.public_key(),
			);

			for (evaluation_element, vector_evaluation_element) in server
				.evaluation_elements()
				.iter()
				.zip(&vector.evaluation_elements)
			{
				assert_eq!(
					vector_evaluation_element,
					evaluation_element.as_repr().as_slice(),
				);
				assert_eq!(
					&EvaluationElement::from_repr(vector_evaluation_element).unwrap(),
					evaluation_element,
				);
			}

			let proof = server.proof().unwrap();

			assert_eq!(vector_proof.repr, proof.to_repr().as_slice());
			assert_eq!(&Proof::from_repr(&vector_proof.repr).unwrap(), proof);

			#[cfg(feature = "alloc")]
			{
				let alloc_server = CommonServer::batch_alloc_with(
					mode,
					Some(SecretKey::derive::<Cs>(mode, &SEED, KEY_INFO).unwrap()),
					clients.blinded_elements(),
					Some(&vector_proof.r),
					INFO,
				)
				.unwrap();

				assert_eq!(alloc_server, server);
			}

			// Finalize.
			let outputs = clients
				.finalize_with::<2>(
					server.public_key(),
					&inputs,
					server.evaluation_elements(),
					server.proof(),
					Some(INFO),
				)
				.unwrap();

			for (output, vector_output) in outputs.into_iter().zip(&vector.outputs) {
				assert_eq!(vector_output, output.as_slice());
			}

			// Evaluate.
			let outputs = server.evaluate_with::<2>(&inputs, Some(INFO)).unwrap();

			for (output, vector_output) in outputs.into_iter().zip(&vector.outputs) {
				assert_eq!(vector_output, output.as_slice());
			}

			#[cfg(feature = "alloc")]
			{
				let outputs = server.evaluate_alloc_with(&inputs, INFO).unwrap();

				for (output, vector_output) in outputs.into_iter().zip(&vector.outputs) {
					assert_eq!(vector_output, output.as_slice());
				}
			}
		}
	}

	assert_eq!(tests, 1);
}
