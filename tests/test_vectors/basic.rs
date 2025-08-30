//! Non-batched test vectors test.

use std::ops::Deref;

use oprf::cipher_suite::CipherSuite;
use oprf::common::{BlindedElement, EvaluationElement, Mode, Proof};
use oprf::key::{KeyPair, PublicKey, SecretKey};
use oprf_test::{CommonClient, CommonServer, INFO, test_ciphersuites};

use super::parse::{TEST_VECTORS, Vector};
use crate::{KEY_INFO, SEED};

test_ciphersuites!(test, Mode);

/// Tests non-batched test vectors.
fn test<CS: CipherSuite>(mode: Mode) {
	let mut tests = 0;

	for test_vector in TEST_VECTORS.iter().filter(|test_vector| {
		test_vector.identifier.as_bytes() == CS::ID.deref() && test_vector.mode == mode
	}) {
		for vector in &test_vector.vectors {
			let Vector::Single(vector) = vector else {
				continue;
			};

			tests += 1;

			let vector_proof = vector.proof.as_ref();

			// Blind.
			let client =
				CommonClient::<CS>::blind_with(mode, Some(&vector.blind), &[&vector.input])
					.unwrap();

			assert_eq!(
				vector.blinded_element,
				client.blinded_element().as_repr().as_slice(),
			);
			assert_eq!(
				&BlindedElement::from_repr(&vector.blinded_element).unwrap(),
				client.blinded_element(),
			);

			// Blind evaluate.
			let server = CommonServer::blind_evaluate_with(
				mode,
				Some(SecretKey::derive::<CS>(mode, &SEED, KEY_INFO).unwrap()),
				client.blinded_element(),
				vector_proof.map(|proof| proof.r.as_slice()),
				INFO,
			)
			.unwrap();

			let secret_key = SecretKey::derive::<CS>(mode, &SEED, KEY_INFO).unwrap();

			assert_eq!(server.secret_key(), &secret_key);
			assert_eq!(test_vector.secret_key, secret_key.to_repr().as_slice());
			assert_eq!(
				SecretKey::from_repr(&test_vector.secret_key).unwrap(),
				secret_key,
			);

			assert_eq!(
				vector.evaluation_element,
				server.evaluation_element().as_repr().as_slice(),
			);
			assert_eq!(
				&EvaluationElement::from_repr(&vector.evaluation_element).unwrap(),
				server.evaluation_element(),
			);

			if !matches!(mode, Mode::Oprf) {
				let public_key = server.public_key().unwrap();

				assert_eq!(
					KeyPair::from_secret_key(secret_key).public_key(),
					public_key
				);

				let vector_public_key = test_vector.public_key.as_ref().unwrap();
				assert_eq!(vector_public_key, public_key.as_repr().as_slice());
				assert_eq!(
					&PublicKey::from_repr(vector_public_key).unwrap(),
					public_key,
				);

				let vector_proof = vector_proof.unwrap();

				assert_eq!(
					vector_proof.proof,
					server.proof().unwrap().to_repr().as_slice()
				);
				assert_eq!(
					&Proof::from_repr(&vector_proof.proof).unwrap(),
					server.proof().unwrap()
				);
			}

			// Finalize.
			assert_eq!(
				vector.output,
				client
					.finalize_with(
						server.public_key(),
						&[&vector.input],
						server.evaluation_element(),
						server.proof(),
						INFO,
					)
					.unwrap()
					.as_slice(),
			);

			// Evaluate.
			assert_eq!(
				vector.output,
				server
					.evaluate_with(&[&vector.input], INFO)
					.unwrap()
					.as_slice(),
			);
		}
	}

	assert_eq!(tests, 2);
}
