//! Non-batched test vectors test.

use std::ops::Deref;

use oprf::cipher_suite::CipherSuite;
use oprf::common::{BlindedElement, EvaluationElement, Mode, Proof};
use oprf_test::{HelperClient, HelperServer, INFO, test_ciphersuites};

use super::parse::{TEST_VECTORS, Vector};

test_ciphersuites!(test, Oprf);
test_ciphersuites!(test, Voprf);
test_ciphersuites!(test, Poprf);

/// Tests non-batched test vectors.
fn test<CS: CipherSuite>(mode: Mode) {
	let mut tests = 0;

	for test_vector in TEST_VECTORS.iter().filter(|test_vector| {
		test_vector.identifier.as_bytes() == CS::ID.deref() && test_vector.mode == mode
	}) {
		let secret_key = crate::secret_key::<CS>(mode, test_vector);

		for vector in &test_vector.vectors {
			let Vector::Single(vector) = vector else {
				continue;
			};

			tests += 1;

			let vector_proof = vector.proof.as_ref();

			// Blind.
			let client =
				HelperClient::<CS>::blind_with(mode, Some(&vector.blind), &[&vector.input])
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
			let server = HelperServer::blind_evaluate_with(
				&client,
				Some(secret_key.clone()),
				vector_proof.map(|proof| proof.r.as_slice()),
				INFO,
			)
			.unwrap();

			assert_eq!(
				vector.evaluation_element,
				server.evaluation_element().as_repr().as_slice(),
			);
			assert_eq!(
				&EvaluationElement::from_repr(&vector.evaluation_element).unwrap(),
				server.evaluation_element(),
			);

			if !matches!(mode, Mode::Oprf) {
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
