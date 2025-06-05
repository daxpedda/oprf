//! VOPRF test vectors testing.

use std::ops::Deref;
use std::slice;
use std::vec::Vec;

use oprf_test::test_ciphersuites;

use super::parse::{TEST_VECTORS, TestVector, Vector};
use super::{KEY_INFO, SEED};
use crate::ciphersuite::CipherSuite;
use crate::common::{BlindedElement, EvaluationElement, Mode, Proof};
use crate::internal;
use crate::key::{PublicKey, SecretKey};
use crate::test_vectors::cycle_rng::CycleRng;
use crate::util::Concat;
#[cfg(feature = "alloc")]
use crate::voprf::VoprfBatchBlindEvaluateResult;
use crate::voprf::{
	VoprfBatchBlindEvaluateFixedResult, VoprfBlindEvaluateResult, VoprfBlindResult, VoprfClient,
	VoprfServer,
};

test_ciphersuites!(voprf);

test_ciphersuites!(voprf_batch);

/// Tests VOPRF test vectors.
fn voprf<CS: CipherSuite>() {
	for test_vector in TEST_VECTORS.iter().filter(|test_vector| {
		test_vector.identifier.as_bytes() == CS::ID.deref()
			&& matches!(test_vector.mode, Mode::Voprf)
	}) {
		// Server.
		let server = server(test_vector);

		for vector in &test_vector.vectors {
			let Vector::Single(vector) = vector else {
				continue;
			};

			let vector_proof = vector
				.proof
				.as_ref()
				.expect("unexpected missing proof for VOPRF");

			// Blind.
			let VoprfBlindResult {
				client,
				blinded_element,
			} = VoprfClient::<CS>::blind(&mut CycleRng::new(&vector.blind), &[&vector.input]).unwrap();

			assert_eq!(vector.blinded_element, blinded_element.as_repr().as_slice(),);
			assert_eq!(
				BlindedElement::from_repr(&vector.blinded_element).unwrap(),
				blinded_element,
			);

			// Blind evaluate.
			let VoprfBlindEvaluateResult {
				evaluation_element,
				proof,
			} = server
				.blind_evaluate(&mut CycleRng::new(&vector_proof.r), &blinded_element)
				.unwrap();

			assert_eq!(
				vector.evaluation_element,
				evaluation_element.as_repr().as_slice(),
			);
			assert_eq!(
				EvaluationElement::from_repr(&vector.evaluation_element).unwrap(),
				evaluation_element,
			);
			assert_eq!(vector_proof.proof, proof.to_repr().as_slice());
			assert_eq!(Proof::from_repr(&vector_proof.proof).unwrap(), proof);

			// Finalize.
			assert_eq!(
				vector.output,
				client
					.finalize(
						server.public_key(),
						&[&vector.input],
						&evaluation_element,
						&proof
					)
					.unwrap()
					.as_slice(),
			);

			// Evaluate.
			assert_eq!(
				vector.output,
				server.evaluate(&[&vector.input]).unwrap().as_slice(),
			);
		}
	}
}

/// Tests batched VOPRF test vectors.
#[expect(clippy::too_many_lines, reason = "test")]
fn voprf_batch<CS: CipherSuite>() {
	for test_vector in TEST_VECTORS.iter().filter(|test_vector| {
		test_vector.identifier.as_bytes() == CS::ID.deref()
			&& matches!(test_vector.mode, Mode::Voprf)
	}) {
		// Server.
		let server = server(test_vector);

		for vector in &test_vector.vectors {
			let Vector::Batch(vector) = vector else {
				continue;
			};

			let vector_proof = vector
				.proof
				.as_ref()
				.expect("unexpected missing proof for VOPRF");

			// Blind.
			let (clients, blinded_elements): (Vec<_>, Vec<_>) = vector
				.blinds
				.iter()
				.zip(&vector.inputs)
				.zip(&vector.blinded_elements)
				.map(|((blind, input), vector_blinded_element)| {
					let VoprfBlindResult {
						client,
						blinded_element,
					} = VoprfClient::<CS>::blind(&mut CycleRng::new(blind), &[input.as_slice()])
						.unwrap();

					assert_eq!(vector_blinded_element, blinded_element.as_repr().as_slice(),);
					assert_eq!(
						BlindedElement::from_repr(vector_blinded_element).unwrap(),
						blinded_element,
					);

					(client, blinded_element)
				})
				.unzip();
			let clients: [_; 2] = clients.try_into().unwrap();
			let blinded_elements: [_; 2] = blinded_elements.try_into().unwrap();

			// Blind evaluate.
			let rng = &mut CycleRng::new(&vector_proof.r);

			let VoprfBatchBlindEvaluateFixedResult {
				evaluation_elements,
				proof,
			} = server
				.batch_blind_evaluate_fixed(rng, &blinded_elements)
				.unwrap();

			for (evaluation_element, vector_evaluation_element) in
				evaluation_elements.iter().zip(&vector.evaluation_elements)
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

			assert_eq!(vector_proof.proof, proof.to_repr().as_slice());
			assert_eq!(Proof::from_repr(&vector_proof.proof).unwrap(), proof);

			#[cfg(feature = "alloc")]
			{
				let VoprfBatchBlindEvaluateResult {
					evaluation_elements,
					proof,
				} = server
					.batch_blind_evaluate(rng, blinded_elements.iter())
					.unwrap();

				for (evaluation_element, vector_evaluation_element) in evaluation_elements
					.into_iter()
					.zip(&vector.evaluation_elements)
				{
					assert_eq!(
						vector_evaluation_element,
						evaluation_element.as_repr().as_slice(),
					);
					assert_eq!(
						EvaluationElement::from_repr(vector_evaluation_element).unwrap(),
						evaluation_element,
					);
				}

				assert_eq!(vector_proof.proof, proof.to_repr().as_slice());
				assert_eq!(Proof::from_repr(&vector_proof.proof).unwrap(), proof);
			}

			// Finalize.
			let inputs = vector.inputs.each_ref().map(Vec::as_slice);
			let inputs = inputs.each_ref().map(slice::from_ref);
			VoprfClient::batch_finalize_fixed(
				&clients,
				server.public_key(),
				inputs.into_iter(),
				&evaluation_elements,
				&proof,
			)
			.unwrap()
			.into_iter()
			.zip(&vector.outputs)
			.for_each(|(output, vector_output)| {
				assert_eq!(vector_output, output.as_slice());
			});

			#[cfg(feature = "alloc")]
			VoprfClient::batch_finalize(
				clients.iter(),
				server.public_key(),
				inputs.into_iter(),
				evaluation_elements.iter(),
				&proof,
			)
			.unwrap()
			.into_iter()
			.zip(&vector.outputs)
			.for_each(|(output, vector_output)| {
				assert_eq!(vector_output, output.as_slice());
			});

			// Evaluate.
			for (input, output) in inputs.into_iter().zip(&vector.outputs) {
				assert_eq!(output, server.evaluate(input).unwrap().as_slice(),);
			}
		}
	}
}

/// Shared server creation between basic and batched testing.
fn server<CS: CipherSuite>(test_vector: &TestVector) -> VoprfServer<CS> {
	let group_dst = [b"HashToGroup-".as_slice()]
		.concat(internal::create_context_string::<CS>(Mode::Voprf))
		.as_slice()
		.concat();
	assert_eq!(test_vector.group_dst, group_dst);

	let server = VoprfServer::<CS>::from_seed(&SEED, KEY_INFO).unwrap();

	assert_eq!(
		test_vector.secret_key,
		server.secret_key().to_repr().as_slice(),
	);
	assert_eq!(
		&SecretKey::from_repr(&test_vector.secret_key).unwrap(),
		server.secret_key(),
	);

	let vector_public_key = test_vector
		.public_key
		.as_ref()
		.expect("unexpected missing public key for VOPRF");
	assert_eq!(vector_public_key, server.public_key().as_repr().as_slice(),);
	assert_eq!(
		&PublicKey::from_repr(vector_public_key).unwrap(),
		server.public_key(),
	);

	server
}
