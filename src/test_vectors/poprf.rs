//! POPRF test vectors testing.

use std::ops::Deref;
use std::slice;
use std::vec::Vec;

use super::parse::{TEST_VECTORS, TestVector, Vector};
use super::{INFO, KEY_INFO, SEED};
use crate::ciphersuite::CipherSuite;
use crate::common::{BlindedElement, EvaluationElement, Mode, Proof};
use crate::key::PublicKey;
#[cfg(feature = "alloc")]
use crate::poprf::PoprfBatchBlindEvaluateResult;
use crate::poprf::{
	PoprfBlindEvaluateResult, PoprfBlindResult, PoprfClient, PoprfFinishBatchBlindEvaluateResult,
	PoprfPrepareBatchBlindEvaluateResult, PoprfServer,
};
use crate::test_vectors::cycle_rng::CycleRng;
use crate::util::Concat;
use crate::{internal, test_ciphersuites};

test_ciphersuites!(poprf);

test_ciphersuites!(poprf_batch);

/// Tests POPRF test vectors.
fn poprf<CS: CipherSuite>() {
	for test_vector in TEST_VECTORS.iter().filter(|test_vector| {
		test_vector.identifier.as_bytes() == CS::ID.deref()
			&& matches!(test_vector.mode, Mode::Poprf)
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
				.expect("unexpected missing proof for POPRF");

			// Blind.
			let PoprfBlindResult {
				client,
				blinded_element,
			} = PoprfClient::<CS>::blind(&mut CycleRng::new(&vector.blind), &[&vector.input]).unwrap();

			assert_eq!(
				vector.blinded_element,
				blinded_element.serialize().as_slice(),
			);
			assert_eq!(
				BlindedElement::deserialize(&vector.blinded_element).unwrap(),
				blinded_element,
			);

			// Blind evaluate.
			let PoprfBlindEvaluateResult {
				state,
				evaluation_element,
				proof,
			} = server
				.blind_evaluate(&mut CycleRng::new(&vector_proof.r), &blinded_element, &INFO)
				.unwrap();

			assert_eq!(
				vector.evaluation_element,
				evaluation_element.serialize().as_slice(),
			);
			assert_eq!(
				EvaluationElement::deserialize(&vector.evaluation_element).unwrap(),
				evaluation_element,
			);
			assert_eq!(vector_proof.proof, proof.serialize().as_slice());
			assert_eq!(Proof::deserialize(&vector_proof.proof).unwrap(), proof);

			// Finalize.
			assert_eq!(
				vector.output,
				client
					.finalize(
						server.public_key(),
						&[&vector.input],
						&evaluation_element,
						&proof,
						&INFO,
					)
					.unwrap()
					.as_slice(),
			);

			// Evaluate.
			assert_eq!(
				vector.output,
				server
					.evaluate(&state, &[&vector.input], &INFO)
					.unwrap()
					.as_slice(),
			);
		}
	}
}

/// Tests batched POPRF test vectors.
#[expect(clippy::too_many_lines, reason = "test")]
fn poprf_batch<CS: CipherSuite>() {
	for test_vector in TEST_VECTORS.iter().filter(|test_vector| {
		test_vector.identifier.as_bytes() == CS::ID.deref()
			&& matches!(test_vector.mode, Mode::Poprf)
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
				.expect("unexpected missing proof for POPRF");

			// Blind.
			let (clients, blinded_elements): (Vec<_>, Vec<_>) = vector
				.blinds
				.iter()
				.zip(&vector.inputs)
				.zip(&vector.blinded_elements)
				.map(|((blind, input), vector_blinded_element)| {
					let PoprfBlindResult {
						client,
						blinded_element,
					} = PoprfClient::<CS>::blind(&mut CycleRng::new(blind), &[input.as_slice()])
						.unwrap();

					assert_eq!(
						vector_blinded_element,
						blinded_element.serialize().as_slice(),
					);
					assert_eq!(
						BlindedElement::deserialize(vector_blinded_element).unwrap(),
						blinded_element,
					);

					(client, blinded_element)
				})
				.unzip();
			let clients: [_; 2] = clients.try_into().unwrap();

			// Blind evaluate.
			let rng = &mut CycleRng::new(&vector_proof.r);

			let PoprfPrepareBatchBlindEvaluateResult {
				state,
				prepared_elements,
			} = server
				.prepare_batch_blind_evaluate(blinded_elements.iter(), &INFO)
				.unwrap();

			let prepared_elements: Vec<_> = prepared_elements.collect();

			let PoprfFinishBatchBlindEvaluateResult {
				state,
				evaluation_elements,
				proof,
			} = server
				.finish_batch_blind_evaluate(
					&state,
					rng,
					blinded_elements.iter(),
					&prepared_elements,
				)
				.unwrap();

			let evaluation_elements: Vec<_> = evaluation_elements.collect();

			for (evaluation_element, vector_evaluation_element) in
				evaluation_elements.iter().zip(&vector.evaluation_elements)
			{
				assert_eq!(
					vector_evaluation_element,
					evaluation_element.serialize().as_slice(),
				);
				assert_eq!(
					&EvaluationElement::deserialize(vector_evaluation_element).unwrap(),
					evaluation_element,
				);
			}

			assert_eq!(vector_proof.proof, proof.serialize().as_slice());
			assert_eq!(Proof::deserialize(&vector_proof.proof).unwrap(), proof);

			#[cfg(feature = "alloc")]
			{
				let PoprfBatchBlindEvaluateResult {
					evaluation_elements,
					proof,
					..
				} = server
					.batch_blind_evaluate(rng, &blinded_elements, &INFO)
					.unwrap();

				for (evaluation_element, vector_evaluation_element) in evaluation_elements
					.into_iter()
					.zip(&vector.evaluation_elements)
				{
					assert_eq!(
						vector_evaluation_element,
						evaluation_element.serialize().as_slice(),
					);
					assert_eq!(
						EvaluationElement::deserialize(vector_evaluation_element).unwrap(),
						evaluation_element,
					);
				}

				assert_eq!(vector_proof.proof, proof.serialize().as_slice());
				assert_eq!(Proof::deserialize(&vector_proof.proof).unwrap(), proof);
			}

			// Finalize.
			let inputs = vector.inputs.each_ref().map(Vec::as_slice);
			let inputs = inputs.each_ref().map(slice::from_ref);
			PoprfClient::batch_finalize_fixed(
				&clients,
				server.public_key(),
				inputs.into_iter(),
				&evaluation_elements,
				&proof,
				&INFO,
			)
			.unwrap()
			.into_iter()
			.zip(&vector.outputs)
			.for_each(|(output, vector_output)| {
				assert_eq!(vector_output, output.as_slice());
			});

			#[cfg(feature = "alloc")]
			PoprfClient::batch_finalize(
				&clients,
				server.public_key(),
				inputs.into_iter(),
				&evaluation_elements,
				&proof,
				&INFO,
			)
			.unwrap()
			.into_iter()
			.zip(&vector.outputs)
			.for_each(|(output, vector_output)| {
				assert_eq!(vector_output, output.as_slice());
			});

			// Evaluate.
			for (input, output) in inputs.into_iter().zip(&vector.outputs) {
				assert_eq!(
					output,
					server.evaluate(&state, input, &INFO).unwrap().as_slice(),
				);
			}
		}
	}
}

/// Shared server creation between basic and batched testing.
fn server<CS: CipherSuite>(test_vector: &TestVector) -> PoprfServer<CS> {
	let group_dst = [b"HashToGroup-".as_slice()]
		.concat(internal::create_context_string::<CS>(Mode::Poprf))
		.as_slice()
		.concat();
	assert_eq!(test_vector.group_dst, group_dst);

	let server = PoprfServer::<CS>::from_seed(&SEED, KEY_INFO).unwrap();

	assert_eq!(
		test_vector.secret_key,
		server.secret_key().serialize().as_slice(),
	);

	let vector_public_key = test_vector
		.public_key
		.as_ref()
		.expect("unexpected missing public key for VOPRF");
	assert_eq!(
		vector_public_key,
		server.public_key().serialize().as_slice(),
	);
	assert_eq!(
		&PublicKey::deserialize(vector_public_key).unwrap(),
		server.public_key(),
	);

	server
}
