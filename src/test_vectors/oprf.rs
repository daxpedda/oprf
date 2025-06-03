//! OPRF test vectors testing.

use core::ops::Deref;
use core::{array, iter};

use super::parse::{TEST_VECTORS, Vector};
use super::{KEY_INFO, SEED};
use crate::ciphersuite::CipherSuite;
use crate::common::{BlindedElement, EvaluationElement, Mode};
use crate::key::SecretKey;
use crate::oprf::{OprfBlindResult, OprfClient, OprfServer};
use crate::test_vectors::cycle_rng::CycleRng;
use crate::util::Concat;
use crate::{internal, test_ciphersuites};

test_ciphersuites!(oprf);

/// Tests OPRF test vectors.
fn oprf<CS: CipherSuite>() {
	for test_vector in TEST_VECTORS.iter().filter(|test_vector| {
		test_vector.identifier.as_bytes() == CS::ID.deref()
			&& matches!(test_vector.mode, Mode::Oprf)
	}) {
		let group_dst = [b"HashToGroup-".as_slice()]
			.concat(internal::create_context_string::<CS>(Mode::Oprf))
			.as_slice()
			.concat();
		assert_eq!(test_vector.group_dst, group_dst);

		// Server.
		let server = OprfServer::<CS>::from_seed(&SEED, KEY_INFO).unwrap();

		assert_eq!(
			test_vector.secret_key,
			server.secret_key().to_repr().as_slice(),
		);
		assert_eq!(
			&SecretKey::from_repr(&test_vector.secret_key).unwrap(),
			server.secret_key(),
		);

		assert!(test_vector.public_key.is_none());

		for vector in &test_vector.vectors {
			let Vector::Single(vector) = vector else {
				panic!("found unexpected batch vector for OPRF")
			};

			assert!(vector.proof.is_none());

			// Blind.
			let OprfBlindResult {
				client,
				blinded_element,
			} = OprfClient::<CS>::blind(&mut CycleRng::new(&vector.blind), &[&vector.input]).unwrap();

			assert_eq!(vector.blinded_element, blinded_element.as_repr().as_slice(),);
			assert_eq!(
				BlindedElement::from_repr(&vector.blinded_element).unwrap(),
				blinded_element,
			);

			// Blind evaluate.
			let evaluation_element = server.blind_evaluate(&blinded_element);
			assert_eq!(
				vector.evaluation_element,
				evaluation_element.as_repr().as_slice(),
			);
			assert_eq!(
				EvaluationElement::from_repr(&vector.evaluation_element).unwrap(),
				evaluation_element,
			);

			// Finalize.
			assert_eq!(
				vector.output,
				client
					.finalize(&[&vector.input], &evaluation_element)
					.unwrap()
					.as_slice(),
			);

			let [output] = OprfClient::batch_finalize_fixed(
				array::from_ref(&client),
				iter::once::<&[&[u8]]>(&[&vector.input]),
				array::from_ref(&evaluation_element),
			)
			.unwrap();
			assert_eq!(vector.output, output.as_slice());

			#[cfg(feature = "alloc")]
			{
				let [output] = OprfClient::batch_finalize(
					iter::once(&client),
					iter::once::<&[&[u8]]>(&[&vector.input]),
					iter::once(&evaluation_element),
				)
				.unwrap()
				.try_into()
				.unwrap();
				assert_eq!(vector.output, output.as_slice());
			}

			// Evaluate.
			assert_eq!(
				vector.output,
				server.evaluate(&[&vector.input]).unwrap().as_slice(),
			);
		}
	}
}
