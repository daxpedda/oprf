//! Bench utilities.

use derive_where::derive_where;
use digest::Output;
use hybrid_array::Array;
use oprf::cipher_suite::CipherSuite;
use oprf::common::{BlindedElement, EvaluationElement, Mode, Proof};
use oprf::group::Group;
use oprf::key::{PublicKey, SecretKey};
use rand_core::OsRng;

use crate::{CommonClient, CommonServer, INFO, INPUT};

/// Holds the data that should *not* be included in measurements.
#[derive_where(Debug)]
pub struct Setup<CS: CipherSuite> {
	/// `blind`.
	blind: Array<u8, <CS::Group as Group>::ScalarLength>,
	/// Server [`SecretKey`].
	secret_key: SecretKey<CS::Group>,
	/// [`Proof`] `r`.
	r: Array<u8, <CS::Group as Group>::ScalarLength>,
}

impl<CS: CipherSuite> Default for Setup<CS> {
	fn default() -> Self {
		let blind = <CS::Group as Group>::scalar_random(&mut OsRng).unwrap();
		let blind = <CS::Group as Group>::scalar_to_repr(&blind);

		let secret_key = SecretKey::generate(&mut OsRng).unwrap();

		let r = <CS::Group as Group>::scalar_random(&mut OsRng).unwrap();
		let r = <CS::Group as Group>::scalar_to_repr(&r);

		Self {
			blind,
			secret_key,
			r,
		}
	}
}

/// Runs a benchmark of the full protocol.
#[expect(clippy::missing_panics_doc, reason = "benchmarks")]
pub fn bench<CS: CipherSuite>(
	mode: Mode,
	setup: Setup<CS>,
) -> (Output<CS::Hash>, Output<CS::Hash>) {
	let Setup {
		blind,
		secret_key,
		r,
	} = setup;

	let client = CommonClient::<CS>::blind_with(mode, Some(&blind), INPUT).unwrap();
	let blinded_element = client.blinded_element().as_repr();

	let blinded_element = BlindedElement::from_repr(blinded_element).unwrap();
	let server = CommonServer::<CS>::blind_evaluate_with(
		mode,
		Some(secret_key),
		&blinded_element,
		Some(&r),
		INFO,
	)
	.unwrap();
	let public_key = server.public_key().map(PublicKey::as_repr);
	let evaluation_element = server.evaluation_element().as_repr();
	let proof = server.proof().map(Proof::to_repr);
	let server_output = server.evaluate();

	let public_key = public_key.map(|bytes| PublicKey::from_repr(bytes).unwrap());
	let evaluation_element = EvaluationElement::from_repr(evaluation_element).unwrap();
	let proof = proof.map(|bytes| Proof::from_repr(&bytes).unwrap());
	let client_output = client
		.finalize_with(
			public_key.as_ref(),
			INPUT,
			&evaluation_element,
			proof.as_ref(),
			INFO,
		)
		.unwrap();

	(client_output, server_output)
}
