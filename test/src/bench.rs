//! Bench utilities.

use derive_where::derive_where;
use digest::Output;
use hybrid_array::Array;
use oprf::cipher_suite::CipherSuite;
use oprf::common::{BlindedElement, EvaluationElement, Mode, Proof};
use oprf::group::Group;
use oprf::key::{PublicKey, SecretKey};

use crate::{CommonClient, CommonServer, INFO, INPUT};

/// Holds the data that should *not* be included in measurements.
#[derive_where(Debug)]
pub struct Setup<Cs: CipherSuite> {
	/// `blind`.
	blind: Array<u8, <Cs::Group as Group>::ScalarLength>,
	/// Server [`SecretKey`].
	secret_key: SecretKey<Cs::Group>,
	/// [`Proof`] `r`.
	r: Array<u8, <Cs::Group as Group>::ScalarLength>,
}

impl<Cs: CipherSuite> Default for Setup<Cs> {
	fn default() -> Self {
		let blind = <Cs::Group as Group>::scalar_random(&mut rand::rng()).unwrap();
		let blind = <Cs::Group as Group>::scalar_to_repr(&blind);

		let secret_key = SecretKey::generate(&mut rand::rng()).unwrap();

		let r = <Cs::Group as Group>::scalar_random(&mut rand::rng()).unwrap();
		let r = <Cs::Group as Group>::scalar_to_repr(&r);

		Self {
			blind,
			secret_key,
			r,
		}
	}
}

/// Runs a benchmark of the full protocol.
#[expect(clippy::missing_panics_doc, reason = "benchmarks")]
pub fn bench<Cs: CipherSuite>(
	mode: Mode,
	setup: Setup<Cs>,
) -> (Output<Cs::Hash>, Output<Cs::Hash>) {
	let Setup {
		blind,
		secret_key,
		r,
	} = setup;

	let client = CommonClient::<Cs>::blind_with(mode, Some(&blind), INPUT).unwrap();
	let blinded_element = client.blinded_element().as_repr();

	let blinded_element = BlindedElement::from_repr(blinded_element).unwrap();
	let server = CommonServer::<Cs>::blind_evaluate_with(
		mode,
		Some(secret_key),
		&blinded_element,
		Some(&r),
		Some(INFO),
	)
	.unwrap();
	let public_key = server.public_key().map(PublicKey::as_repr);
	let evaluation_element = server.evaluation_element().as_repr();
	let proof = server.proof().map(Proof::to_repr);
	let server_output = server.evaluate();

	let public_key = public_key.map(|repr| PublicKey::from_repr(repr).unwrap());
	let evaluation_element = EvaluationElement::from_repr(evaluation_element).unwrap();
	let proof = proof.map(|repr| Proof::from_repr(&repr).unwrap());
	let client_output = client
		.finalize_with(
			public_key.as_ref(),
			INPUT,
			&evaluation_element,
			proof.as_ref(),
			Some(INFO),
		)
		.unwrap();

	(client_output, server_output)
}
