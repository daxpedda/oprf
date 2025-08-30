//! Basic IAI benchmark.

#![expect(
	clippy::cargo_common_metadata,
	clippy::unwrap_used,
	reason = "benchmarks"
)]
#![expect(clippy::exit, missing_docs, non_snake_case, reason = "iai")]

use ::oprf::cipher_suite::CipherSuite;
use ::oprf::common::{BlindedElement, EvaluationElement, Mode, Proof};
use ::oprf::group::{Group, decaf448, ristretto255};
use ::oprf::key::{PublicKey, SecretKey};
use digest::Output;
use hybrid_array::Array;
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use oprf_test::{CommonClient, CommonServer, INFO, INPUT};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use paste::paste;
use rand_core::OsRng;

macro_rules! group {
	($mode:ident) => {
		paste! {
			library_benchmark_group!(name = [<$mode:upper>]; benchmarks = [<$mode:lower>]);

			#[library_benchmark]
			#[bench::P256(args = (NistP256), setup = Setup::new)]
			#[bench::P384(args = (NistP384), setup = Setup::new)]
			#[bench::P521(args = (NistP521), setup = Setup::new)]
			#[bench::Ristretto255(args = (ristretto255::Ristretto255), setup = Setup::new)]
			#[bench::Decaf448(args = (decaf448::Decaf448), setup = Setup::new)]
			fn [<$mode:lower>]<CS: CipherSuite>(setup: Setup<CS>) {
				bench(Mode::$mode, setup);
			}
		}
	};
}

/// Holds the data that should *not* be included in measurements.
struct Setup<CS: CipherSuite> {
	blind: Array<u8, <CS::Group as Group>::ScalarLength>,
	secret_key: SecretKey<CS::Group>,
	r: Array<u8, <CS::Group as Group>::ScalarLength>,
}

impl<CS: CipherSuite> Setup<CS> {
	fn new(_: CS) -> Self {
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

/// Code to bench.
fn bench<CS: CipherSuite>(mode: Mode, setup: Setup<CS>) -> (Output<CS::Hash>, Output<CS::Hash>) {
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

group!(Oprf);
group!(Voprf);
group!(Poprf);

main!(library_benchmark_groups = OPRF, VOPRF, POPRF);
