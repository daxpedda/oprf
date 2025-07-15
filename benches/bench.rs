//! Basic benchmark.

#![expect(clippy::cargo_common_metadata, clippy::unwrap_used, reason = "tests")]

use std::ops::Deref;
use std::time::Duration;

use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion};
use oprf::cipher_suite::CipherSuite;
use oprf::common::{BlindedElement, EvaluationElement, Mode, Proof};
use oprf::group::Group;
use oprf::group::decaf448::Decaf448;
use oprf::group::ristretto255::Ristretto255;
use oprf::key::{PublicKey, SecretKey};
use oprf_test::{CommonClient, CommonServer, INFO, INPUT};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use rand_core::OsRng;

/// Default [`Criterion`] configuration.
fn criterion() -> Criterion {
	Criterion::default()
		.warm_up_time(Duration::from_secs(1))
		.measurement_time(Duration::from_secs(5))
		.sample_size(10)
		.nresamples(1001)
		.configure_from_args()
}

/// Code to bench.
fn bench<CS: CipherSuite>(group: &mut BenchmarkGroup<'_, WallTime>, mode: Mode) {
	group.bench_function(str::from_utf8(CS::ID.deref()).unwrap(), |bencher| {
		bencher.iter_batched(
			|| {
				let blind = <CS::Group as Group>::scalar_random(&mut OsRng).unwrap();
				let blind = <CS::Group as Group>::scalar_to_repr(&blind);

				let secret_key = SecretKey::generate(&mut OsRng).unwrap();

				let r = <CS::Group as Group>::scalar_random(&mut OsRng).unwrap();
				let r = <CS::Group as Group>::scalar_to_repr(&r);

				(blind, secret_key, r)
			},
			|(blind, secret_key, r)| {
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
			},
			criterion::BatchSize::SmallInput,
		);
	});
}

/// Criterion group.
#[expect(clippy::significant_drop_tightening, reason = "false-positive")]
fn group(mode: Mode) {
	let mut criterion = criterion();
	let mut group = criterion.benchmark_group(format!("{mode:?}").to_uppercase());

	bench::<NistP256>(&mut group, mode);
	bench::<NistP384>(&mut group, mode);
	bench::<NistP521>(&mut group, mode);
	bench::<Ristretto255>(&mut group, mode);
	bench::<Decaf448>(&mut group, mode);
}

fn main() {
	group(Mode::Oprf);
	group(Mode::Voprf);
	group(Mode::Poprf);

	Criterion::default().configure_from_args().final_summary();
}
