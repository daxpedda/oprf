//! Basic Criterion benchmark.

#![expect(
	clippy::cargo_common_metadata,
	clippy::unwrap_used,
	reason = "benchmarks"
)]

use std::ops::Deref;
use std::time::Duration;

use criterion::measurement::WallTime;
use criterion::{BatchSize, BenchmarkGroup, Criterion};
use oprf::cipher_suite::CipherSuite;
use oprf::common::Mode;
use oprf::group::decaf448::Decaf448;
use oprf::group::ristretto255::Ristretto255;
use oprf_test::Setup;
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;

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
			Setup::<CS>::default,
			|setup| oprf_test::bench(mode, setup),
			BatchSize::SmallInput,
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
