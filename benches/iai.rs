//! Basic IAI benchmark.

#![expect(clippy::cargo_common_metadata, reason = "benchmarks")]
#![expect(clippy::exit, missing_docs, non_snake_case, reason = "iai")]

use ::oprf::cipher_suite::CipherSuite;
use ::oprf::common::Mode;
use ::oprf::group::{decaf448, ristretto255};
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use oprf_test::Setup;
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use paste::paste;

/// Benchmark the provided [`Mode`].
macro_rules! group {
	($mode:ident) => {
		paste! {
			library_benchmark_group!(name = [<$mode:upper>]; benchmarks = [<$mode:lower>]);

			#[library_benchmark]
			#[bench::P256(args = (NistP256), setup = setup)]
			#[bench::P384(args = (NistP384), setup = setup)]
			#[bench::P521(args = (NistP521), setup = setup)]
			#[bench::Ristretto255(args = (ristretto255::Ristretto255), setup = setup)]
			#[bench::Decaf448(args = (decaf448::Decaf448), setup = setup)]
			fn [<$mode:lower>]<Cs: CipherSuite>(setup: Setup<Cs>) {
				oprf_test::bench(Mode::$mode, setup);
			}
		}
	};
}

/// IAI doesn't support generics, so we infer it from the parameter.
fn setup<Cs: CipherSuite>(_: Cs) -> Setup<Cs> {
	Setup::default()
}

group!(Oprf);
group!(Voprf);
group!(Poprf);

main!(library_benchmark_groups = OPRF, VOPRF, POPRF);
