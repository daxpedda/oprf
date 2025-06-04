//! TODO

#![expect(clippy::cargo_common_metadata, reason = "tests")]

use std::time::Duration;

use criterion::{Criterion, criterion_main};
use oprf::ciphersuite::CipherSuite;
use oprf::common::{BlindedElement, EvaluationElement, Proof};
use oprf::key::PublicKey;
use oprf::oprf::{OprfBlindResult, OprfClient, OprfServer};
use oprf::poprf::{PoprfBlindEvaluateResult, PoprfBlindResult, PoprfClient, PoprfServer};
use oprf::voprf::{VoprfBlindEvaluateResult, VoprfBlindResult, VoprfClient, VoprfServer};
use oprf::{Error, Result};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use rand::rngs::mock::StepRng;
use rand::{CryptoRng, RngCore};

/// Default `input`.
const INPUT: &[&[u8]] = &[b"test"];
/// Default `info`.
const INFO: &[u8] = b"test";

/// Type alias around [`Output`](digest::Output) over [`CipherSuite`].
type Output<CS> = digest::Output<<CS as CipherSuite>::Hash>;

/// [`CryptoRng`] wrapper around [`StepRng`].
struct MockRng(StepRng);

impl MockRng {
	/// Creates a new [`MockRng`].
	fn new() -> Self {
		Self(StepRng::new(u32::MAX.into(), 1))
	}
}

impl CryptoRng for MockRng {}

impl RngCore for MockRng {
	fn next_u32(&mut self) -> u32 {
		self.0.next_u32()
	}

	fn next_u64(&mut self) -> u64 {
		self.0.next_u64()
	}

	fn fill_bytes(&mut self, dst: &mut [u8]) {
		self.0.fill_bytes(dst);
	}
}

/// Benches OPRF flow.
#[expect(clippy::significant_drop_tightening, reason = "false-positive")]
fn oprf() {
	fn oprf<CS: CipherSuite>() -> Result<(Output<CS>, Output<CS>)> {
		let mut rng = MockRng::new();

		let OprfBlindResult {
			client,
			blinded_element,
		} = OprfClient::<CS>::blind(&mut rng, INPUT)?;
		let blinded_element = blinded_element.as_repr();

		let blinded_element = BlindedElement::from_repr(blinded_element)?;
		let server = OprfServer::<CS>::new(&mut rng).map_err(Error::Random)?;
		let evaluation_element = server.blind_evaluate(&blinded_element);
		let evaluation_element = evaluation_element.as_repr();
		let server_output = server.evaluate(INPUT)?;

		let evaluation_element = EvaluationElement::from_repr(evaluation_element)?;
		let client_output = client.finalize(INPUT, &evaluation_element)?;

		Ok((server_output, client_output))
	}

	let mut criterion = criterion();
	let mut group = criterion.benchmark_group("OPRF");

	group.bench_function("P256", |bencher| {
		bencher.iter(oprf::<NistP256>);
	});
	group.bench_function("P384", |bencher| {
		bencher.iter(oprf::<NistP384>);
	});
	group.bench_function("P521", |bencher| {
		bencher.iter(oprf::<NistP521>);
	});
}

/// Benches VOPRF flow.
#[expect(clippy::significant_drop_tightening, reason = "false-positive")]
fn voprf() {
	fn voprf<CS: CipherSuite>() -> Result<(Output<CS>, Output<CS>)> {
		let mut rng = MockRng::new();

		let VoprfBlindResult {
			client,
			blinded_element,
		} = VoprfClient::<CS>::blind(&mut rng, INPUT)?;
		let blinded_element = blinded_element.as_repr();

		let blinded_element = BlindedElement::from_repr(blinded_element)?;
		let server = VoprfServer::<CS>::new(&mut rng).map_err(Error::Random)?;
		let public_key = server.public_key().as_repr();
		let VoprfBlindEvaluateResult {
			evaluation_element,
			proof,
		} = server.blind_evaluate(&mut rng, &blinded_element)?;
		let evaluation_element = evaluation_element.as_repr();
		let proof = proof.to_repr();
		let server_output = server.evaluate(INPUT)?;

		let public_key = PublicKey::from_repr(public_key)?;
		let evaluation_element = EvaluationElement::from_repr(evaluation_element)?;
		let proof = Proof::from_repr(&proof)?;
		let client_output = client.finalize(&public_key, INPUT, &evaluation_element, &proof)?;

		Ok((server_output, client_output))
	}

	let mut criterion = criterion();
	let mut group = criterion.benchmark_group("VOPRF");

	group.bench_function("P256", |bencher| {
		bencher.iter(voprf::<NistP256>);
	});
	group.bench_function("P384", |bencher| {
		bencher.iter(voprf::<NistP384>);
	});
	group.bench_function("P521", |bencher| {
		bencher.iter(voprf::<NistP521>);
	});
}

/// Benches POPRF flow.
#[expect(clippy::significant_drop_tightening, reason = "false-positive")]
fn poprf() {
	fn poprf<CS: CipherSuite>() -> Result<(Output<CS>, Output<CS>)> {
		let mut rng = MockRng::new();

		let PoprfBlindResult {
			client,
			blinded_element,
		} = PoprfClient::<CS>::blind(&mut rng, INPUT)?;
		let blinded_element = blinded_element.as_repr();

		let blinded_element = BlindedElement::from_repr(blinded_element)?;
		let server = PoprfServer::<CS>::new(&mut rng, INFO)?;
		let public_key = server.public_key().as_repr();
		let PoprfBlindEvaluateResult {
			evaluation_element,
			proof,
		} = server.blind_evaluate(&mut rng, &blinded_element)?;
		let evaluation_element = evaluation_element.as_repr();
		let proof = proof.to_repr();
		let server_output = server.evaluate(INPUT, INFO)?;

		let public_key = PublicKey::from_repr(public_key)?;
		let evaluation_element = EvaluationElement::from_repr(evaluation_element)?;
		let proof = Proof::from_repr(&proof)?;
		let client_output =
			client.finalize(&public_key, INPUT, &evaluation_element, &proof, INFO)?;

		Ok((server_output, client_output))
	}

	let mut criterion = criterion();
	let mut group = criterion.benchmark_group("POPRF");

	group.bench_function("P256", |bencher| {
		bencher.iter(poprf::<NistP256>);
	});
	group.bench_function("P384", |bencher| {
		bencher.iter(poprf::<NistP384>);
	});
	group.bench_function("P521", |bencher| {
		bencher.iter(poprf::<NistP521>);
	});
}

/// Default [`Criterion`] configuration.
fn criterion() -> Criterion {
	Criterion::default()
		.warm_up_time(Duration::from_secs(1))
		.measurement_time(Duration::from_secs(5))
		.sample_size(10)
		.nresamples(1001)
		.configure_from_args()
}

criterion_main!(oprf, voprf, poprf);
