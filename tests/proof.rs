//! Tests for invalid [`Proof`](oprf::Proof)s.

#![cfg(test)]
#![expect(clippy::cargo_common_metadata, reason = "tests")]

use std::iter;

use oprf::Error;
use oprf::cipher_suite::CipherSuite;
use oprf::common::Mode;
use oprf_test::{HelperClient, HelperServer, INFO, INPUT, test_ciphersuites};

test_ciphersuites!(basic, Voprf);
test_ciphersuites!(basic, Poprf);

/// Tests correct failure if the [`Proof`] is invalid.
fn basic<CS: CipherSuite>(mode: Mode) {
	let client = HelperClient::<CS>::blind(mode);
	let server = HelperServer::<CS>::blind_evaluate(&client);
	let wrong_server =
		HelperServer::<CS>::blind_evaluate_with(&client, None, None, b"wrong").unwrap();

	// Failure on wrong public key.
	let result = client.finalize_with(
		wrong_server.public_key(),
		INPUT,
		server.evaluation_element(),
		server.proof(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Proof);

	// Failure on wrong evaluation element.
	let result = client.finalize_with(
		server.public_key(),
		INPUT,
		wrong_server.evaluation_element(),
		server.proof(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Proof);

	// Failure on wrong proof.
	let result = client.finalize_with(
		server.public_key(),
		INPUT,
		server.evaluation_element(),
		wrong_server.proof(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Proof);

	// Failure on wrong info.
	if let Mode::Poprf = mode {
		let result = client.finalize_with(
			server.public_key(),
			INPUT,
			server.evaluation_element(),
			server.proof(),
			b"wrong",
		);
		assert_eq!(result.unwrap_err(), Error::Proof);
	}
}

test_ciphersuites!(batch, Voprf);
test_ciphersuites!(batch, Poprf);

/// Tests correct failure if the [`Proof`] is invalid when using batching
/// methods.
fn batch<CS: CipherSuite>(mode: Mode) {
	let client = HelperClient::<CS>::batch(mode, 1);
	let server = HelperServer::<CS>::batch_fixed::<1>(&client);
	let wrong_server = HelperServer::<CS>::batch_fixed::<1>(&client);

	// Failure on wrong public key.
	let result = client.finalize_fixed_with::<1, _>(
		wrong_server.public_key(),
		iter::once(INPUT),
		server.evaluation_elements(),
		server.proof(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Proof);

	// Failure on wrong evaluation element.
	let result = client.finalize_fixed_with::<1, _>(
		server.public_key(),
		iter::once(INPUT),
		wrong_server.evaluation_elements(),
		server.proof(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Proof);

	// Failure on wrong proof.
	let result = client.finalize_fixed_with::<1, _>(
		server.public_key(),
		iter::once(INPUT),
		server.evaluation_elements(),
		wrong_server.proof(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Proof);

	// Failure on wrong info.
	if let Mode::Poprf = mode {
		let result = client.finalize_fixed_with::<1, _>(
			server.public_key(),
			iter::once(INPUT),
			server.evaluation_elements(),
			server.proof(),
			b"wrong",
		);
		assert_eq!(result.unwrap_err(), Error::Proof);
	}
}

#[cfg(feature = "alloc")]
test_ciphersuites!(batch_alloc, Voprf);
#[cfg(feature = "alloc")]
test_ciphersuites!(batch_alloc, Poprf);

/// Tests correct failure if the [`Proof`] is invalid when using batching
/// methods with alloc.
#[cfg(feature = "alloc")]
fn batch_alloc<CS: CipherSuite>(mode: Mode) {
	let client = HelperClient::<CS>::batch(mode, 1);
	let server = HelperServer::<CS>::batch(&client);
	let wrong_server = HelperServer::<CS>::batch(&client);

	// Failure on wrong public key.
	let result = client.finalize_with(
		..,
		wrong_server.public_key(),
		iter::once(INPUT),
		server.evaluation_elements().iter(),
		server.proof(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Proof);

	// Failure on wrong evaluation element.
	let result = client.finalize_with(
		..,
		server.public_key(),
		iter::once(INPUT),
		wrong_server.evaluation_elements().iter(),
		server.proof(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Proof);

	// Failure on wrong proof.
	let result = client.finalize_with(
		..,
		server.public_key(),
		iter::once(INPUT),
		server.evaluation_elements().iter(),
		wrong_server.proof(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Proof);

	// Failure on wrong info.
	if let Mode::Poprf = mode {
		let result = client.finalize_with(
			..,
			server.public_key(),
			iter::once(INPUT),
			server.evaluation_elements().iter(),
			server.proof(),
			b"wrong",
		);
		assert_eq!(result.unwrap_err(), Error::Proof);
	}
}
