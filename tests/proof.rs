//! Tests for invalid [`Proof`](oprf::Proof)s.

#![cfg(test)]
#![expect(clippy::cargo_common_metadata, reason = "tests")]

#[cfg(feature = "alloc")]
use std::iter;

use oprf::Error;
use oprf::cipher_suite::CipherSuite;
use oprf::common::Mode;
use oprf_test::{CommonClient, CommonServer, INFO, INPUT, test_ciphersuites};

test_ciphersuites!(basic, Voprf);
test_ciphersuites!(basic, Poprf);

/// Tests correct failure if the [`Proof`] is invalid.
fn basic<Cs: CipherSuite>(mode: Mode) {
	let client = CommonClient::<Cs>::blind(mode);
	let server = CommonServer::<Cs>::blind_evaluate(&client);
	let wrong_server = CommonServer::<Cs>::blind_evaluate_with(
		mode,
		None,
		client.blinded_element(),
		None,
		Some(b"wrong"),
	)
	.unwrap();

	// Failure on wrong public key.
	let result = client.finalize_with(
		wrong_server.public_key(),
		INPUT,
		server.evaluation_element(),
		server.proof(),
		Some(INFO),
	);
	assert_eq!(result.unwrap_err(), Error::Proof);

	// Failure on wrong evaluation element.
	let result = client.finalize_with(
		server.public_key(),
		INPUT,
		wrong_server.evaluation_element(),
		server.proof(),
		Some(INFO),
	);
	assert_eq!(result.unwrap_err(), Error::Proof);

	// Failure on wrong proof.
	let result = client.finalize_with(
		server.public_key(),
		INPUT,
		server.evaluation_element(),
		wrong_server.proof(),
		Some(INFO),
	);
	assert_eq!(result.unwrap_err(), Error::Proof);

	// Failure on wrong info.
	if let Mode::Poprf = mode {
		let result = client.finalize_with(
			server.public_key(),
			INPUT,
			server.evaluation_element(),
			server.proof(),
			Some(b"wrong"),
		);
		assert_eq!(result.unwrap_err(), Error::Proof);
	}
}

test_ciphersuites!(batch, Voprf);
test_ciphersuites!(batch, Poprf);

/// Tests correct failure if the [`Proof`] is invalid when using batching
/// methods.
fn batch<Cs: CipherSuite>(mode: Mode) {
	let client = CommonClient::<Cs>::batch::<1>(mode);
	let server = CommonServer::<Cs>::batch::<1>(&client);
	let wrong_server = CommonServer::<Cs>::batch::<1>(&client);

	// Failure on wrong public key.
	let result = client.finalize_with::<1>(
		wrong_server.public_key(),
		&[INPUT],
		server.evaluation_elements(),
		server.proof(),
		Some(INFO),
	);
	assert_eq!(result.unwrap_err(), Error::Proof);

	// Failure on wrong evaluation element.
	let result = client.finalize_with::<1>(
		server.public_key(),
		&[INPUT],
		wrong_server.evaluation_elements(),
		server.proof(),
		Some(INFO),
	);
	assert_eq!(result.unwrap_err(), Error::Proof);

	// Failure on wrong proof.
	let result = client.finalize_with::<1>(
		server.public_key(),
		&[INPUT],
		server.evaluation_elements(),
		wrong_server.proof(),
		Some(INFO),
	);
	assert_eq!(result.unwrap_err(), Error::Proof);

	// Failure on wrong info.
	if let Mode::Poprf = mode {
		let result = client.finalize_with::<1>(
			server.public_key(),
			&[INPUT],
			server.evaluation_elements(),
			server.proof(),
			Some(b"wrong"),
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
fn batch_alloc<Cs: CipherSuite>(mode: Mode) {
	let client = CommonClient::<Cs>::batch_alloc(mode, 1);
	let server = CommonServer::<Cs>::batch_alloc(&client);
	let wrong_server = CommonServer::<Cs>::batch_alloc(&client);

	// Failure on wrong public key.
	let result = client.finalize_alloc_with(
		..,
		wrong_server.public_key(),
		iter::once(INPUT),
		server.evaluation_elements().iter(),
		server.proof(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Proof);

	// Failure on wrong evaluation element.
	let result = client.finalize_alloc_with(
		..,
		server.public_key(),
		iter::once(INPUT),
		wrong_server.evaluation_elements().iter(),
		server.proof(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Proof);

	// Failure on wrong proof.
	let result = client.finalize_alloc_with(
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
		let result = client.finalize_alloc_with(
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
