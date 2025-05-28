//! Tests for invalid [`Proof`](oprf::Proof)s.

#![cfg(test)]
#![expect(clippy::cargo_common_metadata, reason = "tests")]

mod util;

use std::iter;

use oprf::Error;
use oprf::ciphersuite::CipherSuite;
use oprf::common::Mode;
use util::{HelperClient, HelperServer, INFO, INPUT};

test_ciphersuites!(basic, Voprf);
test_ciphersuites!(basic, Poprf);

/// Tests correct failure if the [`Proof`] is invalid.
fn basic<CS: CipherSuite>(mode: Mode) {
	let client = HelperClient::<CS>::blind(mode);
	let server = HelperServer::<CS>::blind_evaluate(&client);
	let wrong_server = HelperServer::<CS>::blind_evaluate_with(&client, b"wrong").unwrap();

	// Failure on wrong public key.
	let result = client.finalize_with(
		wrong_server.public_key(),
		server.evaluation_element(),
		server.proof(),
		INPUT,
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Proof);

	// Failure on wrong evaluation element.
	let result = client.finalize_with(
		server.public_key(),
		wrong_server.evaluation_element(),
		server.proof(),
		INPUT,
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Proof);

	// Failure on wrong proof.
	let result = client.finalize_with(
		server.public_key(),
		server.evaluation_element(),
		wrong_server.proof(),
		INPUT,
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Proof);

	// Failure on wrong info.
	if let Mode::Poprf = mode {
		let result = client.finalize_with(
			server.public_key(),
			server.evaluation_element(),
			server.proof(),
			INPUT,
			b"wrong",
		);
		assert_eq!(result.unwrap_err(), Error::Proof);
	}
}

test_ciphersuites!(state, Poprf);

/// Tests passing wrong state to `PoprfServer::finish_batch_blind_evaluate()`.
fn state<CS: CipherSuite>(_: Mode) {
	let clients = HelperClient::<CS>::batch(Mode::Poprf, 1);
	let prepared = HelperServer::prepare(&clients);
	let wrong_prepared = HelperServer::prepare(&clients);

	let server = prepared
		.finish_with(
			wrong_prepared.state(),
			clients.blinded_elements().iter(),
			prepared.prepared_elements(),
		)
		.unwrap();

	let result = clients.finalize_with(
		..,
		&server,
		iter::once(INPUT),
		server.evaluation_elements(),
		INFO,
	);

	assert_eq!(result.unwrap_err(), Error::Proof);
}
