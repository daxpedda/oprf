//! Tests for unequal `output`.

#![cfg(test)]
#![expect(clippy::cargo_common_metadata, reason = "tests")]

mod util;

use core::slice;
use std::iter;

use oprf::ciphersuite::CipherSuite;
use oprf::common::Mode;
use util::{HelperClient, HelperServer, INFO, INPUT};

test_ciphersuites!(input, Oprf);
test_ciphersuites!(input, Voprf);
test_ciphersuites!(input, Poprf);

/// Tests unequal `output` with different `input`s.
fn input<CS: CipherSuite>(mode: Mode) {
	let client = HelperClient::<CS>::blind(mode);
	let server = HelperServer::blind_evaluate(&client);

	// Failure on wrong input during `Finalize` and `Evaluate`.
	let wrong_client_output = client
		.finalize_with(
			server.public_key(),
			server.evaluation_element(),
			server.proof(),
			&[b"wrong"],
			INFO,
		)
		.unwrap();
	let wrong_server_output = server
		.evaluate_with(server.state(), &[b"wrong"], INFO)
		.unwrap();
	assert_ne!(wrong_client_output, wrong_server_output);

	// Failure on wrong input during `Finalize`.
	let server_output = server.evaluate();
	assert_ne!(wrong_server_output, server_output);

	// Failure on wrong input during `Evaluate`.
	let client_output = client.finalize(&server);
	assert_ne!(client_output, wrong_server_output);
}

test_ciphersuites!(input_batch, Voprf);
test_ciphersuites!(input_batch, Poprf);

/// Tests unequal `output` with different `input`s when using batching methods.
fn input_batch<CS: CipherSuite>(mode: Mode) {
	let clients = HelperClient::<CS>::batch(mode, 1);
	let prepared = HelperServer::prepare(&clients);
	let server = prepared.finish(&clients);

	// Failure on wrong input during `Finalize` and `Evaluate`.
	let wrong_client_output = clients
		.finalize_fixed_with::<1, _, _>(
			&server,
			iter::once::<&[&[u8]]>(&[b"wrong"]),
			server.evaluation_elements(),
			INFO,
		)
		.unwrap();
	let wrong_server_output = server
		.evaluate_with(server.state(), &[b"wrong"], INFO)
		.unwrap();
	assert_ne!(wrong_client_output, slice::from_ref(&wrong_server_output));

	// Failure on wrong input during `Finalize`.
	let server_output = server.evaluate();
	assert_ne!(wrong_client_output, [server_output]);

	// Failure on wrong input during `Evaluate`.
	let client_output = clients.finalize_fixed::<1>(&server);
	assert_ne!(client_output, [wrong_server_output]);
}

test_ciphersuites!(info, Poprf);

/// Tests unequal `output` with different `info`s.
fn info<CS: CipherSuite>(mode: Mode) {
	let client = HelperClient::<CS>::blind(mode);
	let server = HelperServer::blind_evaluate(&client);

	let client_output = client.finalize(&server);

	let server_output = server
		.evaluate_with(server.state(), INPUT, b"wrong")
		.unwrap();

	assert_ne!(client_output, server_output);
}

test_ciphersuites!(info_batch, Poprf);

/// Tests unequal `output` with different `info`s when using batching methods.
fn info_batch<CS: CipherSuite>(_: Mode) {
	let clients = HelperClient::<CS>::batch(Mode::Poprf, 1);
	let prepared = HelperServer::prepare(&clients);
	let server = prepared.finish(&clients);

	let client_output = clients.finalize_fixed::<1>(&server);

	let server_output = server
		.evaluate_with(server.state(), INPUT, b"wrong")
		.unwrap();

	assert_ne!(client_output, [server_output]);
}

test_ciphersuites!(state, Poprf);

/// Tests passing wrong state to POPRF `Evaluate`.
fn state<CS: CipherSuite>(_: Mode) {
	let client = HelperClient::<CS>::blind(Mode::Poprf);
	let server = HelperServer::blind_evaluate(&client);
	let wrong_server = HelperServer::blind_evaluate(&client);

	let client_output = client.finalize(&server);

	let server_output = server
		.evaluate_with(wrong_server.state(), INPUT, INFO)
		.unwrap();

	assert_ne!(client_output, server_output);
}

test_ciphersuites!(state_batch, Poprf);

/// Tests passing wrong state to POPRF `Evaluate` when using batching methods.
fn state_batch<CS: CipherSuite>(_: Mode) {
	let clients = HelperClient::<CS>::batch(Mode::Poprf, 1);
	let prepared = HelperServer::prepare(&clients);
	let server = prepared.finish(&clients);
	let wrong_prepared = HelperServer::prepare(&clients);
	let wrong_server = wrong_prepared.finish(&clients);

	let client_output = clients.finalize_fixed::<1>(&server);

	let server_output = server
		.evaluate_with(wrong_server.state(), INPUT, b"wrong")
		.unwrap();

	assert_ne!(client_output, [server_output]);
}
