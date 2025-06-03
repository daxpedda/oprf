//! Tests for unequal `output`.

#![cfg(test)]
#![expect(clippy::cargo_common_metadata, reason = "tests")]

mod util;

use core::slice;
use std::iter;

use oprf::ciphersuite::CipherSuite;
use oprf::common::Mode;

use crate::util::{HelperClient, HelperServer, INFO, INPUT};

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
			&[b"wrong"],
			server.evaluation_element(),
			server.proof(),
			INFO,
		)
		.unwrap();
	let wrong_server_output = server.evaluate_with(&[b"wrong"], INFO).unwrap();
	assert_ne!(wrong_client_output, wrong_server_output);

	// Failure on wrong input during `Finalize`.
	let server_output = server.evaluate();
	assert_ne!(wrong_server_output, server_output);

	// Failure on wrong input during `Evaluate`.
	let client_output = client.finalize(&server);
	assert_ne!(client_output, wrong_server_output);
}

test_ciphersuites!(input_batch, Oprf);
test_ciphersuites!(input_batch, Voprf);
test_ciphersuites!(input_batch, Poprf);

/// Tests unequal `output` with different `input`s when using batching methods.
fn input_batch<CS: CipherSuite>(mode: Mode) {
	let clients = HelperClient::<CS>::batch(mode, 1);
	let server = HelperServer::batch_fixed::<1>(&clients);

	// Failure on wrong input during `Finalize` and `Evaluate`.
	let wrong_client_output = clients
		.finalize_fixed_with::<1, _>(
			server.public_key(),
			iter::once::<&[&[u8]]>(&[b"wrong"]),
			server.evaluation_elements(),
			server.proof(),
			INFO,
		)
		.unwrap();
	let wrong_server_output = server.evaluate_with(&[b"wrong"], INFO).unwrap();
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
	let server_output = server.evaluate_with(INPUT, b"wrong").unwrap();
	assert_ne!(client_output, server_output);
}

test_ciphersuites!(info_batch, Poprf);

/// Tests unequal `output` with different `info`s when using batching methods.
fn info_batch<CS: CipherSuite>(_: Mode) {
	let clients = HelperClient::<CS>::batch(Mode::Poprf, 1);
	let server = HelperServer::batch_fixed::<1>(&clients);

	let client_output = clients.finalize_fixed::<1>(&server);
	let server_output = server.evaluate_with(INPUT, b"wrong").unwrap();
	assert_ne!(client_output, [server_output]);
}

test_ciphersuites!(server, Oprf);
test_ciphersuites!(server, Voprf);
test_ciphersuites!(server, Poprf);

/// Tests using wrong server in `Evaluate`.
fn server<CS: CipherSuite>(_: Mode) {
	let client = HelperClient::<CS>::blind(Mode::Poprf);
	let server = HelperServer::blind_evaluate(&client);
	let wrong_server = HelperServer::blind_evaluate(&client);

	let client_output = client.finalize(&server);
	let server_output = wrong_server.evaluate();
	assert_ne!(client_output, server_output);
}

test_ciphersuites!(state_batch, Voprf);
test_ciphersuites!(state_batch, Poprf);

/// Tests using wrong server in `Evaluate` when using batching methods.
fn state_batch<CS: CipherSuite>(_: Mode) {
	let clients = HelperClient::<CS>::batch(Mode::Poprf, 1);
	let server = HelperServer::batch_fixed::<1>(&clients);
	let wrong_server = HelperServer::batch_fixed::<1>(&clients);

	let client_output = clients.finalize_fixed::<1>(&server);
	let server_output = wrong_server.evaluate();
	assert_ne!(client_output, [server_output]);
}
