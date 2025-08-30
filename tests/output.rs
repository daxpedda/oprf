//! Tests for unequal `output`.

#![cfg(test)]
#![expect(clippy::cargo_common_metadata, reason = "tests")]

use oprf::cipher_suite::CipherSuite;
use oprf::common::Mode;
use oprf_test::{CommonClient, CommonServer, INFO, INPUT, test_ciphersuites};

test_ciphersuites!(input, Mode);

/// Tests unequal `output` with different `input`s.
fn input<CS: CipherSuite>(mode: Mode) {
	let client = CommonClient::<CS>::blind(mode);
	let server = CommonServer::blind_evaluate(&client);

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

test_ciphersuites!(input_batch, Mode);

/// Tests unequal `output` with different `input`s when using batching methods.
fn input_batch<CS: CipherSuite>(mode: Mode) {
	let clients = CommonClient::<CS>::batch::<1>(mode);
	let server = CommonServer::batch::<1>(&clients);

	// Failure on wrong input during `Finalize` and `Evaluate`.
	let wrong_client_output = clients
		.finalize_with::<1>(
			server.public_key(),
			&[&[b"wrong"]],
			server.evaluation_elements(),
			server.proof(),
			INFO,
		)
		.unwrap();
	let wrong_server_output = server.evaluate_with(&[&[b"wrong"]], INFO).unwrap();
	assert_ne!(wrong_client_output, wrong_server_output);

	// Failure on wrong input during `Finalize`.
	let server_output = server.evaluate();
	assert_ne!(wrong_client_output, server_output);

	// Failure on wrong input during `Evaluate`.
	let client_output = clients.finalize::<1>(&server);
	assert_ne!(client_output, wrong_server_output);
}

test_ciphersuites!(info, Poprf);

/// Tests unequal `output` with different `info`s.
fn info<CS: CipherSuite>(mode: Mode) {
	let client = CommonClient::<CS>::blind(mode);
	let server = CommonServer::blind_evaluate(&client);

	let client_output = client.finalize(&server);
	let server_output = server.evaluate_with(INPUT, b"wrong").unwrap();
	assert_ne!(client_output, server_output);
}

test_ciphersuites!(info_batch, Poprf);

/// Tests unequal `output` with different `info`s when using batching methods.
fn info_batch<CS: CipherSuite>(_: Mode) {
	let clients = CommonClient::<CS>::batch::<1>(Mode::Poprf);
	let server = CommonServer::batch::<1>(&clients);

	let client_output = clients.finalize::<1>(&server);
	let server_output = server.evaluate_with(&[INPUT], b"wrong").unwrap();
	assert_ne!(client_output, server_output);
}

test_ciphersuites!(server, Mode);

/// Tests using wrong server in `Evaluate`.
fn server<CS: CipherSuite>(_: Mode) {
	let client = CommonClient::<CS>::blind(Mode::Poprf);
	let server = CommonServer::blind_evaluate(&client);
	let wrong_server = CommonServer::blind_evaluate(&client);

	let client_output = client.finalize(&server);
	let server_output = wrong_server.evaluate();
	assert_ne!(client_output, server_output);
}

test_ciphersuites!(state_batch, Voprf);
test_ciphersuites!(state_batch, Poprf);

/// Tests using wrong server in `Evaluate` when using batching methods.
fn state_batch<CS: CipherSuite>(_: Mode) {
	let clients = CommonClient::<CS>::batch::<1>(Mode::Poprf);
	let server = CommonServer::batch::<1>(&clients);
	let wrong_server = CommonServer::batch::<1>(&clients);

	let client_output = clients.finalize::<1>(&server);
	let server_output = wrong_server.evaluate();
	assert_ne!(client_output, server_output);
}
