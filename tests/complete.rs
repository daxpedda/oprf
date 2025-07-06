//! Tests complete protocol.

#![cfg(test)]
#![expect(clippy::cargo_common_metadata, reason = "tests")]

use oprf::cipher_suite::CipherSuite;
use oprf::common::Mode;
use oprf_test::{HelperClient, HelperServer, test_ciphersuites};

test_ciphersuites!(basic, Oprf);
test_ciphersuites!(basic, Voprf);
test_ciphersuites!(basic, Poprf);

/// Tests complete protocol.
fn basic<CS: CipherSuite>(mode: Mode) {
	let client = HelperClient::<CS>::blind(mode);
	let server = HelperServer::blind_evaluate(&client);
	let client_output = client.finalize(&server);
	let server_output = server.evaluate();

	assert_eq!(client_output, server_output);
}

test_ciphersuites!(batch, Oprf);
test_ciphersuites!(batch, Voprf);
test_ciphersuites!(batch, Poprf);

/// Tests complete protocol when using batching methods.
fn batch<CS: CipherSuite>(mode: Mode) {
	let clients = HelperClient::<CS>::batch::<2>(mode);
	let server = HelperServer::batch::<2>(&clients);
	let client_outputs = clients.finalize::<2>(&server);
	let server_output = server.evaluate();

	assert_eq!(client_outputs, server_output);
}

#[cfg(feature = "alloc")]
test_ciphersuites!(batch_vec, Oprf);
#[cfg(feature = "alloc")]
test_ciphersuites!(batch_vec, Voprf);
#[cfg(feature = "alloc")]
test_ciphersuites!(batch_vec, Poprf);

/// Tests complete protocol when using batching methods with `alloc`.
#[cfg(feature = "alloc")]
fn batch_vec<CS: CipherSuite>(mode: Mode) {
	let clients = HelperClient::<CS>::batch_vec(mode, 2);
	let server = HelperServer::batch_vec(&clients);
	let client_outputs = clients.finalize_vec(&server);
	let server_output = server.evaluate_vec();

	assert_eq!(client_outputs, server_output);
}
