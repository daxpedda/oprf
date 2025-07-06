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

test_ciphersuites!(batch_fixed, Oprf);
test_ciphersuites!(batch_fixed, Voprf);
test_ciphersuites!(batch_fixed, Poprf);

/// Tests complete protocol when using batching methods.
fn batch_fixed<CS: CipherSuite>(mode: Mode) {
	let clients = HelperClient::<CS>::batch_fixed::<2>(mode);
	let server = HelperServer::batch_fixed::<2>(&clients);
	let client_outputs = clients.finalize_fixed(&server);
	let server_output = server.evaluate();

	assert_eq!(client_outputs, [server_output.clone(), server_output]);
}

#[cfg(feature = "alloc")]
test_ciphersuites!(batch, Oprf);
#[cfg(feature = "alloc")]
test_ciphersuites!(batch, Voprf);
#[cfg(feature = "alloc")]
test_ciphersuites!(batch, Poprf);

/// Tests complete protocol when using batching methods with `alloc`.
#[cfg(feature = "alloc")]
fn batch<CS: CipherSuite>(mode: Mode) {
	let clients = HelperClient::<CS>::batch(mode, 2);
	let server = HelperServer::batch(&clients);
	let client_outputs = clients.finalize(&server);
	let server_output = server.evaluate();

	assert_eq!(client_outputs, [server_output.clone(), server_output]);
}
