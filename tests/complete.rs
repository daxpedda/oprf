//! Tests complete protocol.

#![cfg(test)]
#![expect(clippy::cargo_common_metadata, reason = "tests")]

use oprf::cipher_suite::CipherSuite;
use oprf::common::Mode;
use oprf::group::decaf448::Decaf448;
use oprf::group::ristretto255::Ristretto255;
use oprf_test::{CommonClient, CommonServer, MockCs, test_ciphersuites};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;

test_ciphersuites!(
	basic,
	Mode,
	[
		NistP256 as p256,
		NistP384 as p384,
		NistP521 as p521,
		Ristretto255 as ristretto255,
		Decaf448 as decaf448,
		MockCs as mock
	]
);

/// Tests complete protocol.
fn basic<CS: CipherSuite>(mode: Mode) {
	let client = CommonClient::<CS>::blind(mode);
	let server = CommonServer::blind_evaluate(&client);
	let client_output = client.finalize(&server);
	let server_output = server.evaluate();

	assert_eq!(client_output, server_output);
}

test_ciphersuites!(
	batch,
	Mode,
	[
		NistP256 as p256,
		NistP384 as p384,
		NistP521 as p521,
		Ristretto255 as ristretto255,
		Decaf448 as decaf448,
		MockCs as mock
	]
);

/// Tests complete protocol when using batching methods.
fn batch<CS: CipherSuite>(mode: Mode) {
	let clients = CommonClient::<CS>::batch::<2>(mode);
	let server = CommonServer::batch::<2>(&clients);
	let client_outputs = clients.finalize::<2>(&server);
	let server_output = server.evaluate();

	assert_eq!(client_outputs, server_output);
}

#[cfg(feature = "alloc")]
test_ciphersuites!(
	batch_alloc,
	Mode,
	[
		NistP256 as p256,
		NistP384 as p384,
		NistP521 as p521,
		Ristretto255 as ristretto255,
		Decaf448 as decaf448,
		MockCs as mock
	]
);

/// Tests complete protocol when using batching methods with `alloc`.
#[cfg(feature = "alloc")]
fn batch_alloc<CS: CipherSuite>(mode: Mode) {
	let clients = CommonClient::<CS>::batch_alloc(mode, 2);
	let server = CommonServer::batch_alloc(&clients);
	let client_outputs = clients.finalize_alloc(&server);
	let server_output = server.evaluate_alloc();

	assert_eq!(client_outputs, server_output);
}
