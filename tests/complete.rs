//! Tests complete protocol.

#![cfg(test)]
#![expect(clippy::cargo_common_metadata, reason = "tests")]

use oprf::cipher_suite::CipherSuite;
use oprf::common::Mode;
use oprf::group::ristretto255::Ristretto255;
use oprf::{Decaf448, NistP256, NistP384, NistP521};
use oprf_test::{
	CommonClient, CommonServer, Edwards448, Edwards25519, MockCs, Secp256k1, test_ciphersuites,
};

test_ciphersuites!(
	basic,
	Mode,
	[
		Secp256k1 as k256,
		NistP256 as p256,
		NistP384 as p384,
		NistP521 as p521,
		Edwards25519 as edwards25519,
		Ristretto255 as ristretto255,
		Edwards448 as edwards448,
		Decaf448 as decaf448,
		MockCs as mock
	]
);

/// Tests complete protocol.
fn basic<Cs: CipherSuite>(mode: Mode) {
	let client = CommonClient::<Cs>::blind(mode);
	let server = CommonServer::blind_evaluate(&client);
	let client_output = client.finalize(&server);
	let server_output = server.evaluate();

	assert_eq!(client_output, server_output);
}

test_ciphersuites!(
	batch,
	Mode,
	[
		Secp256k1 as k256,
		NistP256 as p256,
		NistP384 as p384,
		NistP521 as p521,
		Edwards25519 as edwards25519,
		Ristretto255 as ristretto255,
		Edwards448 as edwards448,
		Decaf448 as decaf448,
		MockCs as mock
	]
);

/// Tests complete protocol when using batching methods.
fn batch<Cs: CipherSuite>(mode: Mode) {
	let clients = CommonClient::<Cs>::batch::<2>(mode);
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
		Secp256k1 as k256,
		NistP256 as p256,
		NistP384 as p384,
		NistP521 as p521,
		Edwards25519 as edwards25519,
		Ristretto255 as ristretto255,
		Edwards448 as edwards448,
		Decaf448 as decaf448,
		MockCs as mock
	]
);

/// Tests complete protocol when using batching methods with `alloc`.
#[cfg(feature = "alloc")]
fn batch_alloc<Cs: CipherSuite>(mode: Mode) {
	let clients = CommonClient::<Cs>::batch_alloc(mode, 2);
	let server = CommonServer::batch_alloc(&clients);
	let client_outputs = clients.finalize_alloc(&server);
	let server_output = server.evaluate_alloc();

	assert_eq!(client_outputs, server_output);
}
