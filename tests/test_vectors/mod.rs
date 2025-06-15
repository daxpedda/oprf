//! Test vector suite.

#![cfg(test)]
#![expect(clippy::cargo_common_metadata, reason = "tests")]

mod basic;
mod batch;
mod parse;

use hex_literal::hex;
use oprf::cipher_suite::CipherSuite;
use oprf::common::Mode;
use oprf::key::{KeyPair, PublicKey, SecretKey};

use crate::parse::TestVector;

/// Seed `info` used in every test vector.
const KEY_INFO: &[u8] = b"test key";
/// Seed used in every test vector.
const SEED: [u8; 32] = hex!("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");

/// Shared key checks.
fn secret_key<CS: CipherSuite>(mode: Mode, test_vector: &TestVector) -> SecretKey<CS::Group> {
	let secret_key = SecretKey::<CS::Group>::derive::<CS>(mode, &SEED, KEY_INFO).unwrap();

	assert_eq!(test_vector.secret_key, secret_key.to_repr().as_slice(),);
	assert_eq!(
		SecretKey::from_repr(&test_vector.secret_key).unwrap(),
		secret_key,
	);

	if !matches!(mode, Mode::Oprf) {
		let public_key = KeyPair::from_secret_key(secret_key.clone()).into_keys().1;

		let vector_public_key = test_vector
			.public_key
			.as_ref()
			.expect("unexpected missing public key for VOPRF");
		assert_eq!(vector_public_key, public_key.as_repr().as_slice(),);
		assert_eq!(PublicKey::from_repr(vector_public_key).unwrap(), public_key,);
	}

	secret_key
}
