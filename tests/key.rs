//! Tests [`oprf::key`] related functionality.

#![cfg(test)]
#![expect(clippy::cargo_common_metadata, reason = "tests")]

use oprf::cipher_suite::CipherSuite;
use oprf::common::Mode;
use oprf::key::{KeyPair, PublicKey, SecretKey};
use oprf_test::test_ciphersuites;
use rand::TryRngCore;
use rand_core::OsRng;

test_ciphersuites!(basic);

// Tests basic key functionality.
fn basic<CS: CipherSuite>() {
	let key_pair = KeyPair::<CS::Group>::generate(&mut OsRng).unwrap();

	// Check `from_secret_key()`.
	assert_eq!(
		KeyPair::from_secret_key(key_pair.secret_key().clone()),
		key_pair
	);

	// Check `into_keys()`.
	assert_eq!(
		key_pair.clone().into_keys(),
		(key_pair.secret_key().clone(), key_pair.public_key().clone())
	);

	// Check de/serialization.
	assert_eq!(KeyPair::from_repr(&key_pair.to_repr()).unwrap(), key_pair);
	assert_eq!(
		&SecretKey::from_repr(&key_pair.secret_key().to_repr()).unwrap(),
		key_pair.secret_key()
	);
	assert_eq!(
		&PublicKey::from_repr(key_pair.public_key().as_repr()).unwrap(),
		key_pair.public_key()
	);

	// Check `as_*()` and `into_*()` underlying types.
	assert_eq!(
		key_pair.secret_key().as_scalar(),
		&key_pair.secret_key().clone().into_scalar()
	);
	assert_eq!(
		key_pair.public_key().as_point(),
		&key_pair.public_key().clone().into_point()
	);
}

test_ciphersuites!(derive, Oprf);
test_ciphersuites!(derive, Voprf);
test_ciphersuites!(derive, Poprf);

// Tests key deriviation.
fn derive<CS: CipherSuite>(mode: Mode) {
	let mut seed = [0; 32];
	OsRng.try_fill_bytes(&mut seed).unwrap();

	let key_pair = KeyPair::derive::<CS>(mode, &seed, &[]).unwrap();

	assert_eq!(
		&SecretKey::derive::<CS>(mode, &seed, &[]).unwrap(),
		key_pair.secret_key()
	);
}
