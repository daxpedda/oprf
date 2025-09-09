//! Tests [`oprf::key`] related functionality.

#![cfg(test)]
#![expect(clippy::cargo_common_metadata, reason = "tests")]

use oprf::cipher_suite::CipherSuite;
use oprf::common::Mode;
use oprf::key::{KeyPair, PublicKey, SecretKey};
use oprf::oprf::OprfServer;
use oprf::poprf::PoprfServer;
use oprf::voprf::VoprfServer;
use oprf_test::{INFO, test_ciphersuites};
use rand_core::{OsRng, TryRngCore};

test_ciphersuites!(basic);

// Tests basic key functionality.
fn basic<Cs: CipherSuite>() {
	let key_pair = KeyPair::<Cs::Group>::generate(&mut OsRng).unwrap();

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
		key_pair.public_key().as_element(),
		&key_pair.public_key().clone().into_element()
	);
}

test_ciphersuites!(derive, Mode);

// Tests key deriviation.
fn derive<Cs: CipherSuite>(mode: Mode) {
	let mut seed = [0; 32];
	OsRng.try_fill_bytes(&mut seed).unwrap();

	let key_pair = KeyPair::derive::<Cs>(mode, &seed, &[]).unwrap();

	assert_eq!(
		&SecretKey::derive::<Cs>(mode, &seed, &[]).unwrap(),
		key_pair.secret_key()
	);
}

test_ciphersuites!(oprf_from_seed);

fn oprf_from_seed<Cs: CipherSuite>() {
	let mut seed = [0; 32];
	OsRng.try_fill_bytes(&mut seed).unwrap();

	let server = OprfServer::<Cs>::from_seed(&seed, &[]).unwrap();

	assert_eq!(
		&SecretKey::derive::<Cs>(Mode::Oprf, &seed, &[]).unwrap(),
		server.secret_key()
	);
}

test_ciphersuites!(voprf_from_seed);

fn voprf_from_seed<Cs: CipherSuite>() {
	let mut seed = [0; 32];
	OsRng.try_fill_bytes(&mut seed).unwrap();

	let server = VoprfServer::<Cs>::from_seed(&seed, &[]).unwrap();

	assert_eq!(
		&KeyPair::derive::<Cs>(Mode::Voprf, &seed, &[]).unwrap(),
		server.key_pair()
	);
}

test_ciphersuites!(poprf_from_seed);

fn poprf_from_seed<Cs: CipherSuite>() {
	let mut seed = [0; 32];
	OsRng.try_fill_bytes(&mut seed).unwrap();

	let server = PoprfServer::<Cs>::from_seed(&seed, &[], INFO).unwrap();

	assert_eq!(
		&KeyPair::derive::<Cs>(Mode::Poprf, &seed, &[]).unwrap(),
		server.key_pair()
	);
}
