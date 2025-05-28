//! Test vector suite.

#![expect(clippy::indexing_slicing, reason = "tests should panic")]

mod cycle_rng;
mod oprf;
mod parse;
mod poprf;
mod voprf;

use hex_literal::hex;

/// Generates `#[test]` functions pre-fixed with the given `name` for all
/// available [`CipherSuite`]s.
#[macro_export]
macro_rules! test_ciphersuites {
	($name:ident) => {
		paste::paste! {
			#[test]
			fn [<$name _p256>]() {
				$name::<::p256::NistP256>();
			}

			#[test]
			fn [<$name _p384>]() {
				$name::<::p384::NistP384>();
			}

			#[test]
			fn [<$name _p521>]() {
				$name::<::p521::NistP521>();
			}
		}
	};
}

/// Seed `info` used in every test vector.
const KEY_INFO: &[u8] = b"test key";
/// Seed used in every test vector.
const SEED: [u8; 32] = hex!("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");
/// `info` used in every test vector.
const INFO: [u8; 9] = hex!("7465737420696e666f");
