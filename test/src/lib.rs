//! Test utilities.

#![cfg_attr(coverage_nightly, feature(coverage_attribute), coverage(off))]
#![expect(
	clippy::cargo_common_metadata,
	clippy::indexing_slicing,
	clippy::unwrap_used,
	reason = "tests"
)]

pub mod cipher_suite;
pub mod helper;
mod rng;

pub use self::cipher_suite::MockCs;
pub use self::helper::{HelperClient, HelperServer};

/// Generates `#[test]` functions pre-fixed with the given `name` for all
/// available [`CipherSuite`]s and passes the appropriate
/// [`Mode`](oprf::common::Mode).
#[macro_export]
macro_rules! test_ciphersuites {
	($name:ident) => {
		$crate::test_ciphersuites!(internal: $name, $name);
	};
	($name:ident, Oprf) => {
		$crate::test_ciphersuites!(mode: $name, Oprf, oprf);
	};
	($name:ident, Voprf) => {
		$crate::test_ciphersuites!(mode: $name, Voprf, voprf);
	};
	($name:ident, Poprf) => {
		$crate::test_ciphersuites!(mode: $name, Poprf, poprf);
	};
	(mode: $name:ident, $mode:ident, $mode_prefix:ident) => {
		::paste::paste! {
			$crate::test_ciphersuites!(internal: [<$name _ $mode_prefix>], $name, $mode);
		}
	};
	(internal: $prefixed_name:ident, $name:ident $(, $mode:ident)?) => {
		::paste::paste! {
			#[test]
			fn [<$prefixed_name _p256>]() {
				$name::<::p256::NistP256>($(::oprf::common::Mode::$mode)?);
			}

			#[test]
			fn [<$prefixed_name _p384>]() {
				$name::<::p384::NistP384>($(::oprf::common::Mode::$mode)?);
			}

			#[test]
			fn [<$prefixed_name _p521>]() {
				$name::<::p521::NistP521>($(::oprf::common::Mode::$mode)?);
			}
		}
	};
}

/// Default `input`.
pub const INPUT: &[&[u8]] = &[b"test input"];
/// Default `info`.
pub const INFO: &[u8] = b"test info";
