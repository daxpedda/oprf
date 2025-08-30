//! Test utilities.

#![cfg_attr(coverage_nightly, feature(coverage_attribute), coverage(off))]
#![expect(
	clippy::cargo_common_metadata,
	clippy::indexing_slicing,
	clippy::unwrap_used,
	reason = "tests"
)]

pub mod cipher_suite;
pub mod common;
mod rng;
#[cfg(feature = "serde")]
mod serde;
mod serialized;

pub use oprf;

pub use self::cipher_suite::{MockCs, MockCurve, MockExpandMsg, MockHash};
pub use self::common::{CommonClient, CommonServer};
#[cfg(feature = "serde")]
pub use self::serde::{ScalarRepr, TypeRepr};
pub use self::serialized::*;

/// Generates `#[test]` functions pre-fixed with the given `name` for all
/// available [`CipherSuite`]s and passes the appropriate
/// [`Mode`](oprf::common::Mode).
#[macro_export]
macro_rules! test_ciphersuites {
	($name:ident) => {
		$crate::test_ciphersuites!(internal: $name, $name);
	};
	($name:ident, Oprf) => {
		$crate::test_ciphersuites!(mode: $name, Oprf);
	};
	($name:ident, Voprf) => {
		$crate::test_ciphersuites!(mode: $name, Voprf);
	};
	($name:ident, Poprf) => {
		$crate::test_ciphersuites!(mode: $name, Poprf);
	};
	($name:ident, Mode) => {
		$crate::test_ciphersuites!($name, Oprf);
		$crate::test_ciphersuites!($name, Voprf);
		$crate::test_ciphersuites!($name, Poprf);
	};
	(mode: $name:ident, $mode:ident) => {
		::paste::paste! {
			$crate::test_ciphersuites!(internal: [<$name _ $mode:lower>], $name, $mode);
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

			#[test]
			fn [<$prefixed_name _ristretto255>]() {
				$name::<$crate::oprf::group::ristretto255::Ristretto255>($(::oprf::common::Mode::$mode)?);
			}

			#[test]
			fn [<$prefixed_name _decaf448>]() {
				$name::<$crate::oprf::group::decaf448::Decaf448>($(::oprf::common::Mode::$mode)?);
			}
		}
	};
}

/// Default `input`.
pub const INPUT: &[&[u8]] = &[b"test input"];
/// Default `info`.
pub const INFO: &[u8] = b"test info";
