//! Test utilities.

#![cfg_attr(coverage_nightly, feature(coverage_attribute), coverage(off))]
#![expect(
	clippy::cargo_common_metadata,
	clippy::indexing_slicing,
	clippy::unwrap_used,
	reason = "tests"
)]

mod bench;
pub mod cipher_suite;
pub mod common;
pub mod edwards25519;
mod edwards448;
mod k256;
mod rng;
#[cfg(feature = "serde")]
mod serde;
mod serialized;
mod util;

pub use {oprf, paste};

pub use self::bench::{Setup, bench};
pub use self::cipher_suite::{MockCs, MockCurve, MockExpandMsg, MockHash};
pub use self::common::{CommonClient, CommonServer};
pub use self::edwards448::Edwards448;
pub use self::edwards25519::Edwards25519;
pub use self::k256::Secp256k1;
#[cfg(feature = "serde")]
pub use self::serde::{ScalarRepr, TypeRepr};
pub use self::serialized::*;

/// Generates `#[test]` functions pre-fixed with the provided `name` for all
/// available [`CipherSuite`](oprf::CipherSuite)s and passes the appropriate
/// [`Mode`](oprf::common::Mode).
#[macro_export]
macro_rules! test_ciphersuites {
	($name:ident) => {
		$crate::test_ciphersuites!(internal: $name);
	};
	($name:ident, Oprf $(, [$($cs:path as $cs_name:ident),+])?) => {
		$crate::test_ciphersuites!(mode: $name, Oprf $(, [$($cs as $cs_name),+])?);
	};
	($name:ident, Voprf $(, [$($cs:path as $cs_name:ident),+])?) => {
		$crate::test_ciphersuites!(mode: $name, Voprf $(, [$($cs as $cs_name),+])?);
	};
	($name:ident, Poprf $(, [$($cs:path as $cs_name:ident),+])?) => {
		$crate::test_ciphersuites!(mode: $name, Poprf $(, [$($cs as $cs_name),+])?);
	};
	($name:ident, Mode $(, [$($cs:path as $cs_name:ident),+])?) => {
		$crate::test_ciphersuites!($name, Oprf $(, [$($cs as $cs_name),+])?);
		$crate::test_ciphersuites!($name, Voprf $(, [$($cs as $cs_name),+])?);
		$crate::test_ciphersuites!($name, Poprf $(, [$($cs as $cs_name),+])?);
	};
	(mode: $name:ident, $mode:ident) => {
		$crate::test_ciphersuites!(internal: $name, $mode);
	};
	(mode: $name:ident, $mode:ident, [$($cs:path as $cs_name:ident),+]) => {
		$crate::test_ciphersuites!(internal: $name, $mode, [$($cs as $cs_name),+]);
	};
	(internal: $name:ident $(, $mode:ident)?) => {
		$crate::test_ciphersuites!(
			internal: $name,
			$($mode,)?
			[
				$crate::Secp256k1 as k256,
				$crate::oprf::NistP256 as p256,
				$crate::oprf::NistP384 as p384,
				$crate::oprf::NistP521 as p521,
				$crate::Edwards25519 as edwards25519,
				$crate::oprf::Ristretto255 as ristretto255,
				$crate::Edwards448 as edwards448,
				$crate::oprf::Decaf448 as decaf448
			]
		);
	};
	(internal: $name:ident, [$($cs:path as $cs_name:ident),+]) => {
		$crate::paste::paste! { $(
			#[test]
			fn [<$name _ $cs_name>]() {
				$name::<$cs>();
			}
		)+ }
	};
	(internal: $name:ident, $mode:ident, [$($cs:path as $cs_name:ident),+]) => {
		$crate::paste::paste! { $(
			#[test]
			fn [<$name _ $mode:lower _ $cs_name>]() {
				$name::<$cs>(::oprf::common::Mode::$mode);
			}
		)+ }
	};
}

/// Default `input`.
pub const INPUT: &[&[u8]] = &[b"test input"];
/// Default `info`.
pub const INFO: &[u8] = b"test info";
