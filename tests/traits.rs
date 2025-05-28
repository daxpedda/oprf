//! Tests for traits on exported types.

#![cfg(test)]
#![expect(clippy::cargo_common_metadata, reason = "tests")]

use std::fmt::Debug;
use std::panic::{RefUnwindSafe, UnwindSafe};

use oprf::common::{BlindedElement, EvaluationElement, PreparedElement, Proof};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use paste::paste;
use static_assertions::assert_impl_all;

macro_rules! test_ciphersuite {
	($cs:ident, $prefix:ident) => {
		paste! {
			#[test]
			fn [<test $prefix>]() {
                assert_impl_all!(BlindedElement<$cs>: Clone, Debug, Eq, PartialEq, Send, Sync, Unpin, RefUnwindSafe, UnwindSafe);
                assert_impl_all!(EvaluationElement<$cs>: Clone, Debug, Eq, PartialEq, Send, Sync, Unpin, RefUnwindSafe, UnwindSafe);
                assert_impl_all!(PreparedElement<$cs>: Clone, Debug, Eq, PartialEq, Send, Sync, Unpin, RefUnwindSafe, UnwindSafe);
                assert_impl_all!(Proof<$cs>: Clone, Debug, Eq, PartialEq, Send, Sync, Unpin, RefUnwindSafe, UnwindSafe);
			}
		}
	};
}

test_ciphersuite!(NistP256, p256);
test_ciphersuite!(NistP384, p384);
test_ciphersuite!(NistP521, p521);
