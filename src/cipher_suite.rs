//! [`CipherSuite`] and other related types.

use core::ops::Deref;

use digest::{FixedOutput, Update};
use hash2curve::ExpandMsg;
use hybrid_array::typenum::{IsLess, True, U65536};

use crate::group::Group;

/// OPRF cipher suite. You can find default ciphersuites by enabling the
/// corresponding [crate features](crate#features).
///
/// See [RFC 9497 § 4](https://www.rfc-editor.org/rfc/rfc9497.html#name-ciphersuites).
///
/// # Examples
///
/// ```
/// # use digest::XofFixedWrapper;
/// # use hybrid_array::typenum::U64;
/// # use oprf::cipher_suite::{CipherSuite, Id};
/// # use oprf_test::{MockCurve as Ristretto255, MockHash as Shake256, MockExpandMsg as ExpandMsgXof};
/// #
/// struct CustomRistretto255;
///
/// impl CipherSuite for CustomRistretto255 {
/// 	const ID: Id = Id::new(b"ristretto255-SHAKE256").unwrap();
///
/// 	type Group = Ristretto255;
/// 	type Hash = XofFixedWrapper<Shake256, U64>;
/// 	type ExpandMsg = ExpandMsgXof<Shake256>;
/// }
/// ```
pub trait CipherSuite: 'static {
	/// The ID of this [`CipherSuite`].
	///
	/// See [RFC 9497 § 3.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.1-3).
	const ID: Id;

	/// The prime-order [`Group`] of this [`CipherSuite`].
	type Group: Group;

	/// The hash of this [`CipherSuite`].
	///
	/// See [RFC 9497 § 4](https://www.rfc-editor.org/rfc/rfc9497.html#section-4-3.4).
	type Hash: Default + FixedOutput<OutputSize: IsLess<U65536, Output = True>> + Update;

	/// The [`ExpandMsg`] to use with this [`Group`](CipherSuite::Group).
	type ExpandMsg: ExpandMsg<<Self::Group as Group>::SecurityLevel>;
}

/// Typedef to [`CipherSuite::Group`].
type CsGroup<Cs> = <Cs as CipherSuite>::Group;
/// Typedef to [`Group::NonZeroScalar`] via [`CipherSuite`].
pub(crate) type NonZeroScalar<Cs> = <CsGroup<Cs> as Group>::NonZeroScalar;
/// Typedef to [`Group::Scalar`] via [`CipherSuite`].
pub(crate) type Scalar<Cs> = <CsGroup<Cs> as Group>::Scalar;
/// Typedef to [`Group::ScalarLength`] via [`CipherSuite`].
pub(crate) type ScalarLength<Cs> = <CsGroup<Cs> as Group>::ScalarLength;
/// Typedef to [`Group::NonIdentityElement`] via [`CipherSuite`].
pub(crate) type NonIdentityElement<Cs> = <CsGroup<Cs> as Group>::NonIdentityElement;
/// Typedef to [`Group::Element`] via [`CipherSuite`].
pub(crate) type Element<Cs> = <CsGroup<Cs> as Group>::Element;
/// Typedef to [`Group::ElementLength`] via [`CipherSuite`].
pub(crate) type ElementLength<Cs> = <CsGroup<Cs> as Group>::ElementLength;

/// A valid [`CipherSuite::ID`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Id(&'static [u8]);

impl Id {
	/// Creates an [`Id`]. Returns [`None`] if `id` is longer than 65,521 bytes.
	#[must_use]
	pub const fn new(id: &'static [u8]) -> Option<Self> {
		#[expect(
			clippy::decimal_literal_representation,
			reason = "maximum valid size to not exceed `I2OSP` with 2 bytes; subtract parts added \
			          in `CreateContextString` and `ComputeComposites` from 2^16-1"
		)]
		if id.len() <= 65_521 {
			Some(Self(id))
		} else {
			None
		}
	}
}

impl Deref for Id {
	type Target = [u8];

	fn deref(&self) -> &Self::Target {
		self.0
	}
}

#[cfg(test)]
mod tests {
	use std::sync::LazyLock;
	use std::vec;
	use std::vec::Vec;

	use super::*;

	#[test]
	fn id_success() {
		static TEST: LazyLock<Vec<u8>> = LazyLock::new(|| vec![0; 0xFFF1]);

		let _ = Id::new(&TEST).unwrap();
	}

	#[test]
	fn id_failure() {
		static TEST: LazyLock<Vec<u8>> = LazyLock::new(|| vec![0; 0xFFF2]);

		assert_eq!(Id::new(&TEST), None);
	}
}
