use core::ops::Deref;

use digest::{FixedOutput, Update};
use elliptic_curve::hash2curve::ExpandMsg;
use hybrid_array::typenum::{IsLess, True, U65536};

use crate::group::Group;

pub trait CipherSuite: 'static {
	const ID: Id;

	type Group: Group;
	type Hash: Default + FixedOutput<OutputSize: IsLess<U65536, Output = True>> + Update;
	type ExpandMsg: ExpandMsg<<Self::Group as Group>::K>;
}

type CsGroup<CS> = <CS as CipherSuite>::Group;
pub(crate) type NonZeroScalar<CS> = <CsGroup<CS> as Group>::NonZeroScalar;
pub(crate) type Scalar<CS> = <CsGroup<CS> as Group>::Scalar;
pub(crate) type ScalarLength<CS> = <CsGroup<CS> as Group>::ScalarLength;
pub(crate) type NonIdentityElement<CS> = <CsGroup<CS> as Group>::NonIdentityElement;
pub(crate) type Element<CS> = <CsGroup<CS> as Group>::Element;
pub(crate) type ElementLength<CS> = <CsGroup<CS> as Group>::ElementLength;

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
