use core::fmt::{self, Debug, Formatter};

use hybrid_array::Array;
use hybrid_array::typenum::{Sum, Unsigned};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ciphersuite::{CipherSuite, ElementLength, NonIdentityElement, Scalar, ScalarLength};
use crate::error::{Error, Result};
use crate::group::{self, Group};

// https://www.rfc-editor.org/rfc/rfc9497.html#name-identifiers-for-protocol-va
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Mode {
	Oprf,
	Voprf,
	Poprf,
}

impl Mode {
	/// Returns I2OSP of [`Mode`].
	#[expect(
		clippy::as_conversions,
		reason = "no other way to convert numeric enums"
	)]
	pub(crate) const fn i2osp(self) -> &'static [u8; 1] {
		match self {
			Self::Oprf => &[Self::Oprf as u8],
			Self::Voprf => &[Self::Voprf as u8],
			Self::Poprf => &[Self::Poprf as u8],
		}
	}
}

pub struct BlindedElement<CS: CipherSuite>(pub(crate) NonIdentityElement<CS>);

pub struct EvaluationElement<CS: CipherSuite>(pub(crate) NonIdentityElement<CS>);

pub struct PreparedElement<CS: CipherSuite>(pub(crate) NonIdentityElement<CS>);

pub struct Proof<CS: CipherSuite> {
	pub(crate) c: Scalar<CS>,
	pub(crate) s: Scalar<CS>,
}

impl<CS: CipherSuite> BlindedElement<CS> {
	pub fn serialize(&self) -> Array<u8, ElementLength<CS>> {
		CS::Group::serialize_element(&self.0)
	}

	pub fn deserialize(bytes: &[u8]) -> Result<Self> {
		group::deserialize_non_identity_element::<CS::Group>(bytes).map(Self)
	}
}

impl<CS: CipherSuite> EvaluationElement<CS> {
	pub fn serialize(&self) -> Array<u8, ElementLength<CS>> {
		CS::Group::serialize_element(&self.0)
	}

	pub fn deserialize(bytes: &[u8]) -> Result<Self> {
		group::deserialize_non_identity_element::<CS::Group>(bytes).map(Self)
	}
}

impl<CS: CipherSuite> Proof<CS> {
	pub fn serialize(&self) -> Array<u8, Sum<ScalarLength<CS>, ScalarLength<CS>>> {
		CS::Group::serialize_scalar(&self.c).concat(CS::Group::serialize_scalar(&self.s))
	}

	pub fn deserialize(bytes: &[u8]) -> Result<Self> {
		let (c_bytes, s_bytes) = bytes
			.split_at_checked(ScalarLength::<CS>::USIZE)
			.ok_or(Error::Deserialize)?;
		let c = group::deserialize_scalar::<CS::Group>(c_bytes)?;
		let s = group::deserialize_scalar::<CS::Group>(s_bytes)?;

		Ok(Self { c, s })
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Clone for BlindedElement<CS> {
	fn clone(&self) -> Self {
		Self(self.0)
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for BlindedElement<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_tuple("BlindedElement").field(&self.0).finish()
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Drop for BlindedElement<CS> {
	fn drop(&mut self) {
		self.0.zeroize();
	}
}

impl<CS: CipherSuite> Eq for BlindedElement<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> PartialEq for BlindedElement<CS> {
	fn eq(&self, other: &Self) -> bool {
		self.0.eq(&other.0)
	}
}

impl<CS: CipherSuite> ZeroizeOnDrop for BlindedElement<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Clone for EvaluationElement<CS> {
	fn clone(&self) -> Self {
		Self(self.0)
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for EvaluationElement<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_tuple("EvaluationElement").field(&self.0).finish()
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Drop for EvaluationElement<CS> {
	fn drop(&mut self) {
		self.0.zeroize();
	}
}

impl<CS: CipherSuite> Eq for EvaluationElement<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> PartialEq for EvaluationElement<CS> {
	fn eq(&self, other: &Self) -> bool {
		self.0.eq(&other.0)
	}
}

impl<CS: CipherSuite> ZeroizeOnDrop for EvaluationElement<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Clone for PreparedElement<CS> {
	fn clone(&self) -> Self {
		Self(self.0)
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for PreparedElement<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_tuple("PreparedElement").field(&self.0).finish()
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Drop for PreparedElement<CS> {
	fn drop(&mut self) {
		self.0.zeroize();
	}
}

impl<CS: CipherSuite> Eq for PreparedElement<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> PartialEq for PreparedElement<CS> {
	fn eq(&self, other: &Self) -> bool {
		self.0.eq(&other.0)
	}
}

impl<CS: CipherSuite> ZeroizeOnDrop for PreparedElement<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Clone for Proof<CS> {
	fn clone(&self) -> Self {
		Self {
			c: self.c,
			s: self.s,
		}
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for Proof<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("Proof")
			.field("c", &self.c)
			.field("s", &self.s)
			.finish()
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Drop for Proof<CS> {
	fn drop(&mut self) {
		self.c.zeroize();
		self.s.zeroize();
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Eq for Proof<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> PartialEq for Proof<CS> {
	fn eq(&self, other: &Self) -> bool {
		self.c.eq(&other.c) && self.s.eq(&other.s)
	}
}

impl<CS: CipherSuite> ZeroizeOnDrop for Proof<CS> {}
