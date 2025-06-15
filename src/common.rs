#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt::{self, Debug, Formatter};

#[cfg(feature = "serde")]
use ::serde::de::Error as _;
#[cfg(feature = "serde")]
use ::serde::ser::SerializeStruct;
#[cfg(feature = "serde")]
use ::serde::{Deserialize, Deserializer, Serialize, Serializer};
use hybrid_array::Array;
use hybrid_array::typenum::{Sum, Unsigned};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cipher_suite::{CipherSuite, ElementLength, NonIdentityElement, Scalar, ScalarLength};
use crate::error::{Error, Result};
use crate::group::Group;
#[cfg(feature = "serde")]
use crate::serde::{self, DeserializeWrapper, SerializeWrapper};
use crate::util::CollectArray;

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

pub struct BlindedElement<CS: CipherSuite> {
	element: NonIdentityElement<CS>,
	repr: Array<u8, ElementLength<CS>>,
}

pub struct EvaluationElement<CS: CipherSuite> {
	element: NonIdentityElement<CS>,
	repr: Array<u8, ElementLength<CS>>,
}

pub struct Proof<CS: CipherSuite> {
	pub(crate) c: Scalar<CS>,
	pub(crate) s: Scalar<CS>,
}

impl<CS: CipherSuite> BlindedElement<CS> {
	pub(crate) fn new(element: NonIdentityElement<CS>) -> Self {
		Self {
			element,
			repr: CS::Group::element_to_repr(&element),
		}
	}

	pub(crate) const fn element(&self) -> &NonIdentityElement<CS> {
		&self.element
	}

	pub const fn as_repr(&self) -> &Array<u8, ElementLength<CS>> {
		&self.repr
	}

	pub fn from_repr(bytes: &[u8]) -> Result<Self> {
		Self::from_array(bytes.try_into().map_err(|_| Error::FromRepr)?)
	}

	pub(crate) fn from_array(repr: Array<u8, ElementLength<CS>>) -> Result<Self> {
		let element = CS::Group::non_identity_element_from_repr(&repr).ok_or(Error::FromRepr)?;

		Ok(Self { element, repr })
	}
}

impl<CS: CipherSuite> EvaluationElement<CS> {
	#[cfg(feature = "alloc")]
	pub(crate) fn new_batch(elements: impl Iterator<Item = NonIdentityElement<CS>>) -> Vec<Self> {
		let elements: Vec<_> = elements.collect();
		let repr = CS::Group::non_identity_element_batch_to_repr(&elements);

		elements
			.into_iter()
			.zip(repr)
			.map(|(element, repr)| Self { element, repr })
			.collect()
	}

	pub(crate) fn new_batch_fixed<const N: usize>(
		elements: &[NonIdentityElement<CS>; N],
	) -> [Self; N] {
		let repr = CS::Group::non_identity_element_batch_to_repr_fixed(elements);

		elements
			.iter()
			.copied()
			.zip(repr)
			.map(|(element, repr)| Self { element, repr })
			.collect_array()
	}

	pub(crate) const fn element(&self) -> &NonIdentityElement<CS> {
		&self.element
	}

	pub const fn as_repr(&self) -> &Array<u8, ElementLength<CS>> {
		&self.repr
	}

	pub fn from_repr(bytes: &[u8]) -> Result<Self> {
		Self::from_array(bytes.try_into().map_err(|_| Error::FromRepr)?)
	}

	pub(crate) fn from_array(repr: Array<u8, ElementLength<CS>>) -> Result<Self> {
		let element = CS::Group::non_identity_element_from_repr(&repr).ok_or(Error::FromRepr)?;

		Ok(Self { element, repr })
	}
}

impl<CS: CipherSuite> Proof<CS> {
	#[must_use]
	pub fn to_repr(&self) -> Array<u8, Sum<ScalarLength<CS>, ScalarLength<CS>>> {
		CS::Group::scalar_to_repr(&self.c).concat(CS::Group::scalar_to_repr(&self.s))
	}

	pub fn from_repr(bytes: &[u8]) -> Result<Self> {
		fn scalar_from_repr<G: Group>(bytes: &[u8]) -> Result<G::Scalar> {
			bytes
				.try_into()
				.ok()
				.and_then(G::scalar_from_repr)
				.ok_or(Error::FromRepr)
		}

		let (c_bytes, s_bytes) = bytes
			.split_at_checked(ScalarLength::<CS>::USIZE)
			.ok_or(Error::FromRepr)?;
		let c = scalar_from_repr::<CS::Group>(c_bytes)?;
		let s = scalar_from_repr::<CS::Group>(s_bytes)?;

		Ok(Self { c, s })
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Clone for BlindedElement<CS> {
	fn clone(&self) -> Self {
		Self {
			element: self.element,
			repr: self.repr.clone(),
		}
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for BlindedElement<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("BlindedElement")
			.field("element", &self.element)
			.field("repr", &self.repr)
			.finish()
	}
}

#[cfg(feature = "serde")]
impl<'de, CS: CipherSuite> Deserialize<'de> for BlindedElement<CS> {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		let DeserializeWrapper::<ElementLength<CS>>(repr) =
			serde::newtype_struct(deserializer, "BlindedElement")?;

		Self::from_array(repr).map_err(D::Error::custom)
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Drop for BlindedElement<CS> {
	fn drop(&mut self) {
		self.element.zeroize();
		self.repr.zeroize();
	}
}

impl<CS: CipherSuite> Eq for BlindedElement<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> PartialEq for BlindedElement<CS> {
	fn eq(&self, other: &Self) -> bool {
		self.repr.eq(&other.repr)
	}
}

#[cfg(feature = "serde")]
impl<CS: CipherSuite> Serialize for BlindedElement<CS> {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_newtype_struct("BlindedElement", &SerializeWrapper(&self.repr))
	}
}

impl<CS: CipherSuite> ZeroizeOnDrop for BlindedElement<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Clone for EvaluationElement<CS> {
	fn clone(&self) -> Self {
		Self {
			element: self.element,
			repr: self.repr.clone(),
		}
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for EvaluationElement<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("EvaluationElement")
			.field("element", &self.element)
			.field("repr", &self.repr)
			.finish()
	}
}

#[cfg(feature = "serde")]
impl<'de, CS: CipherSuite> Deserialize<'de> for EvaluationElement<CS> {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		let DeserializeWrapper::<ElementLength<CS>>(repr) =
			serde::newtype_struct(deserializer, "EvaluationElement")?;

		Self::from_array(repr).map_err(D::Error::custom)
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Drop for EvaluationElement<CS> {
	fn drop(&mut self) {
		self.element.zeroize();
		self.repr.zeroize();
	}
}

impl<CS: CipherSuite> Eq for EvaluationElement<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> PartialEq for EvaluationElement<CS> {
	fn eq(&self, other: &Self) -> bool {
		self.repr.eq(&other.repr)
	}
}

#[cfg(feature = "serde")]
impl<CS: CipherSuite> Serialize for EvaluationElement<CS> {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_newtype_struct("EvaluationElement", &SerializeWrapper(&self.repr))
	}
}

impl<CS: CipherSuite> ZeroizeOnDrop for EvaluationElement<CS> {}

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

#[cfg(feature = "serde")]
impl<'de, CS> Deserialize<'de> for Proof<CS>
where
	CS: CipherSuite,
	Scalar<CS>: Deserialize<'de>,
{
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		serde::struct_2(deserializer, "Proof", &["c", "s"]).map(|(c, s)| Self { c, s })
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

#[cfg(feature = "serde")]
impl<CS> Serialize for Proof<CS>
where
	CS: CipherSuite,
	Scalar<CS>: Serialize,
{
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let mut state = serializer.serialize_struct("Proof", 2)?;
		state.serialize_field("c", &self.c)?;
		state.serialize_field("s", &self.s)?;
		state.end()
	}
}

impl<CS: CipherSuite> ZeroizeOnDrop for Proof<CS> {}
