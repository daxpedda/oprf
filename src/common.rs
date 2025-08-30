//! Common types between protocols.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt::{self, Debug, Formatter};

#[cfg(feature = "serde")]
use ::serde::ser::SerializeStruct;
#[cfg(feature = "serde")]
use ::serde::{Deserialize, Deserializer, Serialize, Serializer};
use hybrid_array::Array;
use hybrid_array::typenum::{Sum, Unsigned};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cipher_suite::{
	CipherSuite, ElementLength, NonIdentityElement, NonZeroScalar, Scalar, ScalarLength,
};
use crate::error::{Error, Result};
use crate::group::Group;
use crate::internal::ElementWrapper;
#[cfg(feature = "serde")]
use crate::serde;

/// Protocol mode. Only used in
/// [`SecretKey::derive()`](crate::key::SecretKey::derive).
///
/// See [RFC 9497 § 3.1](https://www.rfc-editor.org/rfc/rfc9497.html#name-identifiers-for-protocol-va).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Mode {
	/// OPRF.
	///
	/// See [RFC 9497 § 3.3.1](https://www.rfc-editor.org/rfc/rfc9497.html#name-oprf-protocol).
	Oprf,
	/// VOPRF.
	///
	/// See [RFC 9497 § 3.3.2](https://www.rfc-editor.org/rfc/rfc9497.html#name-voprf-protocol).
	Voprf,
	/// POPRF.
	///
	/// See [RFC 9497 § 3.3.3](https://www.rfc-editor.org/rfc/rfc9497.html#name-poprf-protocol).
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

/// Returned by [`*Client::blind()`]. Sent to the server to be
/// [`*Server::blind_evaluate()`]d.
///
/// [`*Client::blind()`]: crate::oprf::OprfClient::blind
/// [`*Server::blind_evaluate()`]: crate::oprf::OprfServer::blind_evaluate
#[repr(transparent)]
pub struct BlindedElement<CS: CipherSuite>(ElementWrapper<CS::Group>);

/// Returned by [`*Server::blind_evaluate()`]. Sent to the client to be
/// [`*Client::finalize()`]d.
///
/// [`*Server::blind_evaluate()`]: crate::oprf::OprfServer::blind_evaluate
/// [`*Client::finalize()`]: crate::oprf::OprfClient::finalize
#[repr(transparent)]
pub struct EvaluationElement<CS: CipherSuite>(ElementWrapper<CS::Group>);

/// Returned by [`*Server::blind_evaluate()`]. Sent to the client to be verified
/// by [`*Client::finalize()`].
///
/// [`*Server::blind_evaluate()`]: crate::voprf::VoprfServer::blind_evaluate
/// [`*Client::finalize()`]: crate::voprf::VoprfClient::finalize
pub struct Proof<CS: CipherSuite> {
	pub(crate) c: Scalar<CS>,
	pub(crate) s: Scalar<CS>,
}

/// Returned by [`*Server::blind_evaluate()`]. Contains the
/// [`EvaluationElement`] and [`Proof`].
///
/// [`*Server::blind_evaluate()`]: crate::voprf::VoprfServer::blind_evaluate
pub struct BlindEvaluateResult<CS: CipherSuite> {
	/// The [`EvaluationElement`].
	pub evaluation_element: EvaluationElement<CS>,
	/// The [`Proof`].
	pub proof: Proof<CS>,
}

/// Returned by [`*Server::batch_blind_evaluate()`]. Contains the
/// [`EvaluationElement`]s and [`Proof`].
///
/// [`*Server::batch_blind_evaluate()`]: crate::voprf::VoprfServer::batch_blind_evaluate
pub struct BatchBlindEvaluateResult<CS: CipherSuite, const N: usize> {
	/// The [`EvaluationElement`]s.
	pub evaluation_elements: [EvaluationElement<CS>; N],
	/// The [`Proof`].
	pub proof: Proof<CS>,
}

/// Returned by [`*Server::batch_alloc_blind_evaluate()`]. Contains the
/// [`EvaluationElement`]s and [`Proof`].
///
/// [`*Server::batch_alloc_blind_evaluate()`]: crate::voprf::VoprfServer::batch_alloc_blind_evaluate
#[cfg(feature = "alloc")]
pub struct BatchAllocBlindEvaluateResult<CS: CipherSuite> {
	/// The [`EvaluationElement`]s.
	pub evaluation_elements: Vec<EvaluationElement<CS>>,
	/// The [`Proof`].
	pub proof: Proof<CS>,
}

impl<CS: CipherSuite> BlindedElement<CS> {
	pub(crate) fn new_batch<const N: usize>(
		elements_and_scalars: impl Iterator<Item = (NonIdentityElement<CS>, NonZeroScalar<CS>)>,
	) -> [Self; N] {
		ElementWrapper::new_batch(elements_and_scalars).map(Self)
	}

	#[cfg(feature = "alloc")]
	pub(crate) fn new_batch_alloc(
		elements_and_scalars: impl ExactSizeIterator<Item = (NonIdentityElement<CS>, NonZeroScalar<CS>)>,
	) -> Vec<Self> {
		ElementWrapper::new_batch_alloc(elements_and_scalars)
			.into_iter()
			.map(Self)
			.collect()
	}

	pub(crate) const fn as_element(&self) -> &NonIdentityElement<CS> {
		self.0.as_element()
	}

	/// Serializes this [`BlindedElement`].
	#[must_use]
	pub const fn as_repr(&self) -> &Array<u8, ElementLength<CS>> {
		self.0.as_repr()
	}

	/// Deserializes the given `bytes` to a [`BlindedElement`].
	///
	/// # Errors
	///
	/// Returns [`Error::FromRepr`] if deserialization fails.
	pub fn from_repr(bytes: &[u8]) -> Result<Self> {
		ElementWrapper::from_repr(bytes).map(Self)
	}
}

impl<CS: CipherSuite> EvaluationElement<CS> {
	pub(crate) fn new_batch<const N: usize>(
		elements_and_scalars: impl Iterator<Item = (NonIdentityElement<CS>, NonZeroScalar<CS>)>,
	) -> [Self; N] {
		ElementWrapper::new_batch(elements_and_scalars).map(Self)
	}

	#[cfg(feature = "alloc")]
	pub(crate) fn new_batch_alloc(
		elements_and_scalars: impl ExactSizeIterator<Item = (NonIdentityElement<CS>, NonZeroScalar<CS>)>,
	) -> Vec<Self> {
		ElementWrapper::new_batch_alloc(elements_and_scalars)
			.into_iter()
			.map(Self)
			.collect()
	}

	pub(crate) const fn as_element(&self) -> &NonIdentityElement<CS> {
		self.0.as_element()
	}

	/// Serializes this [`EvaluationElement`].
	#[must_use]
	pub const fn as_repr(&self) -> &Array<u8, ElementLength<CS>> {
		self.0.as_repr()
	}

	/// Deserializes the given `bytes` to a [`EvaluationElement`].
	///
	/// # Errors
	///
	/// Returns [`Error::FromRepr`] if deserialization fails.
	pub fn from_repr(bytes: &[u8]) -> Result<Self> {
		ElementWrapper::from_repr(bytes).map(Self)
	}
}

impl<CS: CipherSuite> Proof<CS> {
	/// Serializes this [`Proof`].
	#[must_use]
	pub fn to_repr(&self) -> Array<u8, Sum<ScalarLength<CS>, ScalarLength<CS>>> {
		CS::Group::scalar_to_repr(&self.c).concat(CS::Group::scalar_to_repr(&self.s))
	}

	/// Deserializes the given `bytes` to a [`Proof`].
	///
	/// # Errors
	///
	/// Returns [`Error::FromRepr`] if deserialization fails.
	pub fn from_repr(bytes: &[u8]) -> Result<Self> {
		fn scalar_from_repr<G: Group>(bytes: &[u8]) -> Result<G::Scalar> {
			bytes
				.try_into()
				.ok()
				.and_then(|bytes| G::scalar_from_repr(bytes).ok())
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

impl<CS: CipherSuite> AsRef<ElementWrapper<CS::Group>> for BlindedElement<CS> {
	fn as_ref(&self) -> &ElementWrapper<CS::Group> {
		&self.0
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Clone for BlindedElement<CS> {
	fn clone(&self) -> Self {
		Self(self.0.clone())
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for BlindedElement<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_tuple("BlindedElement").field(&self.0).finish()
	}
}

#[cfg(feature = "serde")]
impl<'de, CS: CipherSuite> Deserialize<'de> for BlindedElement<CS> {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		serde::newtype_struct(deserializer, "BlindedElement").map(Self)
	}
}

impl<CS: CipherSuite> Eq for BlindedElement<CS> {}

impl<CS: CipherSuite> From<ElementWrapper<CS::Group>> for BlindedElement<CS> {
	fn from(value: ElementWrapper<CS::Group>) -> Self {
		Self(value)
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> PartialEq for BlindedElement<CS> {
	fn eq(&self, other: &Self) -> bool {
		self.0.eq(&other.0)
	}
}

#[cfg(feature = "serde")]
impl<CS: CipherSuite> Serialize for BlindedElement<CS> {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_newtype_struct("BlindedElement", &self.0)
	}
}

impl<CS: CipherSuite> ZeroizeOnDrop for BlindedElement<CS> {}

impl<CS: CipherSuite> AsRef<ElementWrapper<CS::Group>> for EvaluationElement<CS> {
	fn as_ref(&self) -> &ElementWrapper<CS::Group> {
		&self.0
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Clone for EvaluationElement<CS> {
	fn clone(&self) -> Self {
		Self(self.0.clone())
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for EvaluationElement<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_tuple("EvaluationElement").field(&self.0).finish()
	}
}

#[cfg(feature = "serde")]
impl<'de, CS: CipherSuite> Deserialize<'de> for EvaluationElement<CS> {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		serde::newtype_struct(deserializer, "EvaluationElement").map(Self)
	}
}

impl<CS: CipherSuite> Eq for EvaluationElement<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> PartialEq for EvaluationElement<CS> {
	fn eq(&self, other: &Self) -> bool {
		self.0.eq(&other.0)
	}
}

#[cfg(feature = "serde")]
impl<CS: CipherSuite> Serialize for EvaluationElement<CS> {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_newtype_struct("EvaluationElement", &self.0)
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

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for BlindEvaluateResult<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("BlindEvaluateResult")
			.field("evaluation_element", &self.evaluation_element)
			.field("proof", &self.proof)
			.finish()
	}
}

impl<CS: CipherSuite> ZeroizeOnDrop for BlindEvaluateResult<CS> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite, const N: usize> Debug for BatchBlindEvaluateResult<CS, N> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("BatchBlindEvaluateResult")
			.field("evaluation_elements", &self.evaluation_elements)
			.field("proof", &self.proof)
			.finish()
	}
}

impl<CS: CipherSuite, const N: usize> ZeroizeOnDrop for BatchBlindEvaluateResult<CS, N> {}

#[cfg(feature = "alloc")]
#[cfg_attr(coverage_nightly, coverage(off))]
impl<CS: CipherSuite> Debug for BatchAllocBlindEvaluateResult<CS> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("BatchAllocBlindEvaluateResult")
			.field("evaluation_elements", &self.evaluation_elements)
			.field("proof", &self.proof)
			.finish()
	}
}

#[cfg(feature = "alloc")]
impl<CS: CipherSuite> ZeroizeOnDrop for BatchAllocBlindEvaluateResult<CS> {}
