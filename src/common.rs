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
pub struct BlindedElement<Cs: CipherSuite>(ElementWrapper<Cs::Group>);

/// Returned by [`*Server::blind_evaluate()`]. Sent to the client to be
/// [`*Client::finalize()`]d.
///
/// [`*Server::blind_evaluate()`]: crate::oprf::OprfServer::blind_evaluate
/// [`*Client::finalize()`]: crate::oprf::OprfClient::finalize
#[repr(transparent)]
pub struct EvaluationElement<Cs: CipherSuite>(ElementWrapper<Cs::Group>);

/// Returned by [`*Server::blind_evaluate()`]. Sent to the client to be verified
/// by [`*Client::finalize()`].
///
/// [`*Server::blind_evaluate()`]: crate::voprf::VoprfServer::blind_evaluate
/// [`*Client::finalize()`]: crate::voprf::VoprfClient::finalize
pub struct Proof<Cs: CipherSuite> {
	/// `c`.
	pub(crate) c: Scalar<Cs>,
	/// `s`.
	pub(crate) s: Scalar<Cs>,
}

/// Returned by [`*Server::blind_evaluate()`]. Contains the
/// [`EvaluationElement`] and [`Proof`].
///
/// [`*Server::blind_evaluate()`]: crate::voprf::VoprfServer::blind_evaluate
pub struct BlindEvaluateResult<Cs: CipherSuite> {
	/// The [`EvaluationElement`].
	pub evaluation_element: EvaluationElement<Cs>,
	/// The [`Proof`].
	pub proof: Proof<Cs>,
}

/// Returned by [`*Server::batch_blind_evaluate()`]. Contains the
/// [`EvaluationElement`]s and [`Proof`].
///
/// [`*Server::batch_blind_evaluate()`]: crate::voprf::VoprfServer::batch_blind_evaluate
pub struct BatchBlindEvaluateResult<Cs: CipherSuite, const N: usize> {
	/// The [`EvaluationElement`]s.
	pub evaluation_elements: [EvaluationElement<Cs>; N],
	/// The [`Proof`].
	pub proof: Proof<Cs>,
}

/// Returned by [`*Server::batch_alloc_blind_evaluate()`]. Contains the
/// [`EvaluationElement`]s and [`Proof`].
///
/// [`*Server::batch_alloc_blind_evaluate()`]: crate::voprf::VoprfServer::batch_alloc_blind_evaluate
#[cfg(feature = "alloc")]
pub struct BatchAllocBlindEvaluateResult<Cs: CipherSuite> {
	/// The [`EvaluationElement`]s.
	pub evaluation_elements: Vec<EvaluationElement<Cs>>,
	/// The [`Proof`].
	pub proof: Proof<Cs>,
}

impl<Cs: CipherSuite> BlindedElement<Cs> {
	/// Creates a fixed-sized array of [`BlindedElement`]s.
	pub(crate) fn new_batch<const N: usize>(
		elements_and_scalars: impl Iterator<Item = (NonIdentityElement<Cs>, NonZeroScalar<Cs>)>,
	) -> [Self; N] {
		ElementWrapper::new_batch(elements_and_scalars).map(Self)
	}

	/// Creates a [`Vec`] of [`BlindedElement`]s.
	#[cfg(feature = "alloc")]
	pub(crate) fn new_batch_alloc(
		elements_and_scalars: impl ExactSizeIterator<Item = (NonIdentityElement<Cs>, NonZeroScalar<Cs>)>,
	) -> Vec<Self> {
		ElementWrapper::new_batch_alloc(elements_and_scalars)
			.into_iter()
			.map(Self)
			.collect()
	}

	/// Deserializes the given `repr` to a [`BlindedElement`].
	///
	/// # Errors
	///
	/// Returns [`Error::FromRepr`] if deserialization fails.
	pub fn from_repr(repr: &[u8]) -> Result<Self> {
		ElementWrapper::from_repr(repr).map(Self)
	}

	/// Returns the [`NonIdentityElement`].
	pub(crate) const fn as_element(&self) -> &NonIdentityElement<Cs> {
		self.0.as_element()
	}

	/// Returns the representation of this [`BlindedElement`].
	#[must_use]
	pub const fn as_repr(&self) -> &Array<u8, ElementLength<Cs>> {
		self.0.as_repr()
	}
}

impl<Cs: CipherSuite> EvaluationElement<Cs> {
	/// Creates a fixed-sized array of [`EvaluationElement`]s.
	pub(crate) fn new_batch<const N: usize>(
		elements_and_scalars: impl Iterator<Item = (NonIdentityElement<Cs>, NonZeroScalar<Cs>)>,
	) -> [Self; N] {
		ElementWrapper::new_batch(elements_and_scalars).map(Self)
	}

	/// Creates a [`Vec`] of [`EvaluationElement`]s.
	#[cfg(feature = "alloc")]
	pub(crate) fn new_batch_alloc(
		elements_and_scalars: impl ExactSizeIterator<Item = (NonIdentityElement<Cs>, NonZeroScalar<Cs>)>,
	) -> Vec<Self> {
		ElementWrapper::new_batch_alloc(elements_and_scalars)
			.into_iter()
			.map(Self)
			.collect()
	}

	/// Deserializes the given `repr` to a [`EvaluationElement`].
	///
	/// # Errors
	///
	/// Returns [`Error::FromRepr`] if deserialization fails.
	pub fn from_repr(repr: &[u8]) -> Result<Self> {
		ElementWrapper::from_repr(repr).map(Self)
	}

	/// Returns the [`NonIdentityElement`].
	pub(crate) const fn as_element(&self) -> &NonIdentityElement<Cs> {
		self.0.as_element()
	}

	/// Returns the representation of this [`EvaluationElement`].
	#[must_use]
	pub const fn as_repr(&self) -> &Array<u8, ElementLength<Cs>> {
		self.0.as_repr()
	}
}

impl<Cs: CipherSuite> Proof<Cs> {
	/// Serializes this [`Proof`].
	#[must_use]
	pub fn to_repr(&self) -> Array<u8, Sum<ScalarLength<Cs>, ScalarLength<Cs>>> {
		Cs::Group::scalar_to_repr(&self.c).concat(Cs::Group::scalar_to_repr(&self.s))
	}

	/// Deserializes the given `repr` to a [`Proof`].
	///
	/// # Errors
	///
	/// Returns [`Error::FromRepr`] if deserialization fails.
	pub fn from_repr(repr: &[u8]) -> Result<Self> {
		fn scalar_from_repr<G: Group>(repr: &[u8]) -> Result<G::Scalar> {
			repr.try_into()
				.ok()
				.and_then(|repr| G::scalar_from_repr(repr).ok())
				.ok_or(Error::FromRepr)
		}

		let (c_repr, s_repr) = repr
			.split_at_checked(ScalarLength::<Cs>::USIZE)
			.ok_or(Error::FromRepr)?;
		let c = scalar_from_repr::<Cs::Group>(c_repr)?;
		let s = scalar_from_repr::<Cs::Group>(s_repr)?;

		Ok(Self { c, s })
	}
}

impl<Cs: CipherSuite> AsRef<ElementWrapper<Cs::Group>> for BlindedElement<Cs> {
	fn as_ref(&self) -> &ElementWrapper<Cs::Group> {
		&self.0
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Clone for BlindedElement<Cs> {
	fn clone(&self) -> Self {
		Self(self.0.clone())
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Debug for BlindedElement<Cs> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_tuple("BlindedElement").field(&self.0).finish()
	}
}

#[cfg(feature = "serde")]
impl<'de, Cs: CipherSuite> Deserialize<'de> for BlindedElement<Cs> {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		serde::newtype_struct(deserializer, "BlindedElement").map(Self)
	}
}

impl<Cs: CipherSuite> Eq for BlindedElement<Cs> {}

impl<Cs: CipherSuite> From<ElementWrapper<Cs::Group>> for BlindedElement<Cs> {
	fn from(value: ElementWrapper<Cs::Group>) -> Self {
		Self(value)
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> PartialEq for BlindedElement<Cs> {
	fn eq(&self, other: &Self) -> bool {
		self.0.eq(&other.0)
	}
}

#[cfg(feature = "serde")]
impl<Cs: CipherSuite> Serialize for BlindedElement<Cs> {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_newtype_struct("BlindedElement", &self.0)
	}
}

impl<Cs: CipherSuite> ZeroizeOnDrop for BlindedElement<Cs> {}

impl<Cs: CipherSuite> AsRef<ElementWrapper<Cs::Group>> for EvaluationElement<Cs> {
	fn as_ref(&self) -> &ElementWrapper<Cs::Group> {
		&self.0
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Clone for EvaluationElement<Cs> {
	fn clone(&self) -> Self {
		Self(self.0.clone())
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Debug for EvaluationElement<Cs> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_tuple("EvaluationElement").field(&self.0).finish()
	}
}

#[cfg(feature = "serde")]
impl<'de, Cs: CipherSuite> Deserialize<'de> for EvaluationElement<Cs> {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		serde::newtype_struct(deserializer, "EvaluationElement").map(Self)
	}
}

impl<Cs: CipherSuite> Eq for EvaluationElement<Cs> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> PartialEq for EvaluationElement<Cs> {
	fn eq(&self, other: &Self) -> bool {
		self.0.eq(&other.0)
	}
}

#[cfg(feature = "serde")]
impl<Cs: CipherSuite> Serialize for EvaluationElement<Cs> {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_newtype_struct("EvaluationElement", &self.0)
	}
}

impl<Cs: CipherSuite> ZeroizeOnDrop for EvaluationElement<Cs> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Clone for Proof<Cs> {
	fn clone(&self) -> Self {
		Self {
			c: self.c,
			s: self.s,
		}
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Debug for Proof<Cs> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("Proof")
			.field("c", &self.c)
			.field("s", &self.s)
			.finish()
	}
}

#[cfg(feature = "serde")]
impl<'de, Cs> Deserialize<'de> for Proof<Cs>
where
	Cs: CipherSuite,
	Scalar<Cs>: Deserialize<'de>,
{
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		serde::struct_2(deserializer, "Proof", &["c", "s"]).map(|(c, s)| Self { c, s })
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Drop for Proof<Cs> {
	fn drop(&mut self) {
		self.c.zeroize();
		self.s.zeroize();
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Eq for Proof<Cs> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> PartialEq for Proof<Cs> {
	fn eq(&self, other: &Self) -> bool {
		self.c.eq(&other.c) && self.s.eq(&other.s)
	}
}

#[cfg(feature = "serde")]
impl<Cs> Serialize for Proof<Cs>
where
	Cs: CipherSuite,
	Scalar<Cs>: Serialize,
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

impl<Cs: CipherSuite> ZeroizeOnDrop for Proof<Cs> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Debug for BlindEvaluateResult<Cs> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("BlindEvaluateResult")
			.field("evaluation_element", &self.evaluation_element)
			.field("proof", &self.proof)
			.finish()
	}
}

impl<Cs: CipherSuite> ZeroizeOnDrop for BlindEvaluateResult<Cs> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite, const N: usize> Debug for BatchBlindEvaluateResult<Cs, N> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("BatchBlindEvaluateResult")
			.field("evaluation_elements", &self.evaluation_elements)
			.field("proof", &self.proof)
			.finish()
	}
}

impl<Cs: CipherSuite, const N: usize> ZeroizeOnDrop for BatchBlindEvaluateResult<Cs, N> {}

#[cfg(feature = "alloc")]
#[cfg_attr(coverage_nightly, coverage(off))]
impl<Cs: CipherSuite> Debug for BatchAllocBlindEvaluateResult<Cs> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("BatchAllocBlindEvaluateResult")
			.field("evaluation_elements", &self.evaluation_elements)
			.field("proof", &self.proof)
			.finish()
	}
}

#[cfg(feature = "alloc")]
impl<Cs: CipherSuite> ZeroizeOnDrop for BatchAllocBlindEvaluateResult<Cs> {}
