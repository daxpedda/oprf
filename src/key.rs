//! [`KeyPair`] and corresponding types.

use core::fmt::{self, Debug, Formatter};
use core::slice;

#[cfg(feature = "serde")]
use ::serde::{Deserialize, Deserializer, Serialize, Serializer};
use hybrid_array::Array;
use rand_core::TryCryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cipher_suite::CipherSuite;
use crate::common::Mode;
use crate::error::{Error, Result};
use crate::group::{CipherSuiteExt, Group};
use crate::internal::ElementWrapper;
#[cfg(feature = "serde")]
use crate::serde;
use crate::util::{Concat, I2ospLength};

/// Holds a [`SecretKey`] and its [`PublicKey`].
pub struct KeyPair<G: Group> {
	/// [`SecretKey`].
	secret_key: SecretKey<G>,
	/// [`PublicKey`].
	public_key: PublicKey<G>,
}

impl<G: Group> KeyPair<G> {
	/// Generates a random [`SecretKey`] and its [`PublicKey`].
	///
	/// Corresponds to
	/// [`GenerateKeyPair()` in RFC 9497 § 3.2](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.2-2).
	///
	/// # Errors
	///
	/// Returns [`TryRngCore::Error`](rand_core::TryRngCore::Error) if the given
	/// `rng` fails.
	pub fn generate<R>(rng: &mut R) -> Result<Self, R::Error>
	where
		R: ?Sized + TryCryptoRng,
	{
		SecretKey::generate(rng).map(Self::from_secret_key)
	}

	/// Deterministically maps the input to a [`SecretKey`] and its
	/// [`PublicKey`].
	///
	/// Corresponds to
	/// [`DeriveKeyPair()` in RFC 9497 § 3.2.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.2.1-2).
	///
	/// # Errors
	///
	/// - [`Error::InfoLength`] if `info` exceeds a length of [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::DeriveKeyPair`] if a [`SecretKey`] can never be derived from
	///   the given input.
	pub fn derive<Cs: CipherSuite<Group = G>>(
		mode: Mode,
		seed: &[u8; 32],
		info: &[u8],
	) -> Result<Self> {
		SecretKey::derive::<Cs>(mode, seed, info).map(Self::from_secret_key)
	}

	/// Returns a [`KeyPair`] with the given [`SecretKey`] and deriving its
	/// [`PublicKey`].
	#[must_use]
	pub fn from_secret_key(secret_key: SecretKey<G>) -> Self {
		let public_key = PublicKey::from_secret_key(&secret_key);

		Self {
			secret_key,
			public_key,
		}
	}

	/// Deserializes the given `repr` to a [`SecretKey`], deriving its
	/// [`PublicKey`] and creating a [`KeyPair`].
	///
	/// # Errors
	///
	/// Returns [`Error::FromRepr`] if deserialization fails.
	pub fn from_repr(repr: &[u8]) -> Result<Self> {
		SecretKey::from_repr(repr).map(Self::from_secret_key)
	}

	/// Returns the [`SecretKey`].
	#[must_use]
	pub const fn secret_key(&self) -> &SecretKey<G> {
		&self.secret_key
	}

	/// Returns the [`PublicKey`].
	#[must_use]
	pub const fn public_key(&self) -> &PublicKey<G> {
		&self.public_key
	}

	/// Returns the [`SecretKey`] and its [`PublicKey`].
	#[must_use]
	pub fn into_keys(self) -> (SecretKey<G>, PublicKey<G>) {
		(self.secret_key, self.public_key)
	}

	/// Serializes this [`KeyPair`] as a [`SecretKey`].
	///
	/// # ⚠️ Warning
	///
	/// This value is key material.
	///
	/// Please treat it with the care it deserves!
	#[must_use]
	pub fn to_repr(&self) -> Array<u8, G::ScalarLength> {
		self.secret_key.to_repr()
	}
}

/// A secret key.
pub struct SecretKey<G: Group>(G::NonZeroScalar);

impl<G: Group> SecretKey<G> {
	/// Creates a new [`SecretKey`].
	pub const fn new(scalar: G::NonZeroScalar) -> Self {
		Self(scalar)
	}

	/// Generates a random [`SecretKey`].
	///
	/// Corresponds to
	/// [`GenerateKeyPair()` in RFC 9497 § 3.2](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.2-2).
	///
	/// # Errors
	///
	/// Returns [`TryRngCore::Error`](rand_core::TryRngCore::Error) if the given
	/// `rng` fails.
	pub fn generate<R>(rng: &mut R) -> Result<Self, R::Error>
	where
		R: ?Sized + TryCryptoRng,
	{
		G::scalar_random(rng).map(Self)
	}

	/// Deterministically maps the input to a [`SecretKey`].
	///
	/// Corresponds to
	/// [`DeriveKeyPair()` in RFC 9497 § 3.2.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-3.2.1-2).
	///
	/// # Errors
	///
	/// - [`Error::InfoLength`] if `info` exceeds a length of [`u16::MAX`].
	/// - [`Error::InvalidCipherSuite`] if the [`CipherSuite`]s
	///   [`Group`](CipherSuite::Group) and
	///   [`ExpandMsg`](CipherSuite::ExpandMsg) are incompatible.
	/// - [`Error::DeriveKeyPair`] if a [`SecretKey`] can never be derived from
	///   the given input.
	pub fn derive<Cs: CipherSuite<Group = G>>(
		mode: Mode,
		seed: &[u8; 32],
		info: &[u8],
	) -> Result<Self> {
		let derive_input = [
			seed.as_slice(),
			&info.i2osp_length().ok_or(Error::InfoLength)?,
			info,
		];

		for counter in 0..=u8::MAX {
			let secret_key = Cs::hash_to_scalar(
				mode,
				&derive_input.concat([slice::from_ref(&counter)]),
				Some(b"DeriveKeyPair"),
			)?;

			if let Ok(secret_key) = secret_key.try_into() {
				return Ok(Self(secret_key));
			}
		}

		Err(Error::DeriveKeyPair)
	}

	/// Deserializes the given `repr` to a [`SecretKey`].
	///
	/// # Errors
	///
	/// Returns [`Error::FromRepr`] if deserialization fails.
	pub fn from_repr(repr: &[u8]) -> Result<Self> {
		repr.try_into()
			.ok()
			.and_then(|repr| G::non_zero_scalar_from_repr(repr).ok())
			.ok_or(Error::FromRepr)
			.map(Self)
	}

	/// Returns the [`NonZeroScalar`](Group::NonZeroScalar).
	#[must_use]
	pub const fn as_scalar(&self) -> &G::NonZeroScalar {
		&self.0
	}

	/// Returns the [`NonZeroScalar`](Group::NonZeroScalar).
	pub(crate) const fn to_scalar(&self) -> G::NonZeroScalar {
		self.0
	}

	/// Returns the [`NonZeroScalar`](Group::NonZeroScalar).
	#[must_use]
	pub fn into_scalar(self) -> G::NonZeroScalar {
		self.0
	}

	/// Serializes this [`SecretKey`].
	///
	/// # ⚠️ Warning
	///
	/// This value is key material.
	///
	/// Please treat it with the care it deserves!
	#[must_use]
	pub fn to_repr(&self) -> Array<u8, G::ScalarLength> {
		G::scalar_to_repr(&self.0)
	}
}

/// A public key.
pub struct PublicKey<G: Group>(ElementWrapper<G>);

impl<G: Group> PublicKey<G> {
	/// Creates a [`PublicKey`].
	pub(crate) fn new(element: G::NonIdentityElement) -> Self {
		Self(ElementWrapper::new(element))
	}

	/// Derives the corresponding [`PublicKey`] from the given [`SecretKey`].
	#[must_use]
	pub fn from_secret_key(secret_key: &SecretKey<G>) -> Self {
		Self::new(G::non_zero_scalar_mul_by_generator(&secret_key.0))
	}

	/// Deserializes the given `repr` to a [`PublicKey`].
	///
	/// # Errors
	///
	/// Returns [`Error::FromRepr`] if deserialization fails.
	pub fn from_repr(repr: &[u8]) -> Result<Self> {
		ElementWrapper::from_repr(repr).map(Self)
	}

	/// Returns the [`NonIdentityElement`](Group::NonIdentityElement).
	#[must_use]
	pub const fn as_element(&self) -> &G::NonIdentityElement {
		self.0.as_element()
	}

	/// Returns the [`NonIdentityElement`](Group::NonIdentityElement).
	#[must_use]
	pub fn into_element(self) -> G::NonIdentityElement {
		self.0.into_element()
	}

	/// Returns the representation of this [`PublicKey`].
	#[must_use]
	pub const fn as_repr(&self) -> &Array<u8, G::ElementLength> {
		self.0.as_repr()
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<G: Group> Clone for KeyPair<G> {
	fn clone(&self) -> Self {
		Self {
			secret_key: self.secret_key.clone(),
			public_key: self.public_key.clone(),
		}
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<G: Group> Debug for KeyPair<G> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("KeyPair")
			.field("secret_key", &self.secret_key)
			.field("public_key", &self.public_key)
			.finish()
	}
}

#[cfg(feature = "serde")]
impl<'de, G> Deserialize<'de> for KeyPair<G>
where
	G: Group,
	G::NonZeroScalar: Deserialize<'de>,
{
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		serde::newtype_struct(deserializer, "KeyPair")
			.map(SecretKey)
			.map(Self::from_secret_key)
	}
}

impl<G: Group> Eq for KeyPair<G> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<G: Group> PartialEq for KeyPair<G> {
	fn eq(&self, other: &Self) -> bool {
		self.secret_key.eq(&other.secret_key)
	}
}

#[cfg(feature = "serde")]
impl<G> Serialize for KeyPair<G>
where
	G: Group,
	G::NonZeroScalar: Serialize,
{
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_newtype_struct("KeyPair", &self.secret_key.0)
	}
}

impl<G: Group> ZeroizeOnDrop for KeyPair<G> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<G: Group> Clone for SecretKey<G> {
	fn clone(&self) -> Self {
		Self(self.0)
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<G: Group> Debug for SecretKey<G> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_tuple("SecretKey").field(&self.0).finish()
	}
}

#[cfg(feature = "serde")]
impl<'de, G> Deserialize<'de> for SecretKey<G>
where
	G: Group,
	G::NonZeroScalar: Deserialize<'de>,
{
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		serde::newtype_struct(deserializer, "SecretKey").map(Self)
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<G: Group> Drop for SecretKey<G> {
	fn drop(&mut self) {
		self.0.zeroize();
	}
}

impl<G: Group> Eq for SecretKey<G> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<G: Group> PartialEq for SecretKey<G> {
	fn eq(&self, other: &Self) -> bool {
		self.0.eq(&other.0)
	}
}

#[cfg(feature = "serde")]
impl<G> Serialize for SecretKey<G>
where
	G: Group,
	G::NonZeroScalar: Serialize,
{
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_newtype_struct("SecretKey", &self.0)
	}
}

impl<G: Group> ZeroizeOnDrop for SecretKey<G> {}

impl<G: Group> AsRef<ElementWrapper<G>> for PublicKey<G> {
	fn as_ref(&self) -> &ElementWrapper<G> {
		&self.0
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<G: Group> Clone for PublicKey<G> {
	fn clone(&self) -> Self {
		Self(self.0.clone())
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<G: Group> Debug for PublicKey<G> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_tuple("PublicKey").field(&self.0).finish()
	}
}

#[cfg(feature = "serde")]
impl<'de, G: Group> Deserialize<'de> for PublicKey<G> {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		serde::newtype_struct(deserializer, "PublicKey").map(Self)
	}
}

impl<G: Group> Eq for PublicKey<G> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<G: Group> PartialEq for PublicKey<G> {
	fn eq(&self, other: &Self) -> bool {
		self.0.eq(&other.0)
	}
}

#[cfg(feature = "serde")]
impl<G: Group> Serialize for PublicKey<G> {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_newtype_struct("PublicKey", &self.0)
	}
}

impl<G: Group> ZeroizeOnDrop for PublicKey<G> {}
