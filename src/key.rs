use core::fmt::{self, Debug, Formatter};
use core::slice;

#[cfg(feature = "serde")]
use ::serde::de::Error as _;
#[cfg(feature = "serde")]
use ::serde::{Deserialize, Deserializer, Serialize, Serializer};
use hybrid_array::Array;
use rand_core::TryCryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ciphersuite::CipherSuite;
use crate::common::Mode;
use crate::error::{Error, Result};
use crate::group::{Group, InternalGroup};
#[cfg(feature = "serde")]
use crate::serde::{self, DeserializeWrapper, SerializeWrapper};
use crate::util::{Concat, I2ospLength};

pub struct KeyPair<G: Group> {
	secret_key: SecretKey<G>,
	public_key: PublicKey<G>,
}

impl<G: Group> KeyPair<G> {
	// `GenerateKeyPair`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.2-2
	pub fn generate<R: TryCryptoRng>(rng: &mut R) -> Result<Self, R::Error> {
		SecretKey::generate(rng).map(Self::from_secret_key)
	}

	// `DeriveKeyPair`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.2.1-2
	pub fn derive<CS: CipherSuite<Group = G>>(
		mode: Mode,
		seed: &[u8; 32],
		info: &[u8],
	) -> Result<Self> {
		SecretKey::derive::<CS>(mode, seed, info).map(Self::from_secret_key)
	}

	#[must_use]
	pub fn from_secret_key(secret_key: SecretKey<G>) -> Self {
		let public_key = PublicKey::from_secret_key(&secret_key);

		Self {
			secret_key,
			public_key,
		}
	}

	pub const fn secret_key(&self) -> &SecretKey<G> {
		&self.secret_key
	}

	pub const fn public_key(&self) -> &PublicKey<G> {
		&self.public_key
	}

	#[must_use]
	pub fn into_keys(self) -> (SecretKey<G>, PublicKey<G>) {
		(self.secret_key, self.public_key)
	}

	#[must_use]
	pub fn to_repr(&self) -> Array<u8, G::ScalarLength> {
		self.secret_key.to_repr()
	}

	pub fn from_repr(bytes: &[u8]) -> Result<Self> {
		SecretKey::from_repr(bytes).map(Self::from_secret_key)
	}
}

pub struct SecretKey<G: Group>(G::NonZeroScalar);

impl<G: Group> SecretKey<G> {
	// `GenerateKeyPair` without public key
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.2-2
	pub fn generate<R: TryCryptoRng>(rng: &mut R) -> Result<Self, R::Error> {
		G::scalar_random(rng).map(Self)
	}

	// `DeriveKeyPair` without public key
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.2.1-2
	pub fn derive<CS: CipherSuite<Group = G>>(
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
			let secret_key = CS::hash_to_scalar(
				mode,
				&derive_input.concat([slice::from_ref(&counter)]),
				Some(b"DeriveKeyPair"),
			);

			if let Ok(secret_key) = secret_key.try_into() {
				return Ok(Self(secret_key));
			}
		}

		Err(Error::DeriveKeyPair)
	}

	#[cfg(feature = "serde")]
	pub(crate) const fn from_scalar(scalar: G::NonZeroScalar) -> Self {
		Self(scalar)
	}

	pub const fn as_scalar(&self) -> &G::NonZeroScalar {
		&self.0
	}

	pub(crate) const fn to_scalar(&self) -> G::NonZeroScalar {
		self.0
	}

	#[must_use]
	pub fn into_scalar(self) -> G::NonZeroScalar {
		self.0
	}

	#[must_use]
	pub fn to_repr(&self) -> Array<u8, G::ScalarLength> {
		G::scalar_to_repr(&self.0)
	}

	pub fn from_repr(bytes: &[u8]) -> Result<Self> {
		bytes
			.try_into()
			.ok()
			.and_then(G::non_zero_scalar_from_repr)
			.ok_or(Error::FromRepr)
			.map(Self)
	}
}

pub struct PublicKey<G: Group> {
	element: G::NonIdentityElement,
	repr: Array<u8, G::ElementLength>,
}

impl<G: Group> PublicKey<G> {
	pub const fn as_point(&self) -> &G::NonIdentityElement {
		&self.element
	}

	#[must_use]
	pub fn into_point(self) -> G::NonIdentityElement {
		self.element
	}

	#[must_use]
	pub const fn as_repr(&self) -> &Array<u8, G::ElementLength> {
		&self.repr
	}

	pub(crate) fn from_point(element: G::NonIdentityElement) -> Self {
		let repr = G::element_to_repr(&element);

		Self { element, repr }
	}

	#[must_use]
	pub fn from_secret_key(secret_key: &SecretKey<G>) -> Self {
		Self::from_point(G::non_zero_scalar_mul_by_generator(&secret_key.0))
	}

	pub fn from_repr(bytes: &[u8]) -> Result<Self> {
		Self::from_array(bytes.try_into().map_err(|_| Error::FromRepr)?)
	}

	fn from_array(repr: Array<u8, G::ElementLength>) -> Result<Self> {
		let element = G::non_identity_element_from_repr(&repr).ok_or(Error::FromRepr)?;

		Ok(Self { element, repr })
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

#[cfg_attr(coverage_nightly, coverage(off))]
impl<G: Group> Clone for PublicKey<G> {
	fn clone(&self) -> Self {
		Self {
			element: self.element,
			repr: self.repr.clone(),
		}
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<G: Group> Debug for PublicKey<G> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PublicKey")
			.field("element", &self.element)
			.field("repr", &self.repr)
			.finish()
	}
}

#[cfg(feature = "serde")]
impl<'de, G> Deserialize<'de> for PublicKey<G>
where
	G: Group,
	G::NonIdentityElement: Deserialize<'de>,
{
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		let DeserializeWrapper::<G::ElementLength>(repr) =
			serde::newtype_struct(deserializer, "PublicKey")?;

		Self::from_array(repr).map_err(D::Error::custom)
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<G: Group> Drop for PublicKey<G> {
	fn drop(&mut self) {
		self.element.zeroize();
		self.repr.zeroize();
	}
}

impl<G: Group> Eq for PublicKey<G> {}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<G: Group> PartialEq for PublicKey<G> {
	fn eq(&self, other: &Self) -> bool {
		self.repr.eq(&other.repr)
	}
}

#[cfg(feature = "serde")]
impl<G> Serialize for PublicKey<G>
where
	G: Group,
	G::NonIdentityElement: Serialize,
{
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_newtype_struct("PublicKey", &SerializeWrapper(&self.repr))
	}
}

impl<G: Group> ZeroizeOnDrop for PublicKey<G> {}
