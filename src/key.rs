use core::fmt::{self, Debug, Formatter};
use core::slice;

use hybrid_array::Array;
use rand_core::TryCryptoRng;

use crate::ciphersuite::CipherSuite;
use crate::common::Mode;
use crate::error::{Error, Result};
use crate::group::{Group, InternalGroup};
use crate::util::{Concat, I2ospLength};

pub struct KeyPair<G: Group> {
	secret_key: SecretKey<G>,
	public_key: PublicKey<G>,
}

impl<G: Group> KeyPair<G> {
	// `GenerateKeyPair`
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.2-2
	pub(crate) fn generate<R: TryCryptoRng>(rng: &mut R) -> Result<Self, R::Error> {
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

	pub fn from_secret_key(secret_key: SecretKey<G>) -> Self {
		let public_key = PublicKey(G::non_zero_scalar_mul_by_generator(secret_key.as_scalar()));

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

	pub const fn into_keys(self) -> (SecretKey<G>, PublicKey<G>) {
		(self.secret_key, self.public_key)
	}
}

pub struct SecretKey<G: Group>(G::NonZeroScalar);

impl<G: Group> SecretKey<G> {
	// `GenerateKeyPair` without public key
	// https://www.rfc-editor.org/rfc/rfc9497.html#section-3.2-2
	pub(crate) fn generate<R: TryCryptoRng>(rng: &mut R) -> Result<Self, R::Error> {
		G::random_scalar(rng).map(Self)
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

	pub const fn as_scalar(&self) -> &G::NonZeroScalar {
		&self.0
	}

	pub(crate) const fn to_scalar(&self) -> G::NonZeroScalar {
		self.0
	}

	pub const fn into_scalar(self) -> G::NonZeroScalar {
		self.0
	}

	pub fn serialize(&self) -> Array<u8, G::ScalarLength> {
		G::serialize_scalar(&self.0)
	}
}

pub struct PublicKey<G: Group>(G::NonIdentityElement);

impl<G: Group> PublicKey<G> {
	pub const fn as_point(&self) -> &G::NonIdentityElement {
		&self.0
	}

	pub(crate) const fn to_point(&self) -> G::NonIdentityElement {
		self.0
	}

	pub const fn into_point(self) -> G::NonIdentityElement {
		self.0
	}

	pub fn serialize(&self) -> Array<u8, G::ElementLength> {
		G::serialize_element(&self.0)
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

#[cfg_attr(coverage_nightly, coverage(off))]
impl<G: Group> Clone for PublicKey<G> {
	fn clone(&self) -> Self {
		Self(self.0)
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<G: Group> Debug for PublicKey<G> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_tuple("PublicKey").field(&self.0).finish()
	}
}
