//! Test vector parsing.

#![cfg_attr(
	feature = "serde",
	expect(clippy::ref_option, reason = "proc-macro false-positive")
)]

use std::env;
use std::fs::File;
use std::sync::LazyLock;

use oprf::common::Mode;
use serde::Deserialize;
#[cfg(feature = "serde")]
use serde::Serialize;

/// Parsed test vectors cache.
pub static TEST_VECTORS: LazyLock<Vec<TestVector>> = LazyLock::new(|| {
	if matches!(env::var("BLESS").as_deref(), Ok("1")) {
		#[cfg(not(feature = "serde"))]
		panic!("use `BLESS` only with the `serde` crate feature");

		#[cfg(feature = "serde")]
		{
			use crate::generate;

			serde_json::to_writer_pretty(
				File::create("tests/test_vectors/vectors.json").unwrap(),
				&generate::generate(),
			)
			.unwrap();
		}
	}

	serde_json::from_reader(File::open("tests/test_vectors/vectors.json").unwrap()).unwrap()
});

/// A single test vector.
#[derive(Deserialize)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct TestVector {
	/// Cipher suite ID.
	pub identifier: String,
	/// OPRF mode.
	#[serde(with = "SerdeMode")]
	pub mode: Mode,
	/// Secret key seed.
	#[serde(with = "hex::serde")]
	pub seed: [u8; 32],
	/// Secret key info.
	#[serde(with = "hex::serde")]
	pub key_info: Vec<u8>,
	/// Secret key.
	#[serde(with = "hex::serde")]
	pub secret_key: Vec<u8>,
	/// JSON Secret key.
	#[cfg(feature = "serde")]
	pub secret_key_json: String,
	/// Public key.
	#[serde(with = "hex::serde")]
	pub public_key: Vec<u8>,
	/// JSON public key.
	#[cfg(feature = "serde")]
	pub public_key_json: String,
	/// JSON server.
	#[cfg(feature = "serde")]
	pub server_json: String,
	/// Info.
	#[serde(with = "HexOpt")]
	pub info: Option<Vec<u8>>,
	/// Proof.
	pub proof: Option<Proof>,
	/// Single or batched data.
	pub data: DataType,
}

/// A proof.
#[derive(Deserialize)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Proof {
	#[serde(with = "hex::serde")]
	pub repr: Vec<u8>,
	#[cfg(feature = "serde")]
	pub json: String,
	#[serde(with = "hex::serde")]
	pub r: Vec<u8>,
}

/// Differentiate between basic and batched.
#[derive(Deserialize)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[serde(untagged)]
pub enum DataType {
	Basic(Data),
	Batch([Data; 2]),
}

/// Separate type for data that needs batching.
#[derive(Deserialize)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Data {
	#[serde(with = "hex::serde")]
	pub input: Vec<u8>,
	#[cfg(feature = "serde")]
	pub client_json: String,
	#[serde(with = "hex::serde")]
	pub blind: Vec<u8>,
	#[serde(with = "hex::serde")]
	pub blinded_element: Vec<u8>,
	#[cfg(feature = "serde")]
	pub blinded_element_json: String,
	#[serde(with = "hex::serde")]
	pub evaluation_element: Vec<u8>,
	#[cfg(feature = "serde")]
	pub evaluation_element_json: String,
	#[serde(with = "hex::serde")]
	pub output: Vec<u8>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[serde(remote = "Option<Vec<u8>>")]
enum HexOpt {
	#[serde(with = "hex::serde")]
	Some(Vec<u8>),
	None,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[serde(remote = "Mode")]
enum SerdeMode {
	Oprf,
	Voprf,
	Poprf,
}
