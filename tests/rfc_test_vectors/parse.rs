//! Test vector parsing.
//!
//! Test vectors sourced from
//! <https://github.com/cfrg/draft-irtf-cfrg-voprf/blob/draft-irtf-cfrg-voprf-21/poc/vectors/allVectors.json>.

use std::fs::File;
use std::sync::LazyLock;

use hex::FromHex;
use oprf::common::Mode;
use oprf_test::INFO;
use serde::de::Error;
use serde::{Deserialize, Deserializer};

use super::{KEY_INFO, SEED};

/// Parsed test vectors cache.
pub static TEST_VECTORS: LazyLock<Vec<TestVector>> = LazyLock::new(|| {
	let raw_test_vectors: Vec<RawTestVector> =
		serde_json::from_reader(File::open("tests/rfc_test_vectors/vectors.json").unwrap())
			.unwrap();
	let mut test_vectors = Vec::new();

	for raw_test_vector in raw_test_vectors {
		test_vectors.push(TestVector::deserialize(raw_test_vector));
	}

	test_vectors
});

/// A single test vector.
pub struct TestVector {
	/// Cipher suite ID.
	pub identifier: String,
	/// OPRF mode.
	pub mode: Mode,
	/// Public key.
	pub public_key: Option<Vec<u8>>,
	/// Secret key.
	pub secret_key: Vec<u8>,
	/// Child test vectors.
	pub vectors: Vec<Vector>,
}

/// Differentiate between basic and batched test vectors.
pub enum Vector {
	Basic(BasicVector),
	Batch(BatchVector),
}

/// A test vector using basic functionality, ergo not batched.
pub struct BasicVector {
	pub blind: Vec<u8>,
	pub blinded_element: Vec<u8>,
	pub evaluation_element: Vec<u8>,
	pub input: Vec<u8>,
	pub output: Vec<u8>,
	pub proof: Option<Proof>,
}

/// A test vector using batched functionality.
pub struct BatchVector {
	pub blinds: [Vec<u8>; 2],
	pub blinded_elements: [Vec<u8>; 2],
	pub evaluation_elements: [Vec<u8>; 2],
	pub inputs: [Vec<u8>; 2],
	pub outputs: [Vec<u8>; 2],
	pub proof: Option<Proof>,
}

/// A proof.
#[derive(Deserialize)]
pub struct Proof {
	#[serde(with = "hex::serde", rename = "proof")]
	pub repr: Vec<u8>,
	#[serde(with = "hex::serde")]
	pub r: Vec<u8>,
}

/// A raw test vector, exactly represents the test vector file before being
/// further processed.
#[derive(Deserialize)]
struct RawTestVector {
	hash: String,
	identifier: String,
	#[serde(with = "hex::serde", rename = "keyInfo")]
	key_info: Vec<u8>,
	mode: u8,
	#[serde(default, deserialize_with = "deserialize_hex_opt", rename = "pkSm")]
	public_key: Option<Vec<u8>>,
	#[serde(with = "hex::serde")]
	seed: [u8; 32],
	#[serde(with = "hex::serde", rename = "skSm")]
	secret_key: Vec<u8>,
	vectors: Vec<RawVector>,
}

/// A raw child test vector, exactly represents the test vector file before
/// being further processed.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", tag = "Batch")]
struct RawVector {
	batch: u8,
	#[serde(deserialize_with = "deserialize_batch")]
	blind: Vec<Vec<u8>>,
	#[serde(deserialize_with = "deserialize_batch")]
	blinded_element: Vec<Vec<u8>>,
	#[serde(deserialize_with = "deserialize_batch")]
	evaluation_element: Vec<Vec<u8>>,
	#[serde(default, deserialize_with = "deserialize_hex_opt")]
	info: Option<Vec<u8>>,
	#[serde(deserialize_with = "deserialize_batch")]
	input: Vec<Vec<u8>>,
	#[serde(deserialize_with = "deserialize_batch")]
	output: Vec<Vec<u8>>,
	proof: Option<Proof>,
}

impl TestVector {
	/// Deserializes a [`RawTestVector`] into a [`TestVector`].
	fn deserialize(raw_test_vector: RawTestVector) -> Self {
		let RawTestVector {
			hash,
			identifier,
			key_info,
			mode,
			public_key,
			seed,
			secret_key,
			vectors: raw_vectors,
		} = raw_test_vector;

		match identifier.as_str() {
			"ristretto255-SHA512" | "P521-SHA512" => assert_eq!(hash, "SHA512"),
			"decaf448-SHAKE256" => assert_eq!(hash, "SHAKE_256"),
			"P256-SHA256" => assert_eq!(hash, "SHA256"),
			"P384-SHA384" => assert_eq!(hash, "SHA384"),
			identifier => panic!("found unrecognized identifier: \"{identifier}\""),
		}

		assert_eq!(seed, SEED);

		assert_eq!(key_info, KEY_INFO);

		let mode = match mode {
			0 => Mode::Oprf,
			1 => Mode::Voprf,
			2 => Mode::Poprf,
			value => panic!("found unrecognized mode: {value}"),
		};

		let mut vectors = Vec::new();

		for raw_vector in raw_vectors {
			let RawVector {
				batch,
				blind,
				blinded_element: blinded_elements,
				evaluation_element: evaluation_elements,
				info,
				input: inputs,
				output: outputs,
				proof,
			} = raw_vector;

			if let Mode::Poprf = mode {
				let info = info.expect("missing `info` for POPRF");
				assert_eq!(info.as_slice(), INFO);
			} else {
				assert_eq!(info, None);
			}

			match batch {
				1 => {
					vectors.push(Vector::Basic(BasicVector {
						blind: vec_to_single(blind).unwrap(),
						blinded_element: vec_to_single(blinded_elements).unwrap(),
						evaluation_element: vec_to_single(evaluation_elements).unwrap(),
						input: vec_to_single(inputs).unwrap(),
						output: vec_to_single(outputs).unwrap(),
						proof,
					}));
				}
				2 => {
					vectors.push(Vector::Batch(BatchVector {
						blinds: blind.try_into().unwrap(),
						blinded_elements: blinded_elements.try_into().unwrap(),
						evaluation_elements: evaluation_elements.try_into().unwrap(),
						inputs: inputs.try_into().unwrap(),
						outputs: outputs.try_into().unwrap(),
						proof,
					}));
				}
				size => panic!("found unsupported batch size: {size}"),
			}
		}

		Self {
			identifier,
			mode,
			public_key,
			secret_key,
			vectors,
		}
	}
}

/// Serde deserialize implementation for deserializing batched test vectors.
/// They are represented as multiple hexadecimal values in a string separated by
/// a comma.
fn deserialize_batch<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
	D: Deserializer<'de>,
{
	let mut batch = Vec::new();

	for value in String::deserialize(deserializer)?.split(',') {
		batch.push(FromHex::from_hex(value).map_err(Error::custom)?);
	}

	Ok(batch)
}

/// Serde deserialize implementation for deserializing an optional string
/// containing a hexadecimal value.
fn deserialize_hex_opt<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
	D: Deserializer<'de>,
{
	hex::serde::deserialize(deserializer).map(Some)
}

// Convenience function converting a `Vec<Vec<u8>>` into a single `Vec<u8>`.
fn vec_to_single(vec: Vec<Vec<u8>>) -> Option<Vec<u8>> {
	let [value] = vec.try_into().ok()?;
	Some(value)
}
