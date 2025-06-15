//! Test vector parsing.

use std::fs::File;
use std::sync::LazyLock;

use hex::FromHex;
use oprf::common::Mode;
use oprf_test::INFO;
use serde::de::Error;
use serde::{Deserialize, Deserializer};

use super::{KEY_INFO, SEED};

/// Parsed test vectors cache.
pub(super) static TEST_VECTORS: LazyLock<Vec<TestVector>> = LazyLock::new(|| {
	let raw_test_vectors: Vec<RawTestVector> =
		serde_json::from_reader(File::open("tests/test_vectors/vectors.json").unwrap()).unwrap();
	let mut test_vectors = Vec::new();

	for raw_test_vector in raw_test_vectors {
		test_vectors.push(TestVector::deserialize(raw_test_vector));
	}

	test_vectors
});

/// A single test vector.
pub(super) struct TestVector {
	/// Cipher suite ID.
	pub(super) identifier: String,
	/// The OPRF mode.
	pub(super) mode: Mode,
	/// The public key.
	pub(super) public_key: Option<Vec<u8>>,
	/// The secret key.
	pub(super) secret_key: Vec<u8>,
	/// Child test vectors.
	pub(super) vectors: Vec<Vector>,
}

/// Differentiate between basic and batched test vectors.
pub(super) enum Vector {
	Single(SingleVector),
	Batch(BatchVector),
}

/// A test vector using basic functionality, ergo not batched.
pub(super) struct SingleVector {
	pub(super) blind: Vec<u8>,
	pub(super) blinded_element: Vec<u8>,
	pub(super) evaluation_element: Vec<u8>,
	pub(super) input: Vec<u8>,
	pub(super) output: Vec<u8>,
	pub(super) proof: Option<Proof>,
}

/// A test vector using batched functionality.
pub(super) struct BatchVector {
	pub(super) blinds: [Vec<u8>; 2],
	pub(super) blinded_elements: [Vec<u8>; 2],
	pub(super) evaluation_elements: [Vec<u8>; 2],
	pub(super) inputs: [Vec<u8>; 2],
	pub(super) outputs: [Vec<u8>; 2],
	pub(super) proof: Option<Proof>,
}

/// A proof.
#[derive(Deserialize)]
pub(super) struct Proof {
	#[serde(with = "hex::serde")]
	pub(super) proof: Vec<u8>,
	#[serde(with = "hex::serde")]
	pub(super) r: Vec<u8>,
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
	/// De-serializes a [`RawTestVector`] into a [`TestVector`].
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
					vectors.push(Vector::Single(SingleVector {
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

/// Serde de-serialize implementation for deserializing batched test vectors.
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

/// Serde de-serialize implementation for deserializing an optional string
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
