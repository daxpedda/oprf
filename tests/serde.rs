//! Tests for Serde implementations.

#![cfg(test)]
#![cfg(feature = "serde")]
#![expect(clippy::cargo_common_metadata, reason = "tests")]

mod util;

use std::fmt::Debug;

use hybrid_array::Array;
use oprf::ciphersuite::CipherSuite;
use oprf::common::{BlindedElement, EvaluationElement, Proof};
use oprf::group::Group;
use oprf::key::{KeyPair, PublicKey, SecretKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_test::de::Deserializer;
use serde_test::{Compact, Configure, Token};

test_ciphersuites!(common);

/// Test common types.
fn common<CS: CipherSuite>()
where
	BlindedElement<CS>: for<'de> Deserialize<'de> + Serialize,
	EvaluationElement<CS>: for<'de> Deserialize<'de> + Serialize,
	Proof<CS>: for<'de> Deserialize<'de> + Serialize,
	KeyPair<CS::Group>: for<'de> Deserialize<'de> + Serialize,
	SecretKey<CS::Group>: for<'de> Deserialize<'de> + Serialize,
	PublicKey<CS::Group>: for<'de> Deserialize<'de> + Serialize,
{
	let scalar1 = CS::Group::scalar_random(&mut OsRng).unwrap();
	let scalar_bytes1 = CS::Group::scalar_to_repr(&scalar1);
	let scalar_bytes1: &'static _ = Box::leak(Box::new(scalar_bytes1));

	let scalar2 = CS::Group::scalar_random(&mut OsRng).unwrap();
	let scalar_bytes2 = CS::Group::scalar_to_repr(&scalar2);
	let scalar_bytes2: &'static _ = Box::leak(Box::new(scalar_bytes2));

	let element = CS::Group::scalar_mul_by_generator(&scalar1);
	let element_bytes = CS::Group::element_to_repr(&element);
	let element_bytes: &'static _ = Box::leak(Box::new(element_bytes));

	let wrong_scalar_bytes = Array::<u8, <CS::Group as Group>::ScalarLength>::from_fn(|_| u8::MAX);
	let wrong_scalar_bytes: &'static _ = Box::leak(Box::new(wrong_scalar_bytes));

	let wrong_element_bytes = Array::<u8, <CS::Group as Group>::ElementLength>::default();
	let wrong_element_bytes: &'static _ = Box::leak(Box::new(wrong_element_bytes));

	let blinded_element = BlindedElement::from_repr(element_bytes).unwrap();
	newtype_struct(
		blinded_element,
		"BlindedElement",
		element_bytes,
		wrong_element_bytes,
	);

	let evaluation_element = EvaluationElement::from_repr(element_bytes).unwrap();
	newtype_struct(
		evaluation_element,
		"EvaluationElement",
		element_bytes,
		wrong_element_bytes,
	);

	let proof_bytes = scalar_bytes1.clone().concat(scalar_bytes2.clone());
	let proof = Proof::<CS>::from_repr(&proof_bytes).unwrap();
	struct_2(
		proof,
		"Proof",
		"c",
		scalar_bytes1,
		"s",
		scalar_bytes2,
		wrong_scalar_bytes,
	);

	let key_pair = KeyPair::<CS::Group>::from_repr(scalar_bytes1).unwrap();
	newtype_struct(key_pair, "KeyPair", scalar_bytes1, wrong_scalar_bytes);

	let secret_key = SecretKey::<CS::Group>::from_repr(scalar_bytes1).unwrap();
	newtype_struct(secret_key, "SecretKey", scalar_bytes1, wrong_scalar_bytes);

	let public_key = PublicKey::<CS::Group>::from_repr(element_bytes).unwrap();
	newtype_struct(public_key, "PublicKey", element_bytes, wrong_element_bytes);
}

/// Test a newtype struct.
fn newtype_struct<T: Clone + Debug + for<'de> Deserialize<'de> + PartialEq + Serialize>(
	value: T,
	name: &'static str,
	bytes: &'static [u8],
	wrong_bytes: &'static [u8],
) {
	serde_test::assert_tokens(
		&value.clone().compact(),
		&[Token::NewtypeStruct { name }, Token::Bytes(bytes)],
	);

	serde_test::assert_de_tokens(
		&value.compact(),
		&[
			Token::Seq { len: Some(1) },
			Token::Bytes(bytes),
			Token::SeqEnd,
		],
	);

	assert_de_tokens_error_partly::<Compact<T>>(
		&[Token::Seq { len: Some(1) }, Token::Unit, Token::SeqEnd],
		"invalid type: unit value, expected",
	);

	serde_test::assert_de_tokens_error::<T>(
		&[Token::Seq { len: Some(0) }, Token::SeqEnd],
		&format!("invalid length 0, expected tuple struct {name} with 1 element"),
	);

	serde_test::assert_de_tokens_error::<T>(
		&[Token::Struct { name, len: 0 }, Token::StructEnd],
		&format!("invalid type: map, expected tuple struct {name}"),
	);

	assert_de_tokens_error_partly::<Compact<T>>(
		&[Token::NewtypeStruct { name }, Token::Bytes(wrong_bytes)],
		"",
	);
}

/// Test a struct with two fields.
#[expect(clippy::too_many_lines, reason = "test")]
fn struct_2<T: Clone + Debug + for<'de> Deserialize<'de> + PartialEq + Serialize>(
	value: T,
	name: &'static str,
	field1: &'static str,
	bytes1: &'static [u8],
	field2: &'static str,
	bytes2: &'static [u8],
	wrong_bytes: &'static [u8],
) {
	serde_test::assert_tokens(
		&value.clone().compact(),
		&[
			Token::Struct { name, len: 2 },
			Token::Str(field1),
			Token::Bytes(bytes1),
			Token::Str(field2),
			Token::Bytes(bytes2),
			Token::StructEnd,
		],
	);

	serde_test::assert_de_tokens(
		&value.clone().compact(),
		&[
			Token::Struct { name, len: 2 },
			Token::Bytes(field1.as_bytes()),
			Token::Bytes(bytes1),
			Token::Bytes(field2.as_bytes()),
			Token::Bytes(bytes2),
			Token::StructEnd,
		],
	);

	serde_test::assert_de_tokens(
		&value.clone().compact(),
		&[
			Token::Struct { name, len: 2 },
			Token::U64(0),
			Token::Bytes(bytes1),
			Token::U64(1),
			Token::Bytes(bytes2),
			Token::StructEnd,
		],
	);

	serde_test::assert_de_tokens(
		&value.compact(),
		&[
			Token::Seq { len: Some(2) },
			Token::Bytes(bytes1),
			Token::Bytes(bytes2),
			Token::SeqEnd,
		],
	);

	serde_test::assert_de_tokens_error::<Compact<T>>(
		&[
			Token::Struct { name, len: 2 },
			Token::Str(field1),
			Token::Unit,
			Token::Str(field2),
		],
		&format!(
			"invalid type: unit value, expected an array of length {}",
			bytes1.len()
		),
	);

	serde_test::assert_de_tokens_error::<Compact<T>>(
		&[
			Token::Struct { name, len: 1 },
			Token::Str(field1),
			Token::Bytes(bytes1),
			Token::StructEnd,
		],
		"missing field `s`",
	);

	serde_test::assert_de_tokens_error::<Compact<T>>(
		&[
			Token::Struct { name, len: 1 },
			Token::Str(field2),
			Token::Bytes(bytes2),
			Token::StructEnd,
		],
		"missing field `c`",
	);

	serde_test::assert_de_tokens_error::<Compact<T>>(
		&[
			Token::Struct { name, len: 2 },
			Token::Str(field1),
			Token::Bytes(bytes1),
			Token::Str(field1),
			Token::Bytes(bytes1),
		],
		"duplicate field `c`",
	);

	serde_test::assert_de_tokens_error::<Compact<T>>(
		&[
			Token::Struct { name, len: 2 },
			Token::Str(field2),
			Token::Bytes(bytes2),
			Token::Str(field2),
			Token::Bytes(bytes2),
		],
		"duplicate field `s`",
	);

	serde_test::assert_de_tokens_error::<Compact<T>>(
		&[Token::Seq { len: Some(0) }, Token::SeqEnd],
		&format!("invalid length 0, expected struct {name} with 2 element"),
	);

	serde_test::assert_de_tokens_error::<Compact<T>>(
		&[
			Token::Seq { len: Some(1) },
			Token::Bytes(bytes1),
			Token::SeqEnd,
		],
		&format!("invalid length 1, expected struct {name} with 2 element"),
	);

	serde_test::assert_de_tokens_error::<Compact<T>>(
		&[
			Token::Struct { name, len: 2 },
			Token::Str("unknown"),
			Token::Bytes(bytes1),
		],
		&format!("unknown field `unknown`, expected `{field1}` or `{field2}`"),
	);

	serde_test::assert_de_tokens_error::<Compact<T>>(
		&[
			Token::Struct { name, len: 2 },
			Token::Bytes(b"unknown"),
			Token::Bytes(bytes1),
		],
		&format!("unknown field `unknown`, expected `{field1}` or `{field2}`"),
	);

	serde_test::assert_de_tokens_error::<Compact<T>>(
		&[
			Token::Struct { name, len: 2 },
			Token::U64(2),
			Token::Bytes(bytes1),
		],
		"invalid value: integer `2`, expected field index 0 <= i < 2",
	);

	serde_test::assert_de_tokens_error::<Compact<T>>(
		&[Token::Struct { name, len: 2 }, Token::Unit],
		"invalid type: unit value, expected field identifier",
	);

	serde_test::assert_de_tokens_error::<T>(
		&[Token::NewtypeStruct { name }, Token::Bytes(bytes1)],
		&format!("invalid type: newtype struct, expected struct {name}"),
	);

	assert_de_tokens_error_partly::<Compact<T>>(
		&[
			Token::Struct { name, len: 2 },
			Token::Str(field1),
			Token::Bytes(wrong_bytes),
		],
		"",
	);

	assert_de_tokens_error_partly::<Compact<T>>(
		&[
			Token::Struct { name, len: 2 },
			Token::Str(field1),
			Token::Bytes(bytes1),
			Token::Str(field2),
			Token::Bytes(wrong_bytes),
		],
		"",
	);

	assert_de_tokens_error_partly::<Compact<T>>(
		&[Token::Seq { len: Some(2) }, Token::Bytes(wrong_bytes)],
		"",
	);

	assert_de_tokens_error_partly::<Compact<T>>(
		&[
			Token::Seq { len: Some(2) },
			Token::Bytes(bytes1),
			Token::Bytes(wrong_bytes),
		],
		"",
	);
}

/// Similar to [`serde_test::assert_de_tokens_error`] but only checks if start
/// of the error message matches.
#[track_caller]
fn assert_de_tokens_error_partly<'de, T>(tokens: &'de [Token], error: &str)
where
	T: Deserialize<'de>,
{
	let mut de = Deserializer::new(tokens);
	match T::deserialize(&mut de) {
		Ok(_) => panic!("tokens deserialized successfully"),
		Err(e) => assert!(
			e.to_string().starts_with(error),
			"\n  left: {e}\n right: {error}"
		),
	}

	de.next_token_opt();
	assert_eq!(de.remaining(), 0, "{} remaining tokens", de.remaining());
}
