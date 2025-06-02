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
use oprf::oprf::{OprfClient, OprfServer};
use oprf::poprf::{PoprfClient, PoprfServer};
use oprf::voprf::{VoprfClient, VoprfServer};
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
	let scalar1 = scalar::<CS>();
	let scalar2 = scalar::<CS>();
	let wrong_scalar = wrong_scalar::<CS>();

	let element = element::<CS>();
	let wrong_element = wrong_element::<CS>();

	let blinded_element = BlindedElement::from_repr(element).unwrap();
	newtype_struct(blinded_element, "BlindedElement", element, wrong_element);

	let evaluation_element = EvaluationElement::from_repr(element).unwrap();
	newtype_struct(
		evaluation_element,
		"EvaluationElement",
		element,
		wrong_element,
	);

	let proof_bytes = [scalar1, scalar2].concat();
	let proof = Proof::<CS>::from_repr(&proof_bytes).unwrap();
	struct_2(
		proof,
		"Proof",
		"c",
		scalar1,
		wrong_scalar,
		"s",
		scalar2,
		wrong_scalar,
	);

	let key_pair = KeyPair::<CS::Group>::from_repr(scalar1).unwrap();
	newtype_struct(key_pair, "KeyPair", scalar1, wrong_scalar);

	let secret_key = SecretKey::<CS::Group>::from_repr(scalar1).unwrap();
	newtype_struct(secret_key, "SecretKey", scalar1, wrong_scalar);

	let public_key = PublicKey::<CS::Group>::from_repr(element).unwrap();
	newtype_struct(public_key, "PublicKey", element, wrong_element);
}

test_ciphersuites!(oprf);

/// Test OPRF types.
fn oprf<CS: CipherSuite>()
where
	OprfClient<CS>: for<'de> Deserialize<'de> + Serialize,
	OprfServer<CS>: for<'de> Deserialize<'de> + Serialize,
{
	let scalar = scalar::<CS>();
	let wrong_scalar = wrong_scalar::<CS>();

	let client = Compact::<OprfClient<CS>>::deserialize(&mut Deserializer::new(&[
		Token::Seq { len: Some(1) },
		Token::Bytes(scalar),
		Token::SeqEnd,
	]))
	.unwrap()
	.0;
	newtype_struct(client, "OprfClient", scalar, wrong_scalar);

	let secret_key = SecretKey::from_repr(scalar).unwrap();
	let server = OprfServer::<CS>::from_key(secret_key);
	newtype_struct(server, "OprfServer", scalar, wrong_scalar);
}

test_ciphersuites!(voprf);

/// Test VOPRF types.
fn voprf<CS: CipherSuite>()
where
	VoprfClient<CS>: for<'de> Deserialize<'de> + Serialize,
	VoprfServer<CS>: for<'de> Deserialize<'de> + Serialize,
{
	let scalar = scalar::<CS>();
	let wrong_scalar = wrong_scalar::<CS>();

	let element = element::<CS>();
	let wrong_element = wrong_element::<CS>();

	let client = Compact::<VoprfClient<CS>>::deserialize(&mut Deserializer::new(&[
		Token::Seq { len: Some(2) },
		Token::Bytes(scalar),
		Token::Bytes(element),
		Token::SeqEnd,
	]))
	.unwrap()
	.0;
	struct_2(
		client,
		"VoprfClient",
		"blind",
		scalar,
		wrong_scalar,
		"blinded_element",
		element,
		wrong_element,
	);

	let secret_key = KeyPair::from_repr(scalar).unwrap();
	let server = VoprfServer::<CS>::from_key_pair(secret_key);
	newtype_struct(server, "VoprfServer", scalar, wrong_scalar);
}

test_ciphersuites!(poprf);

/// Test POPRF types.
fn poprf<CS: CipherSuite>()
where
	PoprfClient<CS>: for<'de> Deserialize<'de> + Serialize,
	PoprfServer<CS>: for<'de> Deserialize<'de> + Serialize,
{
	let scalar = scalar::<CS>();
	let wrong_scalar = wrong_scalar::<CS>();

	let element = element::<CS>();
	let wrong_element = wrong_element::<CS>();

	let client = Compact::<PoprfClient<CS>>::deserialize(&mut Deserializer::new(&[
		Token::Seq { len: Some(2) },
		Token::Bytes(scalar),
		Token::Bytes(element),
		Token::SeqEnd,
	]))
	.unwrap()
	.0;
	struct_2(
		client,
		"PoprfClient",
		"blind",
		scalar,
		wrong_scalar,
		"blinded_element",
		element,
		wrong_element,
	);

	let secret_key = KeyPair::from_repr(scalar).unwrap();
	let server = PoprfServer::<CS>::from_key_pair(secret_key);
	newtype_struct(server, "PoprfServer", scalar, wrong_scalar);
}

fn scalar<CS: CipherSuite>() -> &'static [u8] {
	let scalar = CS::Group::scalar_random(&mut OsRng).unwrap();
	let scalar_bytes = CS::Group::scalar_to_repr(&scalar);
	Box::leak(Box::new(scalar_bytes))
}

fn wrong_scalar<CS: CipherSuite>() -> &'static [u8] {
	let scalar_bytes = Array::<u8, <CS::Group as Group>::ScalarLength>::from_fn(|_| u8::MAX);
	Box::leak(Box::new(scalar_bytes))
}

fn element<CS: CipherSuite>() -> &'static [u8] {
	let scalar = CS::Group::scalar_random(&mut OsRng).unwrap();
	let element = CS::Group::scalar_mul_by_generator(&scalar);
	let element_bytes = CS::Group::element_to_repr(&element);
	Box::leak(Box::new(element_bytes))
}

fn wrong_element<CS: CipherSuite>() -> &'static [u8] {
	let element_bytes = Array::<u8, <CS::Group as Group>::ElementLength>::default();
	Box::leak(Box::new(element_bytes))
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
#[expect(clippy::too_many_arguments, clippy::too_many_lines, reason = "test")]
fn struct_2<T: Clone + Debug + for<'de> Deserialize<'de> + PartialEq + Serialize>(
	value: T,
	name: &'static str,
	field1: &'static str,
	bytes1: &'static [u8],
	wrong_bytes1: &'static [u8],
	field2: &'static str,
	bytes2: &'static [u8],
	wrong_bytes2: &'static [u8],
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
		&format!("missing field `{field2}`"),
	);

	serde_test::assert_de_tokens_error::<Compact<T>>(
		&[
			Token::Struct { name, len: 1 },
			Token::Str(field2),
			Token::Bytes(bytes2),
			Token::StructEnd,
		],
		&format!("missing field `{field1}`"),
	);

	serde_test::assert_de_tokens_error::<Compact<T>>(
		&[
			Token::Struct { name, len: 2 },
			Token::Str(field1),
			Token::Bytes(bytes1),
			Token::Str(field1),
			Token::Bytes(bytes1),
		],
		&format!("duplicate field `{field1}`"),
	);

	serde_test::assert_de_tokens_error::<Compact<T>>(
		&[
			Token::Struct { name, len: 2 },
			Token::Str(field2),
			Token::Bytes(bytes2),
			Token::Str(field2),
			Token::Bytes(bytes2),
		],
		&format!("duplicate field `{field2}`"),
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
			Token::Bytes(wrong_bytes1),
		],
		"",
	);

	assert_de_tokens_error_partly::<Compact<T>>(
		&[
			Token::Struct { name, len: 2 },
			Token::Str(field1),
			Token::Bytes(bytes1),
			Token::Str(field2),
			Token::Bytes(wrong_bytes2),
		],
		"",
	);

	assert_de_tokens_error_partly::<Compact<T>>(
		&[Token::Seq { len: Some(2) }, Token::Bytes(wrong_bytes1)],
		"",
	);

	assert_de_tokens_error_partly::<Compact<T>>(
		&[
			Token::Seq { len: Some(2) },
			Token::Bytes(bytes1),
			Token::Bytes(wrong_bytes2),
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
