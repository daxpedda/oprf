//! Tests for Serde implementations.

#![cfg(test)]
#![cfg(feature = "serde")]
#![expect(clippy::cargo_common_metadata, reason = "tests")]

use std::fmt::Debug;
use std::iter;

use hybrid_array::{Array, ArraySize};
use oprf::cipher_suite::CipherSuite;
use oprf::common::{BlindedElement, EvaluationElement, Proof};
use oprf::key::{KeyPair, PublicKey, SecretKey};
use oprf::oprf::{OprfClient, OprfServer};
use oprf::poprf::{PoprfClient, PoprfServer};
use oprf::voprf::{VoprfClient, VoprfServer};
use oprf_test::{ScalarRepr, TypeRepr, test_ciphersuites};
use serde::{Deserialize, Serialize};
use serde_test::de::Deserializer;
use serde_test::{Compact, Configure, Token};

test_ciphersuites!(common);

/// Test common types.
fn common<CS: CipherSuite<Group: ScalarRepr> + ScalarRepr>()
where
	BlindedElement<CS>: for<'de> Deserialize<'de> + Serialize,
	EvaluationElement<CS>: for<'de> Deserialize<'de> + Serialize,
	Proof<CS>: for<'de> Deserialize<'de> + Serialize,
	KeyPair<CS::Group>: for<'de> Deserialize<'de> + Serialize,
	SecretKey<CS::Group>: for<'de> Deserialize<'de> + Serialize,
	PublicKey<CS::Group>: for<'de> Deserialize<'de> + Serialize,
{
	let scalar1 = leak(oprf_test::scalar::<CS>());
	let scalar2 = leak(oprf_test::scalar::<CS>());
	let invalid_scalar = leak(oprf_test::invalid_scalar::<CS>());
	let zero_scalar = leak(oprf_test::zero_scalar::<CS>());

	let element = leak(oprf_test::element::<CS>());
	let invalid_element = leak(oprf_test::invalid_element::<CS>());
	let identity_element = leak(oprf_test::identity_element::<CS>());

	let blinded_element = BlindedElement::from_repr(element).unwrap();
	newtype_struct(
		&blinded_element,
		"BlindedElement",
		element,
		[invalid_element, identity_element],
	);

	let evaluation_element = EvaluationElement::from_repr(element).unwrap();
	newtype_struct(
		&evaluation_element,
		"EvaluationElement",
		element,
		[invalid_element, identity_element],
	);

	let proof_bytes = [scalar1, scalar2].concat();
	let proof = Proof::<CS>::from_repr(&proof_bytes).unwrap();
	struct_2(
		&proof,
		"Proof",
		"c",
		scalar1,
		[invalid_scalar],
		"s",
		scalar2,
		[invalid_scalar],
	);

	let key_pair = KeyPair::<CS::Group>::from_repr(scalar1).unwrap();
	newtype_struct(&key_pair, "KeyPair", scalar1, [invalid_scalar, zero_scalar]);

	let secret_key = SecretKey::<CS::Group>::from_repr(scalar1).unwrap();
	newtype_struct(
		&secret_key,
		"SecretKey",
		scalar1,
		[invalid_scalar, zero_scalar],
	);

	let public_key = PublicKey::<CS::Group>::from_repr(element).unwrap();
	newtype_struct(
		&public_key,
		"PublicKey",
		element,
		[invalid_element, identity_element],
	);
}

test_ciphersuites!(oprf);

/// Test OPRF types.
fn oprf<CS: CipherSuite + ScalarRepr>()
where
	OprfClient<CS>: for<'de> Deserialize<'de> + Serialize,
	OprfServer<CS>: for<'de> Deserialize<'de> + Serialize,
{
	let scalar = leak(oprf_test::scalar::<CS>());
	let invalid_scalar = leak(oprf_test::invalid_scalar::<CS>());
	let zero_scalar = leak(oprf_test::zero_scalar::<CS>());

	let client = Compact::<OprfClient<CS>>::deserialize(&mut Deserializer::new(
		&iter::once(Token::Seq { len: Some(1) })
			.chain(OprfClient::<CS>::repr(0, scalar))
			.chain(iter::once(Token::SeqEnd))
			.collect::<Vec<_>>(),
	))
	.unwrap()
	.0;
	newtype_struct(&client, "OprfClient", scalar, [invalid_scalar, zero_scalar]);

	let secret_key = SecretKey::from_repr(scalar).unwrap();
	let server = OprfServer::<CS>::from_key(secret_key);
	newtype_struct(&server, "OprfServer", scalar, [invalid_scalar, zero_scalar]);
}

test_ciphersuites!(voprf);

/// Test VOPRF types.
fn voprf<CS: CipherSuite + ScalarRepr>()
where
	VoprfClient<CS>: for<'de> Deserialize<'de> + Serialize,
	VoprfServer<CS>: for<'de> Deserialize<'de> + Serialize,
{
	let scalar = leak(oprf_test::scalar::<CS>());
	let invalid_scalar = leak(oprf_test::invalid_scalar::<CS>());
	let zero_scalar = leak(oprf_test::zero_scalar::<CS>());

	let element = leak(oprf_test::element::<CS>());
	let invalid_element = leak(oprf_test::invalid_element::<CS>());
	let identity_element = leak(oprf_test::identity_element::<CS>());

	let client = Compact::<VoprfClient<CS>>::deserialize(&mut Deserializer::new(
		&iter::once(Token::Seq { len: Some(2) })
			.chain(VoprfClient::<CS>::repr(0, scalar))
			.chain([Token::Bytes(element), Token::SeqEnd])
			.collect::<Vec<_>>(),
	))
	.unwrap()
	.0;
	struct_2(
		&client,
		"VoprfClient",
		"blind",
		scalar,
		[invalid_scalar, zero_scalar],
		"blinded_element",
		element,
		[invalid_element, identity_element],
	);

	let secret_key = KeyPair::from_repr(scalar).unwrap();
	let server = VoprfServer::<CS>::from_key_pair(secret_key);
	newtype_struct(
		&server,
		"VoprfServer",
		scalar,
		[invalid_scalar, zero_scalar],
	);
}

test_ciphersuites!(poprf);

/// Test POPRF types.
fn poprf<CS: CipherSuite + ScalarRepr>()
where
	PoprfClient<CS>: for<'de> Deserialize<'de> + Serialize,
	PoprfServer<CS>: for<'de> Deserialize<'de> + Serialize,
{
	let scalar1 = leak(oprf_test::scalar::<CS>());
	let scalar2 = leak(oprf_test::scalar::<CS>());
	let invalid_scalar = leak(oprf_test::invalid_scalar::<CS>());
	let zero_scalar = leak(oprf_test::zero_scalar::<CS>());

	let element = leak(oprf_test::element::<CS>());
	let invalid_element = leak(oprf_test::invalid_element::<CS>());
	let identity_element = leak(oprf_test::identity_element::<CS>());

	let client = Compact::<PoprfClient<CS>>::deserialize(&mut Deserializer::new(
		&iter::once(Token::Seq { len: Some(2) })
			.chain(PoprfClient::<CS>::repr(0, scalar1))
			.chain([Token::Bytes(element), Token::SeqEnd])
			.collect::<Vec<_>>(),
	))
	.unwrap()
	.0;
	struct_2(
		&client,
		"PoprfClient",
		"blind",
		scalar1,
		[invalid_scalar, zero_scalar],
		"blinded_element",
		element,
		[invalid_element, identity_element],
	);

	let server = Compact::<PoprfServer<CS>>::deserialize(&mut Deserializer::new(
		&iter::once(Token::Seq { len: Some(2) })
			.chain(PoprfServer::<CS>::repr(0, scalar1))
			.chain(PoprfServer::<CS>::repr(1, scalar2))
			.chain(iter::once(Token::SeqEnd))
			.collect::<Vec<_>>(),
	))
	.unwrap()
	.0;
	struct_2(
		&server,
		"PoprfServer",
		"secret_key",
		scalar1,
		[invalid_scalar, zero_scalar],
		"t",
		scalar2,
		[invalid_scalar, zero_scalar],
	);
}

/// Test a newtype struct.
fn newtype_struct<
	T: Clone + Debug + for<'de> Deserialize<'de> + PartialEq + Serialize + TypeRepr,
>(
	value: &T,
	name: &'static str,
	bytes: &'static [u8],
	invalid_bytes: impl IntoIterator<Item = &'static [u8]>,
) {
	serde_test::assert_tokens(
		&value.clone().compact(),
		&iter::once(Token::NewtypeStruct { name })
			.chain(T::repr(0, bytes))
			.collect::<Vec<_>>(),
	);

	serde_test::assert_de_tokens(
		&value.clone().compact(),
		&iter::once(Token::Seq { len: Some(1) })
			.chain(T::repr(0, bytes))
			.chain(iter::once(Token::SeqEnd))
			.collect::<Vec<_>>(),
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

	for invalid_bytes in invalid_bytes {
		assert_de_tokens_error_partly::<Compact<T>>(
			&[Token::NewtypeStruct { name }, Token::Bytes(invalid_bytes)],
			"",
		);
	}
}

/// Test a struct with two fields.
#[expect(clippy::too_many_arguments, clippy::too_many_lines, reason = "test")]
fn struct_2<T: Clone + Debug + for<'de> Deserialize<'de> + PartialEq + Serialize + TypeRepr>(
	value: &T,
	name: &'static str,
	field1: &'static str,
	bytes1: &'static [u8],
	invalid_bytes1: impl Copy + IntoIterator<Item = &'static [u8]>,
	field2: &'static str,
	bytes2: &'static [u8],
	invalid_bytes2: impl Copy + IntoIterator<Item = &'static [u8]>,
) {
	serde_test::assert_tokens(
		&value.clone().compact(),
		&[Token::Struct { name, len: 2 }, Token::Str(field1)]
			.into_iter()
			.chain(T::repr(0, bytes1))
			.chain(iter::once(Token::Str(field2)))
			.chain(T::repr(1, bytes2))
			.chain(iter::once(Token::StructEnd))
			.collect::<Vec<_>>(),
	);

	serde_test::assert_de_tokens(
		&value.clone().compact(),
		&[
			Token::Struct { name, len: 2 },
			Token::Bytes(field1.as_bytes()),
		]
		.into_iter()
		.chain(T::repr(0, bytes1))
		.chain(iter::once(Token::Bytes(field2.as_bytes())))
		.chain(T::repr(1, bytes2))
		.chain(iter::once(Token::StructEnd))
		.collect::<Vec<_>>(),
	);

	serde_test::assert_de_tokens(
		&value.clone().compact(),
		&[Token::Struct { name, len: 2 }, Token::U64(0)]
			.into_iter()
			.chain(T::repr(0, bytes1))
			.chain(iter::once(Token::U64(1)))
			.chain(T::repr(1, bytes2))
			.chain(iter::once(Token::StructEnd))
			.collect::<Vec<_>>(),
	);

	serde_test::assert_de_tokens(
		&value.clone().compact(),
		&iter::once(Token::Seq { len: Some(2) })
			.chain(T::repr(0, bytes1))
			.chain(T::repr(1, bytes2))
			.chain(iter::once(Token::SeqEnd))
			.collect::<Vec<_>>(),
	);

	assert_de_tokens_error_partly::<Compact<T>>(
		&[
			Token::Struct { name, len: 2 },
			Token::Str(field1),
			Token::Unit,
			Token::Str(field2),
		],
		"invalid type: unit value, ",
	);

	serde_test::assert_de_tokens_error::<Compact<T>>(
		&[Token::Struct { name, len: 1 }, Token::Str(field1)]
			.into_iter()
			.chain(T::repr(0, bytes1))
			.chain(iter::once(Token::StructEnd))
			.collect::<Vec<_>>(),
		&format!("missing field `{field2}`"),
	);

	serde_test::assert_de_tokens_error::<Compact<T>>(
		&[Token::Struct { name, len: 1 }, Token::Str(field2)]
			.into_iter()
			.chain(T::repr(1, bytes2))
			.chain(iter::once(Token::StructEnd))
			.collect::<Vec<_>>(),
		&format!("missing field `{field1}`"),
	);

	serde_test::assert_de_tokens_error::<Compact<T>>(
		&[Token::Struct { name, len: 2 }, Token::Str(field1)]
			.into_iter()
			.chain(T::repr(0, bytes1))
			.chain(iter::once(Token::Str(field1)))
			.collect::<Vec<_>>(),
		&format!("duplicate field `{field1}`"),
	);

	serde_test::assert_de_tokens_error::<Compact<T>>(
		&[Token::Struct { name, len: 2 }, Token::Str(field2)]
			.into_iter()
			.chain(T::repr(1, bytes2))
			.chain(iter::once(Token::Str(field2)))
			.collect::<Vec<_>>(),
		&format!("duplicate field `{field2}`"),
	);

	serde_test::assert_de_tokens_error::<Compact<T>>(
		&[Token::Seq { len: Some(0) }, Token::SeqEnd],
		&format!("invalid length 0, expected struct {name} with 2 element"),
	);

	serde_test::assert_de_tokens_error::<Compact<T>>(
		&iter::once(Token::Seq { len: Some(1) })
			.chain(T::repr(0, bytes1))
			.chain(iter::once(Token::SeqEnd))
			.collect::<Vec<_>>(),
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

	for invalid_bytes in invalid_bytes1 {
		assert_de_tokens_error_partly::<Compact<T>>(
			&[
				Token::Struct { name, len: 2 },
				Token::Str(field1),
				Token::Bytes(invalid_bytes),
			],
			"",
		);
	}

	for invalid_bytes in invalid_bytes2 {
		assert_de_tokens_error_partly::<Compact<T>>(
			&[Token::Struct { name, len: 2 }, Token::Str(field1)]
				.into_iter()
				.chain(T::repr(0, bytes1))
				.chain(iter::once(Token::Str(field2)))
				.chain(T::repr(1, invalid_bytes))
				.collect::<Vec<_>>(),
			"",
		);
	}

	for invalid_bytes in invalid_bytes1 {
		assert_de_tokens_error_partly::<Compact<T>>(
			&[Token::Seq { len: Some(2) }, Token::Bytes(invalid_bytes)],
			"",
		);
	}

	for invalid_bytes in invalid_bytes2 {
		assert_de_tokens_error_partly::<Compact<T>>(
			&[
				Token::Seq { len: Some(2) },
				Token::Bytes(bytes1),
				Token::Bytes(invalid_bytes),
			],
			"",
		);
	}
}

/// Similar to [`serde_test::assert_de_tokens_error`] but only checks if the
/// start of the error message matches.
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

fn leak<N: ArraySize>(array: Array<u8, N>) -> &'static [u8] {
	Box::leak(Box::new(array))
}
