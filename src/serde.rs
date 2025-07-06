#[cfg(feature = "alloc")]
use alloc::borrow::Cow;
#[cfg(feature = "alloc")]
use alloc::string::String;
use core::fmt::{self, Formatter};
use core::marker::PhantomData;

use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Unexpected, Visitor};
use serde::{Deserialize, Deserializer};

pub(crate) fn newtype_struct<'de, D, T>(deserializer: D, name: &'static str) -> Result<T, D::Error>
where
	D: Deserializer<'de>,
	T: Deserialize<'de>,
{
	struct VisitorImpl<T> {
		name: &'static str,
		_t: PhantomData<T>,
	}

	impl<'de, T: Deserialize<'de>> Visitor<'de> for VisitorImpl<T> {
		type Value = T;

		fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
			write!(formatter, "tuple struct {}", self.name)
		}

		fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
		where
			D: Deserializer<'de>,
		{
			T::deserialize(deserializer)
		}

		fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
			struct InvalidLengthVisitor(&'static str);

			impl Visitor<'_> for InvalidLengthVisitor {
				type Value = ();

				fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
					write!(formatter, "tuple struct {} with 1 element", self.0)
				}
			}

			seq.next_element()?
				.ok_or_else(|| Error::invalid_length(0, &InvalidLengthVisitor(self.name)))
		}
	}

	deserializer.deserialize_newtype_struct(
		name,
		VisitorImpl {
			name,
			_t: PhantomData,
		},
	)
}

#[expect(clippy::too_many_lines, reason = "serde")]
pub(crate) fn struct_2<'de, D, T1, T2>(
	deserializer: D,
	name: &'static str,
	fields: &'static [&'static str; 2],
) -> Result<(T1, T2), D::Error>
where
	D: Deserializer<'de>,
	T1: Deserialize<'de>,
	T2: Deserialize<'de>,
{
	struct FieldVisitor(&'static [&'static str; 2]);

	enum Field {
		Field1,
		Field2,
	}

	impl Visitor<'_> for FieldVisitor {
		type Value = Field;

		fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
			formatter.write_str("field identifier")
		}

		fn visit_u64<E: Error>(self, v: u64) -> Result<Self::Value, E> {
			match v {
				0 => Ok(Field::Field1),
				1 => Ok(Field::Field2),
				_ => Err(Error::invalid_value(
					Unexpected::Unsigned(v),
					&"field index 0 <= i < 2",
				)),
			}
		}

		fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
			match v {
				field1 if field1 == self.0[0] => Ok(Field::Field1),
				field2 if field2 == self.0[1] => Ok(Field::Field2),
				_ => Err(Error::unknown_field(v, self.0)),
			}
		}

		fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
		where
			E: Error,
		{
			match v {
				field1 if field1 == self.0[0].as_bytes() => Ok(Field::Field1),
				field2 if field2 == self.0[1].as_bytes() => Ok(Field::Field2),
				_ => {
					let v = &from_utf8_lossy(v);
					Err(Error::unknown_field(v, self.0))
				}
			}
		}
	}

	impl<'de> DeserializeSeed<'de> for FieldVisitor {
		type Value = Field;

		fn deserialize<D: Deserializer<'de>>(
			self,
			deserializer: D,
		) -> Result<Self::Value, D::Error> {
			deserializer.deserialize_identifier(self)
		}
	}

	struct VisitorImpl<T1, T2> {
		name: &'static str,
		fields: &'static [&'static str; 2],
		_t: PhantomData<(T1, T2)>,
	}

	impl<'de, T1: Deserialize<'de>, T2: Deserialize<'de>> Visitor<'de> for VisitorImpl<T1, T2> {
		type Value = (T1, T2);

		fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
			write!(formatter, "struct {}", self.name)
		}

		fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
			struct InvalidLengthVisitor(&'static str);

			impl Visitor<'_> for InvalidLengthVisitor {
				type Value = ();

				fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
					write!(formatter, "struct {} with 2 element", self.0)
				}
			}

			let field1 = seq
				.next_element()?
				.ok_or_else(|| Error::invalid_length(0, &InvalidLengthVisitor(self.name)))?;
			let field2 = seq
				.next_element()?
				.ok_or_else(|| Error::invalid_length(1, &InvalidLengthVisitor(self.name)))?;

			Ok((field1, field2))
		}

		fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
			let mut field1 = None;
			let mut field2 = None;

			while let Some(key) = map.next_key_seed(FieldVisitor(self.fields))? {
				match key {
					Field::Field1 => {
						if field1.is_some() {
							return Err(A::Error::duplicate_field(self.fields[0]));
						}

						field1 = Some(map.next_value()?);
					}
					Field::Field2 => {
						if field2.is_some() {
							return Err(A::Error::duplicate_field(self.fields[1]));
						}

						field2 = Some(map.next_value()?);
					}
				}
			}

			let field1 = if let Some(field1) = field1 {
				field1
			} else {
				missing_field(self.fields[0])?
			};
			let field2 = if let Some(field2) = field2 {
				field2
			} else {
				missing_field(self.fields[1])?
			};

			Ok((field1, field2))
		}
	}

	deserializer.deserialize_struct(
		name,
		fields,
		VisitorImpl {
			name,
			fields,
			_t: PhantomData,
		},
	)
}

// https://github.com/serde-rs/serde/blob/49d098debdf8b5c38bfb6868f455c6ce542c422c/serde/src/private/mod.rs#L29-L47
#[cfg(feature = "alloc")]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn from_utf8_lossy(bytes: &[u8]) -> Cow<'_, str> {
	String::from_utf8_lossy(bytes)
}

// https://github.com/serde-rs/serde/blob/49d098debdf8b5c38bfb6868f455c6ce542c422c/serde/src/private/mod.rs#L29-L47
#[cfg(not(feature = "alloc"))]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn from_utf8_lossy(bytes: &[u8]) -> &str {
	str::from_utf8(bytes).unwrap_or("\u{fffd}\u{fffd}\u{fffd}")
}

// https://github.com/serde-rs/serde/blob/49d098debdf8b5c38bfb6868f455c6ce542c422c/serde/src/private/de.rs#L21-L59
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn missing_field<'de, V, E>(field: &'static str) -> Result<V, E>
where
	V: Deserialize<'de>,
	E: Error,
{
	struct MissingFieldDeserializer<E>(&'static str, PhantomData<E>);

	impl<'de, E> Deserializer<'de> for MissingFieldDeserializer<E>
	where
		E: Error,
	{
		type Error = E;

		fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value, E>
		where
			V: Visitor<'de>,
		{
			Err(Error::missing_field(self.0))
		}

		fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, E>
		where
			V: Visitor<'de>,
		{
			visitor.visit_none()
		}

		serde::forward_to_deserialize_any! {
			bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
			bytes byte_buf unit unit_struct newtype_struct seq tuple
			tuple_struct map struct enum identifier ignored_any
		}
	}

	let deserializer = MissingFieldDeserializer(field, PhantomData);
	Deserialize::deserialize(deserializer)
}
