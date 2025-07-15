//! [`Error`] type.

use core::convert::Infallible;
use core::fmt::{Display, Formatter};
use core::{error, fmt, result};

use rand_core::TryCryptoRng;

/// [`Result`](result::Result) type used throughout this crate.
pub type Result<T, E = Error> = result::Result<T, E>;

/// Error type used throughout this crate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[expect(clippy::error_impl_error, reason = "only one error type")]
pub enum Error<E = Infallible> {
	/// Number of passed items don't match, are 0 or larger than `u16::MAX`.
	Batch,
	/// The `Proof` is invalid.
	Proof,
	/// `info` exceeds a length of [`u16::MAX`].
	InfoLength,
	/// A [`SecretKey`](crate::key::SecretKey) can never be derived from the
	/// given input.
	DeriveKeyPair,
	/// `input` exceeds a length of [`u16::MAX`].
	InputLength,
	/// This [`CipherSuite`]s [`Group`] and [`ExpandMsg`] are incompatible.
	///
	/// [`CipherSuite`]: crate::cipher_suite::CipherSuite
	/// [`Group`]: crate::cipher_suite::CipherSuite::Group
	/// [`ExpandMsg`]: crate::cipher_suite::CipherSuite::ExpandMsg
	InvalidCipherSuite,
	/// The given `input` can never produce a valid output.
	InvalidInput,
	/// The given `info` can never produce a valid output.
	InvalidInfo,
	/// The given `info` maps to the [`SecretKey`](crate::key::SecretKey) of the
	/// server, the client can be assumed to know it and it should be replaced.
	InvalidInfoDanger,
	/// The given `bytes` can't be deserialized into the output type.
	FromRepr,
	/// The given `rng` failed.
	Random(E),
}

impl Error {
	/// Converts this [`Error`] to `Error::<R::Error>` with the given `R`. This
	/// is useful when wanting to align types between errors with and without a
	/// [`Error::Random`] type.
	///
	/// # Examples
	///
	/// ```
	/// # use rand_core::{OsRng, OsError};
	/// # use oprf::{BlindedElement, Error, OprfServer, Result};
	/// # use oprf_test::MockCs as MyCipherSuite;
	/// #
	/// fn fun(blinded_element: &[u8]) -> Result<(), Error<OsError>> {
	/// 	let blinded_element = BlindedElement::from_repr(blinded_element).map_err(Error::into_random::<OsRng>)?;
	/// 	let server = OprfServer::<MyCipherSuite>::new(&mut OsRng).map_err(Error::Random)?;
	/// 	let evaluation_element = server.blind_evaluate(&blinded_element);
	/// # /*
	/// 	...
	/// # */
	/// # Ok(())
	/// }
	/// ```
	#[must_use]
	pub const fn into_random<R>(self) -> Error<R::Error>
	where
		R: ?Sized + TryCryptoRng,
	{
		match self {
			Self::Batch => Error::Batch,
			Self::Proof => Error::Proof,
			Self::InfoLength => Error::InfoLength,
			Self::DeriveKeyPair => Error::DeriveKeyPair,
			Self::InputLength => Error::InputLength,
			Self::InvalidCipherSuite => Error::InvalidCipherSuite,
			Self::InvalidInput => Error::InvalidInput,
			Self::InvalidInfo => Error::InvalidInfo,
			Self::InvalidInfoDanger => Error::InvalidInfoDanger,
			Self::FromRepr => Error::FromRepr,
		}
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<E: Display> Display for Error<E> {
	fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::Batch => "number of passed items don't match, are 0 or larger than `u16::MAX`",
			Self::Proof => "the `Proof` is invalid",
			Self::InfoLength => "`info` exceeds a length of `u16::MAX`",
			Self::DeriveKeyPair => "`SecretKey` can never be derived from the given input",
			Self::InputLength => "`input` exceeds a length of `u16::MAX`",
			Self::InvalidCipherSuite => {
				"this `CipherSuite`s `Group` and `ExpandMsg` are incompatible"
			}
			Self::InvalidInput => "the given `input` can never produce a valid output",
			Self::InvalidInfo => "the given `info` can never produce a valid output",
			Self::InvalidInfoDanger => {
				"the given `info` maps to the `SecretKey` of the server, the client can be assumed \
				 to know it and it should be replaced"
			}
			Self::FromRepr => "the given `bytes` can't be deserialized into the output type",
			Self::Random(error) => return error.fmt(formatter),
		})
	}
}

impl<E: error::Error> error::Error for Error<E> {}

/// Used to return an error from [`Group`](crate::group::Group) methods.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InternalError;

#[cfg_attr(coverage_nightly, coverage(off))]
impl Display for InternalError {
	fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
		formatter.write_str("internal ORPF error")
	}
}

impl error::Error for InternalError {}
