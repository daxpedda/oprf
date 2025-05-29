use core::convert::Infallible;
use core::fmt::{Display, Formatter};
use core::{error, fmt, result};

use rand_core::TryCryptoRng;

pub type Result<T, E = Error> = result::Result<T, E>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[expect(clippy::error_impl_error, reason = "only one error type")]
pub enum Error<E = Infallible> {
	Batch,
	Proof,
	InfoLength,
	DeriveKeyPair,
	InputLength,
	InvalidInput,
	InvalidInfo,
	InvalidInfoDanger,
	Random(E),
}

impl Error {
	#[must_use]
	pub const fn into_random<R: TryCryptoRng>(self) -> Error<R::Error> {
		match self {
			Self::Batch => Error::Batch,
			Self::Proof => Error::Proof,
			Self::InfoLength => Error::InfoLength,
			Self::DeriveKeyPair => Error::DeriveKeyPair,
			Self::InputLength => Error::InputLength,
			Self::InvalidInput => Error::InvalidInput,
			Self::InvalidInfo => Error::InvalidInfo,
			Self::InvalidInfoDanger => Error::InvalidInfoDanger,
		}
	}
}

#[cfg_attr(coverage_nightly, coverage(off))]
impl<E: Display> Display for Error<E> {
	fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::Batch => "number of items don't match, are 0 or larger than 0xFFFF",
			Self::Proof => "the `Proof` is invalid",
			Self::InfoLength => "length of `info` larger than 0xFFFF",
			Self::DeriveKeyPair => "key can't be derived from the given input",
			Self::InputLength => "length of `input` larger than 0xFFFF",
			Self::InvalidInput => "the given `input` can't produce a valid `BlindedElement`",
			Self::InvalidInfo => "the given `info` can't produce a valid `BlindedElement`",
			Self::InvalidInfoDanger => {
				"the given `info` maps to the secret key of the server, the client can be assumed \
				 to know it and it should be replaced"
			}
			Self::Random(error) => return error.fmt(formatter),
		})
	}
}

impl<E: error::Error> error::Error for Error<E> {}
