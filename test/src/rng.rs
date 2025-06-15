//! Mock [`RngCore`] implementation.

use rand_core::{OsRng, TryCryptoRng, TryRngCore};

/// A mock RNG. Will panic if the given `bytes` are exhausted. Can function like
/// a redirect to [`OsRng`] as well.
pub(crate) struct MockRng<'bytes>(Option<&'bytes [u8]>);

impl<'bytes> MockRng<'bytes> {
	/// Creates a new [`MockRng`] which redirects to [`OsRng`].
	#[must_use]
	pub(crate) const fn new_os_rng() -> Self {
		Self(None)
	}

	/// Creates a new [`MockRng`] which will panic if the given `bytes` are
	/// exhausted.
	#[must_use]
	pub(crate) const fn new(bytes: &'bytes [u8]) -> Self {
		Self(Some(bytes))
	}
}

impl TryRngCore for MockRng<'_> {
	type Error = <OsRng as TryRngCore>::Error;

	fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
		if self.0.is_some() {
			let mut bytes = [0; size_of::<u32>()];
			self.try_fill_bytes(&mut bytes)?;
			Ok(u32::from_be_bytes(bytes))
		} else {
			OsRng.try_next_u32()
		}
	}

	fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
		if self.0.is_some() {
			let mut bytes = [0; size_of::<u64>()];
			self.try_fill_bytes(&mut bytes)?;
			Ok(u64::from_be_bytes(bytes))
		} else {
			OsRng.try_next_u64()
		}
	}

	fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
		if let Some(bytes) = self.0.as_mut() {
			dst.copy_from_slice(&bytes[..dst.len()]);
			*bytes = &bytes[..dst.len()];
			Ok(())
		} else {
			OsRng.try_fill_bytes(dst)
		}
	}
}

impl TryCryptoRng for MockRng<'_> {}
