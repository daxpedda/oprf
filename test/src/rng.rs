//! Mock [`CryptoRng`] implementation.

use rand_core::{CryptoRng, RngCore};

/// A mock RNG. Will panic if the provided `bytes` are exhausted. Can function
/// like a redirect to [`ThreadRng`](rand::rngs::ThreadRng) as well.
pub(crate) struct MockRng<'bytes>(Option<&'bytes [u8]>);

impl<'bytes> MockRng<'bytes> {
	/// Creates a new [`MockRng`] which redirects to
	/// [`ThreadRng`](rand::rngs::ThreadRng).
	#[must_use]
	pub(crate) const fn new_rng() -> Self {
		Self(None)
	}

	/// Creates a new [`MockRng`] which will panic if the provided `bytes` are
	/// exhausted.
	#[must_use]
	pub(crate) const fn new(bytes: &'bytes [u8]) -> Self {
		Self(Some(bytes))
	}
}

impl RngCore for MockRng<'_> {
	fn next_u32(&mut self) -> u32 {
		if self.0.is_some() {
			let mut bytes = [0; size_of::<u32>()];
			self.fill_bytes(&mut bytes);
			u32::from_be_bytes(bytes)
		} else {
			rand::rng().next_u32()
		}
	}

	fn next_u64(&mut self) -> u64 {
		if self.0.is_some() {
			let mut bytes = [0; size_of::<u64>()];
			self.fill_bytes(&mut bytes);
			u64::from_be_bytes(bytes)
		} else {
			rand::rng().next_u64()
		}
	}

	fn fill_bytes(&mut self, dst: &mut [u8]) {
		if let Some(bytes) = self.0.as_mut() {
			dst.copy_from_slice(&bytes[..dst.len()]);
			*bytes = &bytes[dst.len()..];
		} else {
			rand::rng().fill_bytes(dst);
		}
	}
}

impl CryptoRng for MockRng<'_> {}
