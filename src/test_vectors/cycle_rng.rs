//! A mock RNG, [`CycleRng`], that cycles over the given bytes.

use rand_core::{CryptoRng, RngCore};

/// The mock RNG.
pub(super) struct CycleRng<'bytes> {
	bytes: &'bytes [u8],
	offset: usize,
}

impl<'bytes> CycleRng<'bytes> {
	pub(super) fn new(bytes: &'bytes [u8]) -> Self {
		CycleRng { bytes, offset: 0 }
	}
}

impl RngCore for CycleRng<'_> {
	fn next_u32(&mut self) -> u32 {
		let mut bytes = [0; size_of::<u32>()];
		self.fill_bytes(&mut bytes);
		u32::from_be_bytes(bytes)
	}

	fn next_u64(&mut self) -> u64 {
		let mut bytes = [0; size_of::<u64>()];
		self.fill_bytes(&mut bytes);
		u64::from_be_bytes(bytes)
	}

	fn fill_bytes(&mut self, mut dst: &mut [u8]) {
		let mut left = dst.len();

		while left != 0 {
			if self.offset == self.bytes.len() {
				self.offset = 0;
			}

			let take = (self.bytes.len() - self.offset).min(left);
			dst[..take].copy_from_slice(&self.bytes[self.offset..take]);
			self.offset += take;
			left -= take;
			dst = &mut dst[take..];
		}
	}
}

impl CryptoRng for CycleRng<'_> {}
