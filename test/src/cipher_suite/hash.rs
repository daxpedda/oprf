//! Mock [`Digest`](digest::Digest) implementation.

use digest::{ExtendableOutput, FixedOutput, Output, OutputSizeUser, Update, XofReader};
use hybrid_array::typenum::U0;

/// A mock [`Digest`](digest::Digest) for testing purposes. It is zero-sized.
#[derive(Clone, Copy, Debug, Default)]
pub struct MockHash;

impl ExtendableOutput for MockHash {
	type Reader = Self;

	fn finalize_xof(self) -> Self::Reader {
		Self
	}
}

impl FixedOutput for MockHash {
	fn finalize_into(self, _: &mut Output<Self>) {}
}

impl OutputSizeUser for MockHash {
	type OutputSize = U0;
}

impl Update for MockHash {
	fn update(&mut self, _: &[u8]) {}
}

impl XofReader for MockHash {
	fn read(&mut self, _: &mut [u8]) {}
}
