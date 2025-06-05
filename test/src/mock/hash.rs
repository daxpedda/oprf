//! Mock [`Digest`](digest::Digest) implementation.

use digest::{FixedOutput, Output, OutputSizeUser, Update};
use hybrid_array::typenum::U0;

/// A mock [`Digest`](digest::Digest) for testing purposes. It is zero-sized.
#[derive(Clone, Copy, Debug, Default)]
pub struct MockHash;

impl FixedOutput for MockHash {
	fn finalize_into(self, _: &mut Output<Self>) {}
}

impl OutputSizeUser for MockHash {
	type OutputSize = U0;
}

impl Update for MockHash {
	fn update(&mut self, _: &[u8]) {}
}
