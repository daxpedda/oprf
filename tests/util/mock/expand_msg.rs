//! [`ExpandMsgMock`] implementation.

use std::num::NonZero;

use elliptic_curve::Error;
use elliptic_curve::hash2curve::{ExpandMsg, Expander};

/// A mock [`ExpandMsg`] for testing purposes. It is no-op.
pub struct ExpandMsgMock;

impl ExpandMsg<'_> for ExpandMsgMock {
	type Expander = Self;

	fn expand_message(
		_: &[&[u8]],
		_: &[&[u8]],
		_: NonZero<usize>,
	) -> Result<Self::Expander, Error> {
		Ok(Self)
	}
}

impl Expander for ExpandMsgMock {
	fn fill_bytes(&mut self, _: &mut [u8]) {}
}
