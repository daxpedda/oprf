//! [`ExpandMsgMock`] implementation.

use std::num::NonZero;

use elliptic_curve::Error;
use elliptic_curve::hash2curve::{ExpandMsg, Expander};

/// A mock [`ExpandMsg`] for testing purposes. It is no-op.
#[derive(Clone, Copy, Debug)]
pub struct ExpandMsgMock;

impl<K> ExpandMsg<K> for ExpandMsgMock {
	type Expander<'dst> = Self;

	fn expand_message<'dst>(
		_: &[&[u8]],
		_: &'dst [&[u8]],
		_: NonZero<usize>,
	) -> Result<Self::Expander<'dst>, Error> {
		Ok(Self)
	}
}

impl Expander for ExpandMsgMock {
	fn fill_bytes(&mut self, _: &mut [u8]) {}
}
