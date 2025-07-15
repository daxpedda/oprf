//! [`MockExpandMsg`] implementation.

use std::marker::PhantomData;
use std::num::NonZero;

use derive_where::derive_where;
use elliptic_curve::Error;
use hash2curve::{ExpandMsg, Expander};

/// A mock [`ExpandMsg`] for testing purposes. It is no-op.
#[derive_where(Clone, Copy, Debug)]
pub struct MockExpandMsg<H>(PhantomData<H>);

impl<H, K> ExpandMsg<K> for MockExpandMsg<H> {
	type Expander<'dst> = Self;

	fn expand_message<'dst>(
		_: &[&[u8]],
		_: &'dst [&[u8]],
		_: NonZero<u16>,
	) -> Result<Self::Expander<'dst>, Error> {
		Ok(Self(PhantomData))
	}
}

impl<H> Expander for MockExpandMsg<H> {
	fn fill_bytes(&mut self, _: &mut [u8]) {}
}
