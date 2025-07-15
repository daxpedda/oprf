//! Mock [`CipherSuite`] implementation.

pub mod expand_msg;
pub mod group;
pub mod hash;

use oprf::cipher_suite::{CipherSuite, Id};

pub use self::expand_msg::MockExpandMsg;
pub use self::group::MockCurve;
pub use self::hash::MockHash;

/// A mock [`CipherSuite`] for testing purposes. It is zero-sized, does no
/// checks whatsoever and is no-op.
#[derive(Clone, Copy, Debug)]
pub struct MockCs;

impl CipherSuite for MockCs {
	const ID: Id = Id::new(b"").unwrap();

	type Group = MockCurve;
	type Hash = MockHash;
	type ExpandMsg = MockExpandMsg<MockHash>;
}
