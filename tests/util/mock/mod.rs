mod expand_msg;
mod group;
mod hash;

use oprf::ciphersuite::{CipherSuite, Id};

use self::expand_msg::ExpandMsgMock;
use self::group::MockCurve;
use self::hash::MockHash;

/// A mock [`CipherSuite`] for testing purposes. It is zero-sized, does no
/// checks whatsoever and is no-op.
pub struct MockCs;

impl CipherSuite for MockCs {
	const ID: Id = Id::new(b"").unwrap();

	type Group = MockCurve;
	type Hash = MockHash;
	type ExpandMsg = ExpandMsgMock;
}
