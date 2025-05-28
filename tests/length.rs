//! Tests for [`Error::InputLength`] and [`Error::InfoLength`] cases.

#![cfg(test)]
#![expect(
	clippy::cargo_common_metadata,
	clippy::indexing_slicing,
	reason = "tests"
)]

mod util;

use std::iter;
use std::sync::LazyLock;

use oprf::Error;
use oprf::ciphersuite::CipherSuite;
use oprf::common::Mode;
use util::{HelperClient, HelperServer};

static TEST: LazyLock<Vec<u8>> = LazyLock::new(|| vec![0; usize::from(u16::MAX) + 1]);

test_ciphersuites!(basic, Oprf);
test_ciphersuites!(basic, Voprf);
test_ciphersuites!(basic, Poprf);

/// Tests correct failure on invalid `input` and `info` length.
fn basic<CS: CipherSuite>(mode: Mode) {
	// Failure on too large input.
	let result = HelperClient::<CS>::blind_with(mode, &[&TEST]);
	assert_eq!(result.unwrap_err(), Error::InputLength);

	// Success on maximum length of input.
	let client = HelperClient::<CS>::blind_with(mode, &[&TEST[..u16::MAX.into()]]).unwrap();

	// Failure on too large info.
	if let Mode::Poprf = mode {
		let result = HelperServer::blind_evaluate_with(&client, &TEST);
		assert_eq!(result.unwrap_err(), Error::InfoLength);
	}

	// Success on maximum length of info.
	let server = HelperServer::blind_evaluate_with(&client, &TEST[..u16::MAX.into()]).unwrap();

	// Failure on too large input.
	let result = client.finalize_with(
		server.public_key(),
		server.evaluation_element(),
		server.proof(),
		&[&TEST],
		&TEST[..u16::MAX.into()],
	);
	assert_eq!(result.unwrap_err(), Error::InputLength);

	// Failure on too large info.
	if let Mode::Poprf = mode {
		let result = client.finalize_with(
			server.public_key(),
			server.evaluation_element(),
			server.proof(),
			&[&TEST],
			&TEST,
		);
		assert_eq!(result.unwrap_err(), Error::InfoLength);
	}

	// Success on maximum length of input and info.
	let _ = client
		.finalize_with(
			server.public_key(),
			server.evaluation_element(),
			server.proof(),
			&[&TEST[..u16::MAX.into()]],
			&TEST[..u16::MAX.into()],
		)
		.unwrap();

	// Failure on too large input.
	let result = server.evaluate_with(server.state(), &[&TEST], &TEST[..u16::MAX.into()]);
	assert_eq!(result.unwrap_err(), Error::InputLength);

	// Failure on too large info.
	if let Mode::Poprf = mode {
		let result = server.evaluate_with(server.state(), &[&TEST], &TEST);
		assert_eq!(result.unwrap_err(), Error::InfoLength);
	}

	// Success on maximum length of input and info.
	let _ = server
		.evaluate_with(
			server.state(),
			&[&TEST[..u16::MAX.into()]],
			&TEST[..u16::MAX.into()],
		)
		.unwrap();
}

test_ciphersuites!(batch, Voprf);
test_ciphersuites!(batch, Poprf);

/// Tests correct failure on invalid `input` and `info` length when using
/// batching methods.
fn batch<CS: CipherSuite>(mode: Mode) {
	let clients = HelperClient::<CS>::batch_with(mode, 1, &[&TEST[..u16::MAX.into()]]).unwrap();

	// Failure on too large info.
	if let Mode::Poprf = mode {
		let result = HelperServer::prepare_with(mode, clients.blinded_elements().iter(), &TEST);
		assert_eq!(result.unwrap_err(), Error::InfoLength);
	}

	// Success on maximum length of info.
	let prepared = HelperServer::prepare_with(
		mode,
		clients.blinded_elements().iter(),
		&TEST[..u16::MAX.into()],
	)
	.unwrap();

	#[cfg(feature = "alloc")]
	if let Mode::Poprf = mode {
		// Failure on too large info.
		let result = prepared.batch_with(clients.blinded_elements(), &TEST);
		assert_eq!(result.unwrap_err(), Error::InfoLength);

		// Success on maximum length of info.
		let _ = prepared
			.batch_with(clients.blinded_elements(), &TEST[..u16::MAX.into()])
			.unwrap();
	}

	let server = prepared.finish(&clients);

	// Failure on too large input.
	let result = clients.finalize_with(
		..,
		&server,
		iter::once::<&[&[u8]]>(&[&TEST]),
		server.evaluation_elements(),
		&TEST[..u16::MAX.into()],
	);
	assert_eq!(result.unwrap_err(), Error::InputLength);

	// Failure on too large info.
	if let Mode::Poprf = mode {
		let result = clients.finalize_with(
			..,
			&server,
			iter::once::<&[&[u8]]>(&[&TEST]),
			server.evaluation_elements(),
			&TEST,
		);
		assert_eq!(result, Err(Error::InfoLength));
	}

	// Success on maximum length of input and info.
	let _ = clients
		.finalize_with(
			..,
			&server,
			iter::once::<&[&[u8]]>(&[&TEST[..u16::MAX.into()]]),
			server.evaluation_elements(),
			&TEST[..u16::MAX.into()],
		)
		.unwrap();

	// Failure on too large input.
	let result = server.evaluate_with(server.state(), &[&TEST], &TEST[..u16::MAX.into()]);
	assert_eq!(result.unwrap_err(), Error::InputLength);

	// Failure on too large info.
	if let Mode::Poprf = mode {
		let result = server.evaluate_with(server.state(), &[&TEST], &TEST);
		assert_eq!(result.unwrap_err(), Error::InfoLength);
	}

	// Success on maximum length of input and info.
	let _ = server
		.evaluate_with(
			server.state(),
			&[&TEST[..u16::MAX.into()]],
			&TEST[..u16::MAX.into()],
		)
		.unwrap();
}
