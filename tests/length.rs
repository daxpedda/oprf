//! Tests for [`Error::InputLength`] and [`Error::InfoLength`] cases.

#![cfg(test)]
#![expect(
	clippy::cargo_common_metadata,
	clippy::indexing_slicing,
	reason = "tests"
)]

#[cfg(feature = "alloc")]
use std::iter;
use std::sync::LazyLock;

use oprf::Error;
use oprf::cipher_suite::CipherSuite;
use oprf::common::Mode;
use oprf_test::{CommonClient, CommonServer, test_ciphersuites};

static TEST: LazyLock<Vec<u8>> = LazyLock::new(|| vec![0; usize::from(u16::MAX) + 1]);

test_ciphersuites!(basic, Mode);

/// Tests correct failure on invalid `input` and `info` length.
fn basic<Cs: CipherSuite>(mode: Mode) {
	// Failure on too large input.
	let result = CommonClient::<Cs>::blind_with(mode, None, &[&TEST]);
	assert_eq!(result.unwrap_err(), Error::InputLength);

	// Success on maximum length of input.
	let client = CommonClient::<Cs>::blind_with(mode, None, &[&TEST[..u16::MAX.into()]]).unwrap();

	// Failure on too large info.
	if let Mode::Poprf = mode {
		let result = CommonServer::blind_evaluate_with(
			mode,
			None,
			client.blinded_element(),
			None,
			Some(&TEST),
		);
		assert_eq!(result.unwrap_err(), Error::InfoLength);
	}

	// Success on maximum length of info.
	let server = CommonServer::blind_evaluate_with(
		mode,
		None,
		client.blinded_element(),
		None,
		Some(&TEST[..u16::MAX.into()]),
	)
	.unwrap();

	// Failure on too large input.
	let result = client.finalize_with(
		server.public_key(),
		&[&TEST],
		server.evaluation_element(),
		server.proof(),
		Some(&TEST[..u16::MAX.into()]),
	);
	assert_eq!(result.unwrap_err(), Error::InputLength);

	// Failure on too large info.
	if let Mode::Poprf = mode {
		let result = client.finalize_with(
			server.public_key(),
			&[&TEST],
			server.evaluation_element(),
			server.proof(),
			Some(&TEST),
		);
		assert_eq!(result.unwrap_err(), Error::InfoLength);
	}

	// Success on maximum length of input and info.
	let _ = client
		.finalize_with(
			server.public_key(),
			&[&TEST[..u16::MAX.into()]],
			server.evaluation_element(),
			server.proof(),
			Some(&TEST[..u16::MAX.into()]),
		)
		.unwrap();

	// Failure on too large input.
	let result = server.evaluate_with(&[&TEST], Some(&TEST[..u16::MAX.into()]));
	assert_eq!(result.unwrap_err(), Error::InputLength);

	// Failure on too large info.
	if let Mode::Poprf = mode {
		let result = server.evaluate_with(&[&TEST], Some(&TEST));
		assert_eq!(result.unwrap_err(), Error::InfoLength);
	}

	// Success on maximum length of input and info.
	let _ = server
		.evaluate_with(&[&TEST[..u16::MAX.into()]], Some(&TEST[..u16::MAX.into()]))
		.unwrap();
}

test_ciphersuites!(batch, Mode);

/// Tests correct failure on invalid `input` and `info` length when using
/// batching methods.
#[expect(clippy::too_many_lines, reason = "test")]
fn batch<Cs: CipherSuite>(mode: Mode) {
	// Failure on too large input.
	let result = CommonClient::<Cs>::batch_with::<1>(mode, None, &[&[&TEST]]);
	assert_eq!(result.unwrap_err(), Error::InputLength);

	// Failure on too large input with `alloc`.
	#[cfg(feature = "alloc")]
	assert_eq!(
		CommonClient::<Cs>::batch_alloc_with(mode, None, iter::once([TEST.as_slice()].as_slice())),
		Err(Error::InputLength)
	);

	// Success on maximum length of input.
	let clients =
		CommonClient::<Cs>::batch_with::<1>(mode, None, &[&[&TEST[..u16::MAX.into()]]]).unwrap();

	// Success on maximum length of input with `alloc`.
	#[cfg(feature = "alloc")]
	CommonClient::<Cs>::batch_alloc_with(
		mode,
		None,
		iter::once([&TEST[..u16::MAX.into()]].as_slice()),
	)
	.unwrap();

	// Failure on too large info.
	if let Mode::Poprf = mode {
		let result = CommonServer::batch_with::<1>(
			mode,
			None,
			clients.blinded_elements(),
			None,
			Some(&TEST),
		);
		assert_eq!(result.unwrap_err(), Error::InfoLength);
	}

	// Success on maximum length of info.
	let server = CommonServer::batch_with::<1>(
		mode,
		None,
		clients.blinded_elements(),
		None,
		Some(&TEST[..u16::MAX.into()]),
	)
	.unwrap();

	// Failure on too large input.
	let result = clients.finalize_with::<1>(
		server.public_key(),
		&[&[&TEST]],
		server.evaluation_elements(),
		server.proof(),
		Some(&TEST[..u16::MAX.into()]),
	);
	assert_eq!(result.unwrap_err(), Error::InputLength);

	// Failure on too large info.
	if let Mode::Poprf = mode {
		let result = clients.finalize_with::<1>(
			server.public_key(),
			&[&[&TEST]],
			server.evaluation_elements(),
			server.proof(),
			Some(&TEST),
		);
		assert_eq!(result, Err(Error::InfoLength));
	}

	// Success on maximum length of input and info.
	let _ = clients
		.finalize_with::<1>(
			server.public_key(),
			&[&[&TEST[..u16::MAX.into()]]],
			server.evaluation_elements(),
			server.proof(),
			Some(&TEST[..u16::MAX.into()]),
		)
		.unwrap();

	#[cfg(feature = "alloc")]
	{
		// Failure on too large input with `alloc`.
		let result = clients.finalize_alloc_with(
			..,
			server.public_key(),
			iter::once::<&[&[u8]]>(&[&TEST]),
			server.evaluation_elements().iter(),
			server.proof(),
			&TEST[..u16::MAX.into()],
		);
		assert_eq!(result.unwrap_err(), Error::InputLength);

		// Failure on too large info with `alloc`.
		if let Mode::Poprf = mode {
			let result = clients.finalize_alloc_with(
				..,
				server.public_key(),
				iter::once::<&[&[u8]]>(&[&TEST]),
				server.evaluation_elements().iter(),
				server.proof(),
				&TEST,
			);
			assert_eq!(result, Err(Error::InfoLength));
		}

		// Success on maximum length of input and info with `alloc`.
		let _ = clients
			.finalize_alloc_with(
				..,
				server.public_key(),
				iter::once::<&[&[u8]]>(&[&TEST[..u16::MAX.into()]]),
				server.evaluation_elements().iter(),
				server.proof(),
				&TEST[..u16::MAX.into()],
			)
			.unwrap();
	}

	// Failure on too large input.
	let result = server.evaluate_with::<1>(&[&[&TEST]], Some(&TEST[..u16::MAX.into()]));
	assert_eq!(result.unwrap_err(), Error::InputLength);

	// Failure on too large info.
	if let Mode::Poprf = mode {
		let result = server.evaluate_with::<1>(&[&[&TEST]], Some(&TEST));
		assert_eq!(result.unwrap_err(), Error::InfoLength);
	}

	// Success on maximum length of input and info.
	let _ = server
		.evaluate_with::<1>(
			&[&[&TEST[..u16::MAX.into()]]],
			Some(&TEST[..u16::MAX.into()]),
		)
		.unwrap();

	#[cfg(feature = "alloc")]
	{
		// Failure on too large input with `alloc`.
		let result = server.evaluate_alloc_with(&[&[&TEST]], &TEST[..u16::MAX.into()]);
		assert_eq!(result.unwrap_err(), Error::InputLength);

		// Failure on too large info with `alloc`.
		if let Mode::Poprf = mode {
			let result = server.evaluate_alloc_with(&[&[&TEST]], &TEST);
			assert_eq!(result.unwrap_err(), Error::InfoLength);
		}

		// Success on maximum length of input and info with `alloc`.
		let _ = server
			.evaluate_alloc_with(&[&[&TEST[..u16::MAX.into()]]], &TEST[..u16::MAX.into()])
			.unwrap();
	}
}
