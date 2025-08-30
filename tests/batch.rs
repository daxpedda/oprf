//! Tests for [`Error::Batch`] cases.

#![cfg(test)]
#![expect(
	clippy::cargo_common_metadata,
	clippy::indexing_slicing,
	reason = "tests"
)]

#[cfg(feature = "alloc")]
use std::iter;

use oprf::Error;
use oprf::cipher_suite::CipherSuite;
use oprf::common::Mode;
use oprf_test::{CommonClient, CommonServer, INFO, test_ciphersuites};
#[cfg(feature = "alloc")]
use oprf_test::{INPUT, MockCs};

test_ciphersuites!(empty, Voprf);
test_ciphersuites!(empty, Poprf);

/// Tests correct failure on empty iterators when using batching methods.
fn empty<CS: CipherSuite>(mode: Mode) {
	let clients = CommonClient::<CS>::batch::<1>(mode);

	// Failure on zero blinded elements.
	if let Mode::Voprf | Mode::Poprf = mode {
		let result = CommonServer::<CS>::batch_with::<0>(mode, None, &[], None, INFO);
		assert_eq!(result.unwrap_err(), Error::Batch);
	}

	let server = CommonServer::<CS>::batch::<1>(&clients);

	// Failure on equal but zero elements for all parameters.
	let result = clients.finalize_with::<0>(server.public_key(), &[], &[], server.proof(), INFO);
	assert_eq!(result.unwrap_err(), Error::Batch);

	#[cfg(feature = "alloc")]
	{
		// Failure on zero clients with `alloc`.
		let result = clients.finalize_alloc_with(
			..0,
			server.public_key(),
			iter::once(INPUT),
			server.evaluation_elements().iter(),
			server.proof(),
			INFO,
		);
		assert_eq!(result.unwrap_err(), Error::Batch);

		// Failure on zero inputs with `alloc`.
		let result = clients.finalize_alloc_with(
			..,
			server.public_key(),
			iter::empty(),
			server.evaluation_elements().iter(),
			server.proof(),
			INFO,
		);
		assert_eq!(result.unwrap_err(), Error::Batch);

		// Failure on zero evaluation elements with `alloc`.
		let result = clients.finalize_alloc_with(
			..,
			server.public_key(),
			iter::once(INPUT),
			iter::empty(),
			server.proof(),
			INFO,
		);
		assert_eq!(result.unwrap_err(), Error::Batch);

		// Failure on equal but zero elements for all parameters with `alloc`.
		let result = clients.finalize_alloc_with(
			..0,
			server.public_key(),
			iter::empty(),
			iter::empty(),
			server.proof(),
			INFO,
		);
		assert_eq!(result.unwrap_err(), Error::Batch);
	}
}

#[cfg(feature = "alloc")]
test_ciphersuites!(unequal, Mode);

/// Tests correct failure on iterators with unequal length when using batching
/// methods.
// Not possible to pass unequal parameters to fixed array API.
#[cfg(feature = "alloc")]
fn unequal<CS: CipherSuite>(mode: Mode) {
	let clients = CommonClient::<CS>::batch::<2>(mode);
	let server = CommonServer::<CS>::batch::<2>(&clients);

	// Failure on unequal clients.
	let result = clients.finalize_alloc_with(
		..1,
		server.public_key(),
		iter::repeat_n(INPUT, 2),
		server.evaluation_elements().iter(),
		server.proof(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on unequal inputs.
	let result = clients.finalize_alloc_with(
		..,
		server.public_key(),
		iter::once(INPUT),
		server.evaluation_elements().iter(),
		server.proof(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on unequal evaluation elements.
	let result = clients.finalize_alloc_with(
		..,
		server.public_key(),
		iter::repeat_n(INPUT, 2),
		iter::once(&server.evaluation_elements()[0]),
		server.proof(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on unequal clients and inputs.
	let result = clients.finalize_alloc_with(
		..1,
		server.public_key(),
		iter::once(INPUT),
		server.evaluation_elements().iter(),
		server.proof(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on unequal clients and evaluation elements.
	let result = clients.finalize_alloc_with(
		..1,
		server.public_key(),
		iter::repeat_n(INPUT, 2),
		iter::once(&server.evaluation_elements()[0]),
		server.proof(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Batch);
}

#[test]
#[cfg(feature = "alloc")]
fn max_voprf() {
	max(Mode::Voprf);
}

#[test]
#[cfg(feature = "alloc")]
fn max_poprf() {
	max(Mode::Poprf);
}

/// Tests correct failure on iterators that are too big and success on iterators
/// with the maximum size when using batching methods.
// `hybrid-array` doesn't support sized this big.
#[cfg(feature = "alloc")]
fn max(mode: Mode) {
	let clients = CommonClient::<MockCs>::batch_clone(mode, usize::from(u16::MAX) + 1);

	// Failure on overflowing blinded elements with `alloc`.
	let result = CommonServer::batch_alloc_with(mode, None, clients.blinded_elements(), None, INFO);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Success on maximum number of elements.
	let mut server = CommonServer::batch_alloc_with(
		mode,
		None,
		&clients.blinded_elements()[..u16::MAX.into()],
		None,
		INFO,
	)
	.unwrap();
	server.push(server.evaluation_elements()[0].clone());

	// Failure on overflowing clients.
	let result = clients.finalize_alloc_with(
		..,
		server.public_key(),
		iter::repeat_n(INPUT, u16::MAX.into()),
		server.evaluation_elements()[..u16::MAX.into()].iter(),
		server.proof(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on overflowing inputs.
	let result = clients.finalize_alloc_with(
		..u16::MAX.into(),
		server.public_key(),
		iter::repeat_n(INPUT, usize::from(u16::MAX) + 1),
		server.evaluation_elements()[..u16::MAX.into()].iter(),
		server.proof(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on unequal overflowing elements.
	let result = clients.finalize_alloc_with(
		..u16::MAX.into(),
		server.public_key(),
		iter::repeat_n(INPUT, u16::MAX.into()),
		server.evaluation_elements().iter(),
		server.proof(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on overflowing elements for all parameters.
	let result = clients.finalize_alloc_with(
		..,
		server.public_key(),
		iter::repeat_n(INPUT, usize::from(u16::MAX) + 1),
		server.evaluation_elements().iter(),
		server.proof(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Success on maximum number of elements for all parameters.
	let outputs = clients
		.finalize_alloc_with(
			..u16::MAX.into(),
			server.public_key(),
			iter::repeat_n(INPUT, u16::MAX.into()),
			server.evaluation_elements()[..u16::MAX.into()].iter(),
			server.proof(),
			INFO,
		)
		.unwrap();
	assert_eq!(outputs.len(), usize::from(u16::MAX));
}
