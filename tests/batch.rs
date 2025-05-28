//! Tests for [`Error::Batch`] cases.

#![cfg(test)]
#![expect(
	clippy::cargo_common_metadata,
	clippy::indexing_slicing,
	reason = "tests"
)]

mod util;

use std::{array, iter};

use oprf::Error;
use oprf::ciphersuite::CipherSuite;
use oprf::common::Mode;
use util::{HelperClient, HelperServer, INFO, INPUT, MockCs};

test_ciphersuites!(empty, Voprf);
test_ciphersuites!(empty, Poprf);

/// Tests correct failure on empty iterators when using batching methods.
fn empty<CS: CipherSuite>(mode: Mode) {
	let clients = HelperClient::<CS>::batch(mode, 1);

	// Failure on zero blinded elements.
	let result = HelperServer::<CS>::prepare_with(mode, iter::empty(), INFO);
	assert_eq!(result.unwrap_err(), Error::Batch);

	let prepared = HelperServer::prepare(&clients);

	// Failure on zero blinded elements.
	let result = prepared.finish_with(
		prepared.state(),
		iter::empty(),
		prepared.prepared_elements(),
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on zero prepared elements.
	let result = prepared.finish_with(prepared.state(), clients.blinded_elements().iter(), &[]);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on equal but zero elements for all parameters.
	let result = prepared.finish_with(prepared.state(), iter::empty(), &[]);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on zero blinded elements with `alloc`.
	#[cfg(feature = "alloc")]
	assert_eq!(prepared.batch(&[]).unwrap_err(), Error::Batch);

	let server = prepared.finish(&clients);

	// Failure on zero clients.
	let result = clients.finalize_with(
		..0,
		&server,
		iter::once(INPUT),
		server.evaluation_elements(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on zero inputs.
	let result = clients.finalize_with(
		..,
		&server,
		iter::empty(),
		server.evaluation_elements(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on zero evaluation elements.
	let result = clients.finalize_with(.., &server, iter::once(INPUT), &[], INFO);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on equal but zero elements for all parameters.
	let result = clients.finalize_with(..0, &server, iter::empty(), &[], INFO);
	assert_eq!(result.unwrap_err(), Error::Batch);
}

test_ciphersuites!(unequal, Voprf);
test_ciphersuites!(unequal, Poprf);

/// Tests correct failure on iterators with unequal length when using batching
/// methods.
fn unequal<CS: CipherSuite>(mode: Mode) {
	let clients = HelperClient::<CS>::batch(mode, 2);
	let prepared = HelperServer::prepare(&clients);

	// Failure on unequal blinded elements.
	let result = prepared.finish_with(
		prepared.state(),
		iter::once(&clients.blinded_elements()[0]),
		prepared.prepared_elements(),
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on unequal prepared elements.
	let result = prepared.finish_with(
		prepared.state(),
		clients.blinded_elements().iter(),
		array::from_ref(&prepared.prepared_elements()[0]),
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	let server = prepared.finish(&clients);

	// Failure on unequal clients.
	let result = clients.finalize_with(
		..1,
		&server,
		iter::repeat_n(INPUT, 2),
		server.evaluation_elements(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on unequal inputs.
	let result = clients.finalize_with(
		..,
		&server,
		iter::once(INPUT),
		server.evaluation_elements(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on unequal evaluation elements.
	let result = clients.finalize_with(
		..,
		&server,
		iter::repeat_n(INPUT, 2),
		array::from_ref(&server.evaluation_elements()[0]),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Batch);
}

#[test]
fn max_voprf() {
	max(Mode::Voprf);
}

#[test]
fn max_poprf() {
	max(Mode::Poprf);
}

/// Tests correct failure on iterators that are too big and success on iterators
/// with the maximum size when using batching methods.
fn max(mode: Mode) {
	let clients = HelperClient::<MockCs>::batch_clone(mode, usize::from(u16::MAX) + 1);

	// Failure on overflowing blinded elements.
	let result = HelperServer::prepare_with(mode, clients.blinded_elements().iter(), INFO);
	assert_eq!(result.unwrap_err(), Error::Batch);

	let mut prepared = HelperServer::prepare_with(
		mode,
		clients.blinded_elements()[..u16::MAX.into()].iter(),
		INFO,
	)
	.unwrap();
	prepared.push(prepared.prepared_elements()[0].clone());

	// Failure on overflowing blinded elements.
	let result = prepared.finish_with(
		prepared.state(),
		clients.blinded_elements().iter(),
		&prepared.prepared_elements()[..u16::MAX.into()],
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on overflowing prepared elements.
	let result = prepared.finish_with(
		prepared.state(),
		clients.blinded_elements()[..u16::MAX.into()].iter(),
		prepared.prepared_elements(),
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on overflowing elements for all parameters.
	let result = prepared.finish_with(
		prepared.state(),
		clients.blinded_elements().iter(),
		prepared.prepared_elements(),
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on overflowing blinded elements with `alloc`.
	#[cfg(feature = "alloc")]
	assert_eq!(
		prepared.batch(clients.blinded_elements()).unwrap_err(),
		Error::Batch
	);

	let mut server = prepared
		.finish_with(
			prepared.state(),
			clients.blinded_elements()[..u16::MAX.into()].iter(),
			&prepared.prepared_elements()[..u16::MAX.into()],
		)
		.unwrap();
	server.push(server.evaluation_elements()[0].clone());

	// Failure on overflowing clients.
	let result = clients.finalize_with(
		..,
		&server,
		iter::repeat_n(INPUT, u16::MAX.into()),
		&server.evaluation_elements()[..u16::MAX.into()],
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on overflowing inputs.
	let result = clients.finalize_with(
		..u16::MAX.into(),
		&server,
		iter::repeat_n(INPUT, usize::from(u16::MAX) + 1),
		&server.evaluation_elements()[..u16::MAX.into()],
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on unequal overflowing elements.
	let result = clients.finalize_with(
		..u16::MAX.into(),
		&server,
		iter::repeat_n(INPUT, u16::MAX.into()),
		server.evaluation_elements(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Failure on overflowing elements for all parameters.
	let result = clients.finalize_with(
		..,
		&server,
		iter::repeat_n(INPUT, usize::from(u16::MAX) + 1),
		server.evaluation_elements(),
		INFO,
	);
	assert_eq!(result.unwrap_err(), Error::Batch);

	// Success on maximum number of elements for all parameters.
	let outputs = clients
		.finalize_with(
			..u16::MAX.into(),
			&server,
			iter::repeat_n(INPUT, u16::MAX.into()),
			&server.evaluation_elements()[..u16::MAX.into()],
			INFO,
		)
		.unwrap();
	assert_eq!(outputs.len(), usize::from(u16::MAX));
}
