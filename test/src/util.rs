//! Utility functions.

use std::array;

/// [`Iterator::collect()`] for fixed-sized arrays.
pub(crate) trait CollectArray<T> {
	/// Equivalent of [`Iterator::collect()`] returning a fixed-sized array.
	fn collect_array<const N: usize>(self) -> [T; N];
}

impl<I: Iterator<Item = T>, T> CollectArray<T> for I {
	fn collect_array<const N: usize>(mut self) -> [T; N] {
		let array =
			array::from_fn(|_| self.next().expect("`Iterator` should be the expected size"));
		assert!(
			self.next().is_none(),
			"`Iterator` should be the expected size"
		);

		array
	}
}
