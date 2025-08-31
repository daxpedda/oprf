//! Utility functions.

use core::array;
use core::ops::Add;

use digest::Update;
use hybrid_array::typenum::{Const, Sum, ToUInt, U};
use hybrid_array::{Array, ArrayN, ArraySize, AssocArraySize};

/// Concat fixed-sized arrays.
pub(crate) trait Concat<const L1: usize, T>
where
	Const<L1>: ToUInt,
	U<L1>: ArraySize,
{
	/// Returns the concatenation of both fixed-sized arrays.
	fn concat<const L2: usize>(
		self,
		other: [T; L2],
	) -> <Sum<U<L1>, <[T; L2] as AssocArraySize>::Size> as ArraySize>::ArrayType<T>
	where
		[T; L2]: AssocArraySize + Into<ArrayN<T, L2>>,
		U<L1>: Add<<[T; L2] as AssocArraySize>::Size>,
		<[T; L2] as AssocArraySize>::Size: ArraySize,
		Sum<U<L1>, <[T; L2] as AssocArraySize>::Size>: ArraySize;
}

impl<const L1: usize, T> Concat<L1, T> for [T; L1]
where
	Const<L1>: ToUInt,
	U<L1>: ArraySize,
	Self: Into<Array<T, U<L1>>>,
{
	fn concat<const L2: usize>(
		self,
		other: [T; L2],
	) -> <Sum<U<L1>, <[T; L2] as AssocArraySize>::Size> as ArraySize>::ArrayType<T>
	where
		[T; L2]: AssocArraySize + Into<ArrayN<T, L2>>,
		U<L1>: Add<<[T; L2] as AssocArraySize>::Size>,
		<[T; L2] as AssocArraySize>::Size: ArraySize,
		Sum<U<L1>, <[T; L2] as AssocArraySize>::Size>: ArraySize,
	{
		self.into().concat(other.into()).into()
	}
}

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

/// [`Update`] taking [`Iterator`]s.
#[expect(single_use_lifetimes, reason = "false-positive")]
pub(crate) trait UpdateIter {
	/// Equivalent of [`Update::chain()`] taking an [`Iterator`] of byte slices.
	fn chain_iter<'slice>(self, iter: impl Iterator<Item = &'slice [u8]>) -> Self;
}

#[expect(single_use_lifetimes, reason = "false-positive")]
impl<T: Update> UpdateIter for T {
	fn chain_iter<'slice>(self, iter: impl Iterator<Item = &'slice [u8]>) -> Self {
		let mut this = self;

		for bytes in iter {
			this = this.chain(bytes);
		}

		this
	}
}

/// [`I2OSP`](https://datatracker.ietf.org/doc/html/rfc8017#section-4.1) implementation directly on types.
pub(crate) trait I2osp {
	/// [`I2OSP(self, 2)`](https://datatracker.ietf.org/doc/html/rfc8017#section-4.1).
	fn i2osp(self) -> [u8; 2];
}

impl I2osp for u16 {
	fn i2osp(self) -> [u8; 2] {
		self.to_be_bytes()
	}
}

/// [`I2OSP`](https://datatracker.ietf.org/doc/html/rfc8017#section-4.1) implementation directly on types.
pub(crate) trait I2ospLength {
	/// [`I2OSP(length, 2)`](https://datatracker.ietf.org/doc/html/rfc8017#section-4.1)
	/// where `length` is the number of bytes of the given slice(s).
	fn i2osp_length(&self) -> Option<[u8; 2]>;
}

impl I2ospLength for &[u8] {
	fn i2osp_length(&self) -> Option<[u8; 2]> {
		u16::try_from(self.len()).map(u16::i2osp).ok()
	}
}

impl I2ospLength for &[&[u8]] {
	fn i2osp_length(&self) -> Option<[u8; 2]> {
		u16::try_from(self.iter().map(|slice| slice.len()).sum::<usize>())
			.map(u16::i2osp)
			.ok()
	}
}

impl<const L: usize> I2ospLength for [&[u8]; L] {
	fn i2osp_length(&self) -> Option<[u8; 2]> {
		self.as_slice().i2osp_length()
	}
}
