#![allow(clippy::len_without_is_empty)]

use core::convert::TryInto;
use core::ops::Range;
use core::{mem, result};

use crate::pod::{from_bytes, slice_from_bytes, Pod};

type Result<T> = result::Result<T, ()>;

/// A trait for reading references to `Pod` types from a block of data.
///
/// This allows parsers to handle both of these cases:
/// - the block of data exists in memory, and it is desirable
///   to use references to this block instead of copying it,
/// - the block of data exists in storage, and it is desirable
///   to read on demand to minimize I/O and memory usage.
///
/// The methods accept `self` by value because `Self` is expected to behave
/// similar to a reference: it may be a reference with a lifetime of `'a`,
/// or it may be a wrapper of a reference.
///
/// The `Clone` and `Copy` bounds are for convenience, and since `Self` is
/// expected to be similar to a reference, these are easily satisfied.
///
/// Object file parsers typically use offsets to locate the structures
/// in the block, and will most commonly use the `*_at` methods to
/// read a structure at a known offset.
///
/// Occasionally file parsers will need to treat the block as a stream,
/// and so convenience methods are provided that update an offset with
/// the size that was read.
//
// An alternative would be for methods to accept `&mut self` and use a
// `seek` method instead of the `offset` parameters, but this is less
// convenient for implementers.
pub trait ReadRef<'a>: Clone + Copy {
    /// The total size of the block of data.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn len(self) -> Result<u64>;

    /// Get a reference to a `u8` slice at the given offset.
    ///
    /// Returns an error if offset or size are out of bounds.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn read_bytes_at(self, offset: u64, size: u64) -> Result<&'a [u8]>;

    /// Get a reference to a delimited `u8` slice which starts at range.start.
    ///
    /// Does not include the delimiter.
    ///
    /// Returns an error if the range is out of bounds or the delimiter is
    /// not found in the range.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn read_bytes_at_until(self, range: Range<u64>, delimiter: u8) -> Result<&'a [u8]>;

    /// Get a reference to a `u8` slice at the given offset, and update the offset.
    ///
    /// Returns an error if offset or size are out of bounds.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn read_bytes(self, offset: &mut u64, size: u64) -> Result<&'a [u8]> {
        let bytes = self.read_bytes_at(*offset, size)?;
        *offset = offset.wrapping_add(size);
        Ok(bytes)
    }

    /// Get a reference to a `Pod` type at the given offset, and update the offset.
    ///
    /// Returns an error if offset or size are out of bounds.
    ///
    /// The default implementation uses `read_bytes`, and returns an error if
    /// `read_bytes` does not return bytes with the correct alignment for `T`.
    /// Implementors may want to provide their own implementation that ensures
    /// the alignment can be satisified. Alternatively, only use this method with
    /// types that do not need alignment (see the `unaligned` feature of this crate).
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn read<T: Pod>(self, offset: &mut u64) -> Result<&'a T> {
        let size = mem::size_of::<T>().try_into().map_err(|_| ())?;
        let bytes = self.read_bytes(offset, size)?;
        let (t, _) = from_bytes(bytes)?;
        Ok(t)
    }

    /// Get a reference to a `Pod` type at the given offset.
    ///
    /// Returns an error if offset or size are out of bounds.
    ///
    /// Also see the `read` method for information regarding alignment of `T`.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn read_at<T: Pod>(self, mut offset: u64) -> Result<&'a T> {
        self.read(&mut offset)
    }

    /// Get a reference to a slice of a `Pod` type at the given offset, and update the offset.
    ///
    /// Returns an error if offset or size are out of bounds.
    ///
    /// Also see the `read` method for information regarding alignment of `T`.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn read_slice<T: Pod>(self, offset: &mut u64, count: usize) -> Result<&'a [T]> {
        let size = count
            .checked_mul(mem::size_of::<T>())
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?;
        let bytes = self.read_bytes(offset, size)?;
        let (t, _) = slice_from_bytes(bytes, count)?;
        Ok(t)
    }

    /// Get a reference to a slice of a `Pod` type at the given offset.
    ///
    /// Returns an error if offset or size are out of bounds.
    ///
    /// Also see the `read` method for information regarding alignment of `T`.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn read_slice_at<T: Pod>(self, mut offset: u64, count: usize) -> Result<&'a [T]> {
        self.read_slice(&mut offset, count)
    }
}

impl<'a> ReadRef<'a> for &'a [u8] {
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn len(self) -> Result<u64> {
        self.len().try_into().map_err(|_| ())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn read_bytes_at(self, offset: u64, size: u64) -> Result<&'a [u8]> {
        let offset: usize = offset.try_into().map_err(|_| ())?;
        let size: usize = size.try_into().map_err(|_| ())?;
        self.get(offset..).ok_or(())?.get(..size).ok_or(())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn read_bytes_at_until(self, range: Range<u64>, delimiter: u8) -> Result<&'a [u8]> {
        let start: usize = range.start.try_into().map_err(|_| ())?;
        let end: usize = range.end.try_into().map_err(|_| ())?;
        let bytes = self.get(start..end).ok_or(())?;
        match memchr::memchr(delimiter, bytes) {
            Some(len) => {
                // This will never fail.
                bytes.get(..len).ok_or(())
            }
            None => Err(()),
        }
    }
}
