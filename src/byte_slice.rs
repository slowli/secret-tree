//! Operations on byte slices.

use core::{mem, slice};

/// Converts a type to a mutable byte slice. This is used within the crate to fill
/// secret values with the RNG output.
///
/// This trait is implemented for numeric types (`u8`, `i8`, ..., `u128`, `i128`), slices
/// of these types, and arrays of small sizes (1..=64).
// This is an ad-hoc replacement for the eponymous trait from `rand` v0.7, which was removed
// in `rand` v0.8.
pub trait AsByteSliceMut {
    /// Performs conversion to a mutable byte slice.
    fn as_byte_slice_mut(&mut self) -> &mut [u8];

    /// Converts values within this type to the little-endian byte order.
    ///
    /// This method is called after filling bytes to achieve uniform behavior across
    /// big-endian and little-endian platforms.
    fn convert_to_le(&mut self);
}

impl AsByteSliceMut for [u8] {
    fn as_byte_slice_mut(&mut self) -> &mut [u8] {
        self
    }

    fn convert_to_le(&mut self) {
        // No-op.
    }
}

macro_rules! impl_as_byte_slice {
    ($ty:ty) => {
        impl AsByteSliceMut for [$ty] {
            fn as_byte_slice_mut(&mut self) -> &mut [u8] {
                if self.is_empty() {
                    // Empty slices need special handling since `from_raw_parts_mut` doesn't accept
                    // an empty pointer.
                    &mut []
                } else {
                    let byte_len = self.len() * mem::size_of::<$ty>();
                    let data = self as *mut [$ty] as *mut u8;
                    unsafe { slice::from_raw_parts_mut(data, byte_len) }
                }
            }

            fn convert_to_le(&mut self) {
                for element in self {
                    *element = element.to_le();
                }
            }
        }
    };

    ($($t:ty,)*) => {
        $(impl_as_byte_slice!($t);)*
    };
}

impl_as_byte_slice!(i8, u16, i16, u32, i32, u64, i64, u128, i128,);

impl<T> AsByteSliceMut for T
where
    [T]: AsByteSliceMut,
{
    fn as_byte_slice_mut(&mut self) -> &mut [u8] {
        AsByteSliceMut::as_byte_slice_mut(slice::from_mut(self))
    }

    fn convert_to_le(&mut self) {
        AsByteSliceMut::convert_to_le(slice::from_mut(self));
    }
}

macro_rules! impl_as_byte_slice_array {
    ($($n:expr,)*) => {
        $(
        impl<T> AsByteSliceMut for [T; $n]
        where
            [T]: AsByteSliceMut,
        {
            fn as_byte_slice_mut(&mut self) -> &mut [u8] {
                AsByteSliceMut::as_byte_slice_mut(&mut self[..])
            }

            fn convert_to_le(&mut self) {
                AsByteSliceMut::convert_to_le(&mut self[..])
            }
        }
        )*
    };
}

impl_as_byte_slice_array!(
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
);
