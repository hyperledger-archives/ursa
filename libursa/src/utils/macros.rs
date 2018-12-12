macro_rules! array_copy {
    ($src:expr, $dst:expr) => {
        for i in 0..$dst.len() {
            $dst[i] = $src[i];
        }
    };
    ($src:expr, $dst:expr, $offset:expr, $length:expr) => {
        for i in 0..$length {
            $dst[i + $offset] = $src[i]
        }
    };
    ($src:expr, $src_offset:expr, $dst:expr, $dst_offset:expr, $length:expr) => {
        for i in 0..$length {
            $dst[i + $dst_offset] = $src[i + $src_offset]
        }
    }
}

macro_rules! impl_bytearray {
    ($thing:ident) => {
        impl $thing {
            #[inline]
            /// Converts the object to a raw pointer for FFI interfacing
            pub fn as_ptr(&self) -> *const u8 {
                self.0.as_slice().as_ptr()
            }

            #[inline]
            /// Converts the object to a mutable raw pointer for FFI interfacing
            pub fn as_mut_ptr(&mut self) -> *mut u8 {
                self.0.as_mut_slice().as_mut_ptr()
            }

            #[inline]
            /// Returns the length of the object as an array
            pub fn len(&self) -> usize { self.0.len() }
        }

        impl PartialEq for $thing {
            #[inline]
            fn eq(&self, other: &$thing) -> bool {
                self.0 == other.0
            }
        }

        impl Eq for $thing {}

        impl Clone for $thing {
            #[inline]
            fn clone(&self) -> $thing {
                $thing(self.0.clone())
            }
        }

        impl ::std::ops::Index<usize> for $thing {
            type Output = u8;

            #[inline]
            fn index(&self, index: usize) -> &u8 {
               &self.0[index]
            }
        }

        impl ::std::ops::Index<::std::ops::Range<usize>> for $thing {
            type Output = [u8];

            #[inline]
            fn index(&self, index: ::std::ops::Range<usize>) -> &[u8] {
                &self.0[index]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeTo<usize>> for $thing {
            type Output = [u8];

            #[inline]
            fn index(&self, index: ::std::ops::RangeTo<usize>) -> &[u8] {
                &self.0[index]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeFrom<usize>> for $thing {
            type Output = [u8];

            #[inline]
            fn index(&self, index: ::std::ops::RangeFrom<usize>) -> &[u8] {
                &self.0[index]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeFull> for $thing {
            type Output = [u8];

            #[inline]
            fn index(&self, _: ::std::ops::RangeFull) -> &[u8] {
                self.0.as_slice()
            }
        }
        impl ::std::fmt::Display for $thing {
            fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(formatter, "{} {{ {} }}", stringify!($thing), bin2hex(&self.0[..]))
            }
        }

        impl ::std::fmt::Debug for $thing {
            fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(formatter, "{} {{ {} }}", stringify!($thing), bin2hex(&self.0[..]))
            }
        }
    }
}
