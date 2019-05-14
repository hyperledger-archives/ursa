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
            pub fn len(&self) -> usize {
                self.0.len()
            }

            #[inline]
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
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
                write!(
                    formatter,
                    "{} {{ {} }}",
                    stringify!($thing),
                    bin2hex(&self.0[..])
                )
            }
        }

        impl ::std::fmt::Debug for $thing {
            fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(
                    formatter,
                    "{} {{ {} }}",
                    stringify!($thing),
                    bin2hex(&self.0[..])
                )
            }
        }

        impl Zeroize for $thing {
            #[inline]
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }

        impl ::std::ops::Drop for $thing {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }

        #[cfg(feature = "serialization")]
        impl serde::ser::Serialize for $thing {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::ser::Serializer,
            {
                serializer.serialize_newtype_struct(stringify!($thing), &bin2hex(&self.0[..]))
            }
        }

        #[cfg(feature = "serialization")]
        impl<'a> serde::de::Deserialize<'a> for $thing {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: ::serde::de::Deserializer<'a>,
            {
                struct Thingvisitor;

                impl<'a> ::serde::de::Visitor<'a> for Thingvisitor {
                    type Value = $thing;

                    fn expecting(
                        &self,
                        formatter: &mut ::std::fmt::Formatter,
                    ) -> ::std::fmt::Result {
                        write!(formatter, "expected {}", stringify!($thing))
                    }

                    fn visit_str<E>(self, value: &str) -> Result<$thing, E>
                    where
                        E: ::serde::de::Error,
                    {
                        Ok($thing(hex2bin(value).map_err(::serde::de::Error::custom)?))
                    }
                }

                deserializer.deserialize_str(Thingvisitor)
            }
        }
    };
}
