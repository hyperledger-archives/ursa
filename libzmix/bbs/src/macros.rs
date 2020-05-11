macro_rules! slice_to_elem {
    ($data:expr, $elem:ident, $compressed:expr) => {{
        use pairing_plus::{bls12_381::$elem, serdes::SerDes};
        $elem::deserialize($data, $compressed)
    }};
}

macro_rules! from_impl {
    ($name:ident, $type:ident, $size:expr) => {
        impl TryFrom<Vec<u8>> for $name {
            type Error = BBSError;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(value.as_slice())
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = BBSError;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                let mut value = value;
                let inner = $type::deserialize(&mut value, true).map_err(|e| {
                    BBSErrorKind::GeneralError {
                        msg: format!("{:?}", e),
                    }
                })?;
                Ok(Self(inner))
            }
        }

        impl From<[u8; $size]> for $name {
            fn from(data: [u8; $size]) -> Self {
                Self::from(&data)
            }
        }

        impl From<&[u8; $size]> for $name {
            fn from(data: &[u8; $size]) -> Self {
                Self($type::deserialize(&mut data.as_ref(), true).unwrap())
            }
        }

        impl From<$type> for $name {
            fn from(src: $type) -> Self {
                Self(src.clone())
            }
        }

        impl From<&$type> for $name {
            fn from(src: &$type) -> Self {
                Self(src.clone())
            }
        }
    };

    ($name:ident, $type:ident, $comp_size:expr,$uncomp_size:expr) => {
        impl TryFrom<Vec<u8>> for $name {
            type Error = BBSError;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(value.as_slice())
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = BBSError;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                let inner = $type::deserialize(&mut value.as_ref(), value.len() == $comp_size)
                    .map_err(|_| BBSErrorKind::GeneralError {
                        msg: "Invalid bytes".to_string(),
                    })?;
                Ok(Self(inner))
            }
        }

        impl From<[u8; $comp_size]> for $name {
            fn from(data: [u8; $comp_size]) -> Self {
                Self::from(&data)
            }
        }

        impl From<&[u8; $comp_size]> for $name {
            fn from(data: &[u8; $comp_size]) -> Self {
                Self($type::deserialize(&mut data.as_ref(), true).unwrap())
            }
        }

        impl From<[u8; $uncomp_size]> for $name {
            fn from(data: [u8; $uncomp_size]) -> Self {
                Self::from(&data)
            }
        }

        impl From<&[u8; $uncomp_size]> for $name {
            fn from(data: &[u8; $uncomp_size]) -> Self {
                Self($type::deserialize(&mut data.as_ref(), false).unwrap())
            }
        }

        impl From<$type> for $name {
            fn from(src: $type) -> Self {
                Self(src)
            }
        }

        impl From<&$type> for $name {
            fn from(src: &$type) -> Self {
                Self(src.clone())
            }
        }
    };
}

macro_rules! try_from_impl {
    ($name:ident, $error:ident) => {
        impl TryFrom<&[u8]> for $name {
            type Error = $error;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                Self::from_bytes_compressed_form(value)
            }
        }

        impl TryFrom<Vec<u8>> for $name {
            type Error = $error;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                Self::from_bytes_compressed_form(value)
            }
        }
    };
}

macro_rules! display_impl {
    ($name:ident) => {
        impl Display for $name {
            fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
                let bytes = self.to_bytes_uncompressed_form();
                write!(f, "{} {{ {} }}", stringify!($name), hex::encode(&bytes[..]))
            }
        }
    };
}

macro_rules! serdes_impl {
    ($name:ident) => {
        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_bytes(&self.to_bytes_compressed_form()[..])
            }
        }

        impl<'a> Deserialize<'a> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'a>,
            {
                struct DeserializeVisitor;

                impl<'a> Visitor<'a> for DeserializeVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                        formatter.write_str("expected byte array")
                    }

                    fn visit_bytes<E>(self, value: &[u8]) -> Result<$name, E>
                    where
                        E: DError,
                    {
                        $name::try_from(value).map_err(|_| {
                            DError::invalid_value(serde::de::Unexpected::Bytes(value), &self)
                        })
                    }
                }

                deserializer.deserialize_bytes(DeserializeVisitor)
            }
        }
    };
}

macro_rules! to_fixed_length_bytes_impl {
    ($name:ident, $type:ident, $compressed:expr, $uncompressed:expr) => {
        /// Convert to raw bytes compressed form
        pub fn to_bytes_compressed_form(&self) -> [u8; $compressed] {
            let mut o = [0u8; $compressed];
            self.0.serialize(&mut o[..].as_mut(), true).unwrap();
            o
        }

        /// Convert to raw bytes uncompressed form
        pub fn to_bytes_uncompressed_form(&self) -> [u8; $uncompressed] {
            let mut o = [0u8; $uncompressed];
            self.0.serialize(&mut o[..].as_mut(), false).unwrap();
            o
        }
    };
}

macro_rules! hash_elem_impl {
    ($name:ident, $func:expr) => {
        impl HashElem for $name {
            type Output = $name;

            fn hash<I: AsRef<[u8]>>(data: I) -> Self::Output {
                $func(data.as_ref())
            }
        }
    };
}

macro_rules! random_elem_impl {
    ($name:ident, $func:block) => {
        impl RandomElem for $name {
            type Output = $name;

            fn random() -> Self::Output $func
        }
    };
}

macro_rules! as_ref_impl {
    ($name:ident, $inner:ident) => {
        impl AsRef<$inner> for $name {
            fn as_ref(&self) -> &$inner {
                &self.0
            }
        }
    };
}
