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
                let inner = $type::deserialize(&mut value, true)?;
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

        impl From<Box<[u8]>> for $name {
            fn from(data: Box<[u8]>) -> $name {
                let data = Vec::from(data);
                match $name::try_from(data) {
                    Ok(t) => t,
                    Err(_) => $name::default(),
                }
            }
        }

        impl Into<Box<[u8]>> for $name {
            fn into(self) -> Box<[u8]> {
                self.to_bytes_compressed_form().to_vec().into()
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
                let inner = $type::deserialize(&mut value.as_ref(), value.len() == $comp_size)?;
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

        impl From<Box<[u8]>> for $name {
            fn from(data: Box<[u8]>) -> $name {
                let data = Vec::from(data);
                match $name::try_from(data) {
                    Ok(t) => t,
                    Err(_) => $name::default(),
                }
            }
        }

        impl Into<Box<[u8]>> for $name {
            fn into(self) -> Box<[u8]> {
                self.to_bytes_compressed_form().to_vec().into()
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

        impl From<Box<[u8]>> for $name {
            fn from(data: Box<[u8]>) -> $name {
                let data = Vec::from(data);
                match $name::try_from(data) {
                    Ok(t) => t,
                    Err(_) => $name::default(),
                }
            }
        }

        impl Into<Box<[u8]>> for $name {
            fn into(self) -> Box<[u8]> {
                self.to_bytes_compressed_form().into()
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

macro_rules! default_zero_impl {
    ($name:ident, $type:ident) => {
        impl Default for $name {
            fn default() -> Self {
                Self($type::zero())
            }
        }
    };
}

#[cfg(feature = "wasm")]
macro_rules! wasm_slice_impl {
    ($name:ident) => {
        impl wasm_bindgen::convert::IntoWasmAbi for $name {
            type Abi = wasm_bindgen::convert::WasmSlice;

            fn into_abi(self) -> Self::Abi {
                let r: Box<[u8]> = self.to_bytes_compressed_form().to_vec().into();
                r.into_abi()
            }
        }

        impl wasm_bindgen::convert::FromWasmAbi for $name {
            type Abi = wasm_bindgen::convert::WasmSlice;

            #[inline]
            unsafe fn from_abi(js: wasm_bindgen::convert::WasmSlice) -> Self {
                let ptr = <*mut u8>::from_abi(js.ptr);
                let len = js.len as usize;
                let r = Vec::from_raw_parts(ptr, len, len).into_boxed_slice();
                match Self::try_from(r) {
                    Ok(d) => d,
                    Err(_) => Self::default(),
                }
            }
        }

        impl wasm_bindgen::convert::OptionIntoWasmAbi for $name {
            fn none() -> wasm_bindgen::convert::WasmSlice {
                wasm_bindgen::convert::WasmSlice { ptr: 0, len: 0 }
            }
        }

        impl wasm_bindgen::convert::OptionFromWasmAbi for $name {
            fn is_none(slice: &wasm_bindgen::convert::WasmSlice) -> bool {
                slice.ptr == 0
            }
        }

        impl wasm_bindgen::describe::WasmDescribe for $name {
            fn describe() {
                wasm_bindgen::describe::inform(wasm_bindgen::describe::SLICE)
            }
        }

        impl TryFrom<JsValue> for $name {
            type Error = BBSError;

            fn try_from(value: JsValue) -> Result<Self, Self::Error> {
                serde_wasm_bindgen::from_value(value).map_err(|e| {
                    BBSError::from(BBSErrorKind::GeneralError {
                        msg: format!("{:?}", e),
                    })
                })
            }
        }
    };
}
