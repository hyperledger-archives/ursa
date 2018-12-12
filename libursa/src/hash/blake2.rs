use super::Digest;
use CryptoError;
use blake2b_simd::{Params, State};

macro_rules! impl_hasher {
    ($thing:ident,$size:tt) => {
        impl Digest for $thing {
            #[inline]
            fn new() -> $thing {
                $thing(Params::new()
                       .hash_length($size)
                       .to_state())
            }
            #[inline]
            fn reset(&mut self) {
                self.0 = Params::new()
                         .hash_length($size)
                         .to_state();
            }
            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.0.update(data);
            }
            #[inline]
            fn finalize(&mut self) -> Result<Vec<u8>, CryptoError> {
                Ok(self.0.finalize().as_bytes().to_vec())
            }
        }
    };
}

pub struct Blake2b256(State);
impl_hasher!(Blake2b256, 32);

pub struct Blake2b384(State);
impl_hasher!(Blake2b384, 48);

pub struct Blake2b512(State);
impl_hasher!(Blake2b512, 64);

#[cfg(test)]
mod tests {
    // See https://raw.githubusercontent.com/BLAKE2/BLAKE2/master/testvectors/blake2b-kat.txt
    use super::*;
    use encoding::hex::hex2bin;

    #[test]
    fn blake2b_256() {
        let mut hasher = Blake2b256::new();
        let message = b"";
        let expected = hex2bin("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8").unwrap();

        hasher.update(&message[..]);
        let result = hasher.finalize().unwrap();
        assert_eq!(expected.to_vec(), result);

        let mut hasher = Blake2b256::new();
        let message = b"00";
        let expected = hex2bin("cbc63dc2acb86bd8967453ef98fd4f2be2f26d7337a0937958211c128a18b442").unwrap();

        hasher.update(&message[..]);
        let result = hasher.finalize().unwrap();
        assert_eq!(expected.to_vec(), result);

        let mut hasher = Blake2b256::new();
        let message = b"0001";
        let expected = hex2bin("e6a2a7281707b12d5c44315845a63651602dc8e387693161103326263ef64cb2").unwrap();

        hasher.update(&message[..]);
        let result = hasher.finalize().unwrap();
        assert_eq!(expected.to_vec(), result);
    }

    #[test]
    fn blake2b_384() {
        let mut hasher = Blake2b384::new();
        let message = b"";
        let expected = hex2bin("b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100").unwrap();

        hasher.update(&message[..]);
        let result = hasher.finalize().unwrap();
        assert_eq!(expected.to_vec(), result);

        let mut hasher = Blake2b384::new();
        let message = b"00";
        let expected = hex2bin("0604ba2f245f0e2896aace5b03ddfe41beab2e7966929ecf387edc1c85d666233ef280e3caf85b910792851307a7309e").unwrap();

        hasher.update(&message[..]);
        let result = hasher.finalize().unwrap();
        assert_eq!(expected.to_vec(), result);

        let mut hasher = Blake2b384::new();
        let message = b"0001";
        let expected = hex2bin("723f6fe6589ccc1bb9504d280499426d2c448e0765b9ebfe28194e12dad66718109b8176f733625df925194c7e00e594").unwrap();

        hasher.update(&message[..]);
        let result = hasher.finalize().unwrap();
        assert_eq!(expected.to_vec(), result);
    }

    #[test]
    fn blake2b_512() {
        let mut hasher = Blake2b512::new();
        let message = b"";
        let expected = hex2bin("786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce").unwrap();

        hasher.update(&message[..]);
        let result = hasher.finalize().unwrap();
        assert_eq!(expected.to_vec(), result);

        let mut hasher = Blake2b512::new();
        let message = b"00";
        let expected = hex2bin("7a4754f2de4589268c2a2d11914f71a1cf170c3f245e9b0593c27ab27f8d19a962da68e8d7e2d229e52510481ef285a0031ad3ac88f35a586ab6347b1716db02").unwrap();

        hasher.update(&message[..]);
        let result = hasher.finalize().unwrap();
        assert_eq!(expected.to_vec(), result);

        let mut hasher = Blake2b512::new();
        let message = b"0001";
        let expected = hex2bin("b0e209d7640593ad8b8a0260ade998d72dc5a57aaa48a21388f0f54f0472d4d9f7acc936a95d19bbb7f8066c57cd1409cbd43b82a5faa4084017cb83a0dc5313").unwrap();

        hasher.update(&message[..]);
        let result = hasher.finalize().unwrap();
        assert_eq!(expected.to_vec(), result);
    }
}
