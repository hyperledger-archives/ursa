use super::Digest;
use CryptoError;

use amcl_3::hash256::HASH256;
use amcl_3::hash384::HASH384;
use amcl_3::hash512::HASH512;

macro_rules! impl_hasher {
    ($thing:ident,$wrapped:ident) => {
        impl Digest for $thing {
            #[inline]
            fn new() -> $thing {
                $thing($wrapped::new())
            }
            #[inline]
            fn reset(&mut self) {
                self.0.init()
            }
            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.0.process_array(data)
            }
            #[inline]
            fn finalize(&mut self) -> Result<Vec<u8>, CryptoError> {
                Ok(self.0.hash().to_vec())
            }
        }
    };
}

pub struct Sha256(HASH256);
impl_hasher!(Sha256, HASH256);

pub struct Sha384(HASH384);
impl_hasher!(Sha384, HASH384);

pub struct Sha512(HASH512);
impl_hasher!(Sha512, HASH512);

#[cfg(test)]
mod tests {
    use super::*;
    use encoding::hex::hex2bin;

    #[test]
    fn sha2_256() {
        let mut hasher = Sha256::new();
        // Taken from https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2withchangenotice.pdf
        let message = b"abc";
        let expected = hex2bin("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD").unwrap();

        hasher.update(&message[..]);
        let result = hasher.finalize().unwrap();
        assert_eq!(expected.to_vec(), result);

        let message = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected = hex2bin("248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1").unwrap();

        hasher.update(&message[..]);
        let result = hasher.finalize().unwrap();
        assert_eq!(expected.to_vec(), result);

        let expected = hex2bin("CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0").unwrap();
        for _ in 0..1000000 {
            hasher.update(b"a");
        }
        let result = hasher.finalize().unwrap();
        assert_eq!(expected.to_vec(), result);
    }

    #[test]
    fn sha2_384() {
        let mut hasher = Sha384::new();
        // Taken from https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2withchangenotice.pdf
        let message = b"abc";
        let expected = hex2bin("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7").unwrap();

        hasher.update(&message[..]);
        let result = hasher.finalize().unwrap();
        assert_eq!(expected.to_vec(), result);

        let message = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let expected = hex2bin("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039").unwrap();

        hasher.update(&message[..]);
        let result = hasher.finalize().unwrap();
        assert_eq!(expected.to_vec(), result);

        let expected = hex2bin("9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985").unwrap();
        for _ in 0..1000000 {
            hasher.update(b"a");
        }
        let result = hasher.finalize().unwrap();
        assert_eq!(expected.to_vec(), result);
    }

    #[test]
    fn sha2_512() {
        let mut hasher = Sha512::new();
        // Taken from https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2withchangenotice.pdf
        let message = b"abc";

        let expected = hex2bin("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f").unwrap();

        hasher.update(&message[..]);
        let result = hasher.finalize().unwrap();
        assert_eq!(expected.to_vec(), result);

        let message = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let expected = hex2bin("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909").unwrap();

        hasher.update(&message[..]);
        let result = hasher.finalize().unwrap();
        assert_eq!(expected.to_vec(), result);

        let expected = hex2bin("e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b").unwrap();
        for _ in 0..1000000 {
            hasher.update(b"a");
        }
        let result = hasher.finalize().unwrap();
        assert_eq!(expected.to_vec(), result);
    }
}
