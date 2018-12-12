use super::*;
use hash::{digest, DigestAlgorithm};
use CryptoError;

use rand::rngs::OsRng;

pub const PRIVATE_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 33;
pub const PUBLIC_UNCOMPRESSED_KEY_SIZE: usize = 65;
pub const SIGNATURE_POINT_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;
pub const ALGORITHM_NAME: &str = "ECDSA_SECP256K1_SHA256";

pub struct EcdsaSecp256k1Sha256(ecdsa_secp256k1sha256::EcdsaSecp256k1Sha256Impl);

impl EcdsaSecp256k1Sha256 {
    pub fn normalize_s(&self, signature: &mut [u8]) -> Result<(), CryptoError> {
        self.0.normalize_s(signature)
    }
}

impl SignatureScheme for EcdsaSecp256k1Sha256 {
    fn new() -> EcdsaSecp256k1Sha256 {
        EcdsaSecp256k1Sha256(ecdsa_secp256k1sha256::EcdsaSecp256k1Sha256Impl::new())
    }
    fn keypair(&self, option: Option<KeyPairOption>) -> Result<(PublicKey, PrivateKey), CryptoError> {
        self.0.keypair(option)
    }
    fn sign(&self, message: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, CryptoError> {
        self.0.sign(message, sk)
    }
    fn verify(&self, message: &[u8], signature: &[u8], pk: &PublicKey) -> Result<bool, CryptoError> {
        self.0.verify(message, signature, pk)
    }
    fn signature_size() -> usize { SIGNATURE_SIZE }
    fn private_key_size() -> usize { PRIVATE_KEY_SIZE }
    fn public_key_size() -> usize { PUBLIC_KEY_SIZE }
}

impl EcdsaPublicKeyHandler for EcdsaSecp256k1Sha256 {
    /// Returns the compressed bytes
    fn serialize(&self, pk: &PublicKey) -> Vec<u8> {
        self.0.serialize(pk)
    }
    /// Returns the uncompressed bytes
    fn serialize_uncompressed(&self, pk: &PublicKey) -> Vec<u8> {
        self.0.serialize_uncompressed(pk)
    }
    /// Read raw bytes into key struct. Can be either compressed or uncompressed
    fn parse(&self, data: &[u8]) -> Result<PublicKey, CryptoError> {
        self.0.parse(data)
    }
    fn public_key_uncompressed_size() -> usize { PUBLIC_UNCOMPRESSED_KEY_SIZE }
}

#[cfg(all(feature = "native", not(feature = "portable")))]
mod ecdsa_secp256k1sha256 {
    use super::*;
    use libsecp256k1;

    use rand_chacha::ChaChaRng;
    use rand::{RngCore, SeedableRng};

    pub struct EcdsaSecp256k1Sha256Impl(libsecp256k1::Secp256k1<libsecp256k1::All>);

    impl EcdsaSecp256k1Sha256Impl {
        pub fn serialize(&self, pk: &PublicKey) -> Vec<u8> {
            let pk = libsecp256k1::key::PublicKey::from_slice(&pk[..]).unwrap();
            pk.serialize().to_vec()
        }
        pub fn serialize_uncompressed(&self, pk: &PublicKey) -> Vec<u8> {
            let pk = libsecp256k1::key::PublicKey::from_slice(&pk[..]).unwrap();
            pk.serialize_uncompressed().to_vec()
        }
        pub fn parse(&self, data: &[u8]) -> Result<PublicKey, CryptoError> {
            let res = libsecp256k1::key::PublicKey::from_slice(data)?;
            let pk = PublicKey(res.serialize().to_vec());
            Ok(pk)
        }
        pub fn new() -> EcdsaSecp256k1Sha256Impl {
            EcdsaSecp256k1Sha256Impl(libsecp256k1::Secp256k1::new())
        }
        pub fn keypair(&self, option: Option<KeyPairOption>) -> Result<(PublicKey, PrivateKey), CryptoError> {
            let sk = match option {
                    Some(o) => {
                        match o {
                            KeyPairOption::UseSeed(seed) => {
                                let mut s = [0u8; PRIVATE_KEY_SIZE];
                                let mut rng = ChaChaRng::from_seed(*array_ref!(seed.as_slice(), 0, 32));
                                rng.fill_bytes(&mut s);
                                libsecp256k1::key::SecretKey::from_slice(&s[..])?
                            },
                            KeyPairOption::FromSecretKey(s) => libsecp256k1::key::SecretKey::from_slice(&s[..])?
                        }
                    },
                    None => {
                        let mut rng = OsRng::new().map_err(|err| CryptoError::KeyGenError(format!("{}", err)))?;
                        let mut s = [0u8; PRIVATE_KEY_SIZE];
                        rng.fill_bytes(&mut s);
                        libsecp256k1::key::SecretKey::from_slice(&s[..])?
                    }
                };
            let pk = libsecp256k1::key::PublicKey::from_secret_key(&self.0, &sk);
            Ok((PublicKey(pk.serialize().to_vec()), PrivateKey(sk[..].to_vec())))
        }
        pub fn sign(&self, message: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, CryptoError> {
            let h = digest(DigestAlgorithm::Sha2_256, message)?;
            let msg = libsecp256k1::Message::from_slice(h.as_slice())?;
            let s = libsecp256k1::key::SecretKey::from_slice(&sk[..])?;
            let sig = self.0.sign(&msg, &s);
            Ok(sig.serialize_compact().to_vec())
        }
        pub fn verify(&self, message: &[u8], signature: &[u8], pk: &PublicKey) -> Result<bool, CryptoError> {
            let h = digest(DigestAlgorithm::Sha2_256, message)?;
            let msg = libsecp256k1::Message::from_slice(h.as_slice())?;
            let p = libsecp256k1::PublicKey::from_slice(&pk[..])?;
            let sig = libsecp256k1::Signature::from_compact(signature)?;
            let res = self.0.verify(&msg, &sig, &p);
            match res {
                Ok(()) => Ok(true),
                Err(libsecp256k1::Error::IncorrectSignature) => Ok(false),
                Err(err) => Err(CryptoError::from(err))
            }
        }
        pub fn normalize_s(&self, signature: &mut [u8]) -> Result<(), CryptoError> {
            let mut sig = libsecp256k1::Signature::from_compact(signature)?;
            sig.normalize_s();
            let compact = sig.serialize_compact();
            array_copy!(compact, signature);
            Ok(())
        }
    }
}

#[cfg(all(feature = "portable", not(feature = "native")))]
mod ecdsa_secp256k1sha256 {
    use super::*;
    use rustlibsecp256k1;

    use rand::{SeedableRng, RngCore};
    use rand_chacha::ChaChaRng;

    use amcl_3::secp256k1::{ecp, ecdh};

    pub struct EcdsaSecp256k1Sha256Impl{}

    impl EcdsaSecp256k1Sha256Impl {
        pub fn serialize(&self, pk: &PublicKey) -> Vec<u8> {
            let mut compressed = [0u8; PUBLIC_KEY_SIZE];
            ecp::ECP::frombytes(&pk[..]).tobytes(&mut compressed, true);
            compressed.to_vec()
        }
        pub fn serialize_uncompressed(&self, pk: &PublicKey) -> Vec<u8> {
            let mut uncompressed = [0u8; PUBLIC_UNCOMPRESSED_KEY_SIZE];
            ecp::ECP::frombytes(&pk[..]).tobytes(&mut uncompressed, false);
            uncompressed.to_vec()
        }
        pub fn parse(&self, data: &[u8]) -> Result<PublicKey, CryptoError> {
            match data.len() {
                PUBLIC_KEY_SIZE => Ok(PublicKey(data.to_vec())),
                PUBLIC_UNCOMPRESSED_KEY_SIZE => {
                    let mut compressed = [0u8; PUBLIC_KEY_SIZE];
                    ecp::ECP::frombytes(data).tobytes(&mut compressed, true);
                    Ok(PublicKey(compressed.to_vec()))
                }
                _ => Err(CryptoError::ParseError("Invalid key length".to_string()))
            }
        }
        pub fn new() -> EcdsaSecp256k1Sha256Impl {
            EcdsaSecp256k1Sha256Impl{}
        }
        pub fn keypair(&self, option: Option<KeyPairOption>) -> Result<(PublicKey, PrivateKey), CryptoError> {
            let mut sk = [0u8; PRIVATE_KEY_SIZE];
            match option {
                    Some(o) => {
                        match o {
                            KeyPairOption::UseSeed(seed) => {
                                let mut rng = ChaChaRng::from_seed(*array_ref!(seed.as_slice(), 0, PRIVATE_KEY_SIZE));
                                rng.fill_bytes(&mut sk);
                                let d = digest(DigestAlgorithm::Sha2_256, &sk[..])?;
                                array_copy!(d.as_slice(), sk)
                            },
                            KeyPairOption::FromSecretKey(s) => array_copy!(s, sk)
                        }
                    },
                    None => {
                        let mut rng = OsRng::new().map_err(|err| CryptoError::KeyGenError(format!("{}", err)))?;
                        rng.fill_bytes(&mut sk);
                        let d = digest(DigestAlgorithm::Sha2_256, &sk[..])?;
                        array_copy!(d.as_slice(), sk);
                    }
                };
            let mut pk = [0u8; PUBLIC_KEY_SIZE]; //Compressed
            ecdh::key_pair_generate(None, &mut sk, &mut pk);
            Ok((PublicKey(pk.to_vec()), PrivateKey(sk.to_vec())))
        }
        pub fn sign(&self, message: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, CryptoError> {
            let h = digest(DigestAlgorithm::Sha2_256, message)?;
            match rustlibsecp256k1::sign(array_ref!(h.as_slice(), 0, SIGNATURE_POINT_SIZE), array_ref!(sk[..], 0, PRIVATE_KEY_SIZE)) {
                Ok(sig) => Ok(sig.to_vec()),
                Err(_) => Err(CryptoError::SigningError("".to_string()))
            }
        }
        pub fn verify(&self, message: &[u8], signature: &[u8], pk: &PublicKey) -> Result<bool, CryptoError> {
            let h = digest(DigestAlgorithm::Sha2_256, message)?;
            let uncompressed_pk = self.serialize_uncompressed(&pk);
            match rustlibsecp256k1::verify(array_ref!(h.as_slice(), 0, SIGNATURE_POINT_SIZE),
                                           array_ref!(signature, 0, SIGNATURE_SIZE),
                                           array_ref!(uncompressed_pk.as_slice(), 0, PUBLIC_UNCOMPRESSED_KEY_SIZE)) {
                Ok(b) => Ok(b),
                Err(_) => Err(CryptoError::SigningError("Incorrect signature".to_string()))
            }
        }
        pub fn normalize_s(&self, signature: &mut [u8]) -> Result<(), CryptoError> {
            let mut new_s = set_b32(array_ref!(signature, 32, 32));
            if is_high(&new_s) {
                negate(&mut new_s);
                let s_tmp = get_b32(&new_s);
                array_copy!(s_tmp, 0, signature, 32, 32);
            }
            Ok(())
        }
    }

    const HALF_CURVE_ORDER: [u32; 8] = [0x681B20A0, 0xDFE92F46, 0x57A4501D, 0x5D576E73, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF];
    const CURVE_C: [u32; 5] = [!HALF_CURVE_ORDER[0] + 1, !HALF_CURVE_ORDER[1], !HALF_CURVE_ORDER[2], !HALF_CURVE_ORDER[3], 1u32];
    const CURVE_ORDER: [u32; 8] = [0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF];

    /// Convert a little-endian byte array to 8 32 bit numbers
    fn set_b32(s: &[u8; 32]) -> [u32; 8] {
        let mut new_s = [0u32; 8];

        new_s[0] = get_u32(&s[28..32]);
        new_s[1] = get_u32(&s[24..28]);
        new_s[2] = get_u32(&s[20..24]);
        new_s[3] = get_u32(&s[16..20]);
        new_s[4] = get_u32(&s[12..16]);
        new_s[5] = get_u32(&s[8..12]);
        new_s[6] = get_u32(&s[4..8]);
        new_s[7] = get_u32(&s[0..4]);

        let overflow = check_overflow(&new_s);
        reduce(&mut new_s, overflow);
        new_s
    }

    fn get_u32(n: &[u8]) -> u32 {
        let mut res = 0u32;
        for i in 0..4 {
            res <<= 8;
            res |= n[i] as u32;
        }
        res
    }

    /// Convert 8 32 bit numbers array to a little-endian byte array.
    fn get_b32(s: &[u32; 8]) -> [u8; 32] {
        let mut new_s = [0u8; 32];
        let mut index = 0;
        for i in 0..8 {
            let mut shift = 24;
            for _ in 0..4 {
                new_s[index] = (s[7 - i] >> shift) as u8;
                index += 1;
                shift -= 8;
            }
        }
        new_s
    }

    /// Check whether a scalar is higher than the group order divided
    /// by 2.
    fn is_high(s: &[u32; 8]) -> bool {
        let mut yes: bool = false;
        let mut no: bool = false;
        no = no || (s[7] < HALF_CURVE_ORDER[7]);
        yes = yes || ((s[7] > HALF_CURVE_ORDER[7]) & !no);
        no = no || ((s[6] < HALF_CURVE_ORDER[6]) & !yes); /* No need for a > check. */
        no = no || ((s[5] < HALF_CURVE_ORDER[5]) & !yes); /* No need for a > check. */
        no = no || ((s[4] < HALF_CURVE_ORDER[4]) & !yes); /* No need for a > check. */
        no = no || ((s[3] < HALF_CURVE_ORDER[3]) & !yes);
        yes = yes || ((s[3] > HALF_CURVE_ORDER[3]) && !no);
        no = no || ((s[2] < HALF_CURVE_ORDER[2]) && !yes);
        yes = yes || ((s[2] > HALF_CURVE_ORDER[2]) && !no);
        no = no || ((s[1] < HALF_CURVE_ORDER[1]) && !yes);
        yes = yes || ((s[1] > HALF_CURVE_ORDER[1]) && !no);
        yes = yes || ((s[0] >= HALF_CURVE_ORDER[0]) && !no);
        yes
    }

    fn negate(s: &mut [u32; 8]) {
        let nonzero = if is_zero(s) { 0u64 } else { 0xFFFFFFFFu64 };
        let mut t = (!s[0]) as u64 + (CURVE_ORDER[0] + 1) as u64;

        for i in 0..7 {
            s[i] = (t & nonzero) as u32;
            t >>= 32;
            t += (!s[i + 1]) as u64 + CURVE_ORDER[i + 1] as u64;
        }
        s[7] = (t & nonzero) as u32;
    }

    fn is_zero(s: &[u32; 8]) -> bool {
        s.iter().all(|b| *b == 0)
    }

    fn check_overflow(s: &[u32; 8]) -> bool {
        let mut yes: bool = false;
        let mut no: bool = false;
        for i in 0..3 {
            no = no || (s[7 - i] < CURVE_ORDER[7 - i])
        }
        for i in 0..4 {
            no = no || (s[4 - i] < CURVE_ORDER[4 - i]);
            yes = yes || ((s[4 - i] > CURVE_ORDER[4 - i]) && !no);
        }
        yes = yes || ((s[0] >= CURVE_ORDER[0]) && !no);
        yes
    }

    fn reduce(s: &mut [u32; 8], overflow: bool) {
        let o = if overflow { 1u64 } else { 0u64 };
        let mut t = 0u64;

        for i in 0..5 {
            t += (s[i] as u64) + o * (CURVE_C[i] as u64);
            s[i] = (t & 0xFFFFFFFF) as u32;
            t >>= 32;
        }

        for i in 5..7 {
            t += s[i] as u64;
            s[i] = (t & 0xFFFFFFFF) as u32;
            t >>= 32;
        }

        t += s[7] as u64;
        s[7] = (t & 0xFFFFFFFF) as u32;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use encoding::hex;
    use libsecp256k1;
    use openssl::ecdsa::EcdsaSig;
    use openssl::ec::{EcGroup, EcPoint, EcKey};
    use openssl::nid::Nid;
    use openssl::bn::{BigNum, BigNumContext};

    const MESSAGE_1: &[u8] = b"This is a dummy message for use with tests";
    const SIGNATURE_1: &str = "ae46d3fec8e2eb95ebeaf95f7f096ec4bf517f5ef898e4379651f8af8e209ed75f3c47156445d6687a5f817fb3e188e2a76df653b330df859ec47579c8c409be";
    const PRIVATE_KEY: &str = "e4f21b38e005d4f895a29e84948d7cc83eac79041aeb644ee4fab8d9da42f713";
    const PUBLIC_KEY: &str = "0242c1e1f775237a26da4fd51b8d75ee2709711f6e90303e511169a324ef0789c0";

    #[test]
    #[ignore]
    fn create_new_keys() {
        let scheme = EcdsaSecp256k1Sha256::new();
        let (s, p) = scheme.keypair(None).unwrap();

        println!("{:?}", s);
        println!("{:?}", p);
    }

    #[test]
    fn secp256k1_load_keys() {
        let scheme = EcdsaSecp256k1Sha256::new();
        let secret = PrivateKey(hex::hex2bin(PRIVATE_KEY).unwrap());
        let sres = scheme.keypair(Some(KeyPairOption::FromSecretKey(&secret)));
        assert!(sres.is_ok());
        let pres = scheme.parse(hex::hex2bin(PUBLIC_KEY).unwrap().as_slice());
        assert!(pres.is_ok());
        let (p1, _) = sres.unwrap();
        assert_eq!(p1, pres.unwrap());
    }

    #[test]
    fn secp256k1_compatibility() {
        let scheme = EcdsaSecp256k1Sha256::new();
        let secret = PrivateKey(hex::hex2bin(PRIVATE_KEY).unwrap());
        let (p, s) = scheme.keypair(Some(KeyPairOption::FromSecretKey(&secret))).unwrap();

        let p_u = scheme.parse(&scheme.serialize_uncompressed(&p));
        assert!(p_u.is_ok());
        let p_u = p_u.unwrap();
        assert_eq!(p_u, p);

        let sk = libsecp256k1::key::SecretKey::from_slice(&s[..]);
        assert!(sk.is_ok());
        let pk = libsecp256k1::key::PublicKey::from_slice(&p[..]);
        assert!(pk.is_ok());
        let pk = libsecp256k1::key::PublicKey::from_slice(&scheme.serialize_uncompressed(&p)[..]);
        assert!(pk.is_ok());

        let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let openssl_point = EcPoint::from_bytes(&openssl_group, &scheme.serialize_uncompressed(&p)[..], &mut ctx);
        assert!(openssl_point.is_ok());
    }

    #[test]
    fn secp256k1_verify() {
        let scheme = EcdsaSecp256k1Sha256::new();
        let p = PublicKey(hex::hex2bin(PUBLIC_KEY).unwrap());

        let result = scheme.verify(&MESSAGE_1, hex::hex2bin(SIGNATURE_1).unwrap().as_slice(), &p);
        assert!(result.is_ok());
        assert!(result.unwrap());

        let context = libsecp256k1::Secp256k1::new();
        let pk = libsecp256k1::key::PublicKey::from_slice(hex::hex2bin(PUBLIC_KEY).unwrap().as_slice()).unwrap();

        let h = digest(DigestAlgorithm::Sha2_256, &MESSAGE_1).unwrap();
        let msg = libsecp256k1::Message::from_slice(h.as_slice()).unwrap();

        //Check if signatures produced here can be verified by libsecp256k1
        let mut signature = libsecp256k1::Signature::from_compact(&hex::hex2bin(SIGNATURE_1).unwrap()[..]).unwrap();
        signature.normalize_s();
        let result = context.verify(&msg, &signature, &pk);
        assert!(result.is_ok());

        let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let openssl_point = EcPoint::from_bytes(&openssl_group, &pk.serialize_uncompressed(), &mut ctx).unwrap();
        let openssl_pkey = EcKey::from_public_key(&openssl_group, &openssl_point).unwrap();

        //Check if the signatures produced here can be verified by openssl
        let (r, s) = SIGNATURE_1.split_at(SIGNATURE_1.len() / 2);
        let openssl_r = BigNum::from_hex_str(r).unwrap();
        let openssl_s = BigNum::from_hex_str(s).unwrap();
        let openssl_sig = EcdsaSig::from_private_components(openssl_r, openssl_s).unwrap();
        let openssl_result = openssl_sig.verify(h.as_slice(), &openssl_pkey);
        assert!(openssl_result.is_ok());
        assert!(openssl_result.unwrap());
    }

    #[test]
    fn secp256k1_sign() {
        let scheme = EcdsaSecp256k1Sha256::new();
        let secret = PrivateKey(hex::hex2bin(PRIVATE_KEY).unwrap());
        let (p, s) = scheme.keypair(Some(KeyPairOption::FromSecretKey(&secret))).unwrap();

        match scheme.sign(MESSAGE_1, &s) {
            Ok(sig) => {
                let result = scheme.verify(&MESSAGE_1, &sig, &p);
                assert!(result.is_ok());
                assert!(result.unwrap());

                assert_eq!(sig.len(), SIGNATURE_SIZE);

                //Check if libsecp256k1 signs the message and this module still can verify it
                //And that private keys can sign with other libraries
                let mut context = libsecp256k1::Secp256k1::new();
                let sk = libsecp256k1::key::SecretKey::from_slice(hex::hex2bin(PRIVATE_KEY).unwrap().as_slice()).unwrap();

                let h = digest(DigestAlgorithm::Sha2_256, &MESSAGE_1).unwrap();

                let msg = libsecp256k1::Message::from_slice(h.as_slice()).unwrap();
                let sig_1 = context.sign(&msg, &sk).serialize_compact();

                let result = scheme.verify(&MESSAGE_1, &sig_1, &p);

                assert!(result.is_ok());
                assert!(result.unwrap());

                let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
                let mut ctx = BigNumContext::new().unwrap();
                let openssl_point = EcPoint::from_bytes(&openssl_group, &scheme.serialize_uncompressed(&p)[..], &mut ctx).unwrap();
                let openssl_pkey = EcKey::from_public_key(&openssl_group, &openssl_point).unwrap();
                let openssl_skey = EcKey::from_private_components(&openssl_group, &BigNum::from_hex_str(PRIVATE_KEY).unwrap(), &openssl_point).unwrap();

                let openssl_sig = EcdsaSig::sign(h.as_slice(), &openssl_skey).unwrap();
                let openssl_result = openssl_sig.verify(h.as_slice(), &openssl_pkey);
                assert!(openssl_result.is_ok());
                assert!(openssl_result.unwrap());
                let mut temp_sig = Vec::new();
                temp_sig.extend(openssl_sig.r().to_vec());
                temp_sig.extend(openssl_sig.s().to_vec());

                //libsecp256k1 expects normalized "s"'s.
                scheme.normalize_s(temp_sig.as_mut_slice()).unwrap();
                let result = scheme.verify(&MESSAGE_1, temp_sig.as_slice(), &p);
                assert!(result.is_ok());
                assert!(result.unwrap());

                let (p, s) = scheme.keypair(None).unwrap();
                match scheme.sign(&MESSAGE_1, &s) {
                    Ok(signed) => {
                        let result = scheme.verify(&MESSAGE_1, &signed, &p);
                        assert!(result.is_ok());
                        assert!(result.unwrap());
                    },
                    Err(er) => assert!(false, er)
                }

                let signer = Signer::new(&scheme, &s);
                match signer.sign(&MESSAGE_1) {
                    Ok(signed) => {
                        let result = scheme.verify(&MESSAGE_1, &signed, &p);
                        assert!(result.is_ok());
                        assert!(result.unwrap());
                    },
                    Err(er) => assert!(false, er)
                }
            },
            Err(e) => assert!(false, e)
        }
    }
}
