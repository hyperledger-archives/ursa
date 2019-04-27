
pub mod ed25519 {

    use ursa::encoding::hex::{hex2bin};
    use ursa::signatures::{Signer, SignatureScheme};
    use ursa::keys::{PrivateKey, KeyGenOption};
    use ursa::signatures::ed25519::Ed25519Sha512;

    const MESSAGE_1: &[u8] = b"This is a dummy message for use with tests";
    const SIGNATURE_1: &str = "451b5b8e8725321541954997781de51f4142e4a56bab68d24f6a6b92615de5eefb74134138315859a32c7cf5fe5a488bc545e2e08e5eedfd1fb10188d532d808";
    const PRIVATE_KEY: &str = "1c1179a560d092b90458fe6ab8291215a427fcd6b3927cb240701778ef55201927c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf";
    const PUBLIC_KEY: &str = "27c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf";

    pub fn create_keys() {
        let scheme = Ed25519Sha512::new();
        scheme.keypair(None).unwrap();
    }

    pub fn load_keys() {
        let scheme = Ed25519Sha512::new();
        let secret = PrivateKey(hex2bin(PRIVATE_KEY).unwrap());
        let sres = scheme.keypair(Some(KeyGenOption::FromSecretKey(secret)));
        sres.unwrap();
    }

    pub fn verify() {
        let scheme = Ed25519Sha512::new();
        let secret = PrivateKey(hex2bin(PRIVATE_KEY).unwrap());
        let (p, _s) = scheme.keypair(Some(KeyGenOption::FromSecretKey(secret))).unwrap();

        scheme.verify(&MESSAGE_1, hex2bin(SIGNATURE_1).unwrap().as_slice(), &p);
    }

    pub fn sign() {
        let scheme = Ed25519Sha512::new();
        let secret = PrivateKey(hex2bin(PRIVATE_KEY).unwrap());
        let (_p, s) = scheme.keypair(Some(KeyGenOption::FromSecretKey(secret))).unwrap();

        let signer = Signer::new(&scheme, &s);
        signer.sign(&MESSAGE_1);
        // match signer.sign(&MESSAGE_1) {
        //     Ok(signed) => {
        //         scheme.verify(&MESSAGE_1, &signed, &p);
        //     },
        //     Err(_) => panic!("Encountered error during signing.")
        // }
    }

}

pub mod secp256k1 {

    use ursa::encoding::hex;
    use ursa::keys::{PrivateKey, PublicKey, KeyGenOption};
    use ursa::signatures::*;
    use ursa::signatures::EcdsaPublicKeyHandler;
    use ursa::signatures::secp256k1::EcdsaSecp256k1Sha256;
    use libsecp256k1;
    use ursa::sha2::Digest;
    use openssl::ecdsa::EcdsaSig;
    use openssl::ec::{EcGroup, EcPoint, EcKey};
    use openssl::nid::Nid;
    use openssl::bn::{BigNum, BigNumContext};

    const MESSAGE_1: &[u8] = b"This is a dummy message for use with tests";
    const SIGNATURE_1: &str = "ae46d3fec8e2eb95ebeaf95f7f096ec4bf517f5ef898e4379651f8af8e209ed75f3c47156445d6687a5f817fb3e188e2a76df653b330df859ec47579c8c409be";
    const PRIVATE_KEY: &str = "e4f21b38e005d4f895a29e84948d7cc83eac79041aeb644ee4fab8d9da42f713";
    const PUBLIC_KEY: &str = "0242c1e1f775237a26da4fd51b8d75ee2709711f6e90303e511169a324ef0789c0";

    pub fn create_keys() {
        let scheme = EcdsaSecp256k1Sha256::new();
        scheme.keypair(None).unwrap();
    }

    pub fn load_keys() {
        let scheme = EcdsaSecp256k1Sha256::new();
        let secret = PrivateKey(hex::hex2bin(PRIVATE_KEY).unwrap());
        scheme.keypair(Some(KeyGenOption::FromSecretKey(secret)));
        scheme.parse(hex::hex2bin(PUBLIC_KEY).unwrap().as_slice());
    }

    // pub fn compatibility() {
    //     let scheme = EcdsaSecp256k1Sha256::new();
    //     let secret = PrivateKey(hex::hex2bin(PRIVATE_KEY).unwrap());
    //     let (p, s) = scheme.keypair(Some(KeyGenOption::FromSecretKey(secret))).unwrap();

    //     let p_u = scheme.parse(&scheme.public_key_uncompressed(&p));
    //     let p_u = p_u.unwrap();

    //     let sk = libsecp256k1::key::SecretKey::from_slice(&s[..]);
    //     let pk = libsecp256k1::key::PublicKey::from_slice(&p[..]);
    //     let pk = libsecp256k1::key::PublicKey::from_slice(&scheme.public_key_uncompressed(&p)[..]);

    //     let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    //     let mut ctx = BigNumContext::new().unwrap();
    //     let openssl_point = EcPoint::from_bytes(&openssl_group, &scheme.public_key_uncompressed(&p)[..], &mut ctx);
    // }

    pub fn verify() {
        let scheme = EcdsaSecp256k1Sha256::new();
        let p = PublicKey(hex::hex2bin(PUBLIC_KEY).unwrap());

        scheme.verify(&MESSAGE_1, hex::hex2bin(SIGNATURE_1).unwrap().as_slice(), &p);

        // let context = libsecp256k1::Secp256k1::new();
        // let pk = libsecp256k1::key::PublicKey::from_slice(hex::hex2bin(PUBLIC_KEY).unwrap().as_slice()).unwrap();

        // let h = sha2::Sha256::digest(&MESSAGE_1);
        // let msg = libsecp256k1::Message::from_slice(h.as_slice()).unwrap();

        // //Check if signatures produced here can be verified by libsecp256k1
        // let mut signature = libsecp256k1::Signature::from_compact(&hex::hex2bin(SIGNATURE_1).unwrap()[..]).unwrap();
        // signature.normalize_s();
        // let result = context.verify(&msg, &signature, &pk);

        // let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        // let mut ctx = BigNumContext::new().unwrap();
        // let openssl_point = EcPoint::from_bytes(&openssl_group, &pk.serialize_uncompressed(), &mut ctx).unwrap();
        // let openssl_pkey = EcKey::from_public_key(&openssl_group, &openssl_point).unwrap();

        // //Check if the signatures produced here can be verified by openssl
        // let (r, s) = SIGNATURE_1.split_at(SIGNATURE_1.len() / 2);
        // let openssl_r = BigNum::from_hex_str(r).unwrap();
        // let openssl_s = BigNum::from_hex_str(s).unwrap();
        // let openssl_sig = EcdsaSig::from_private_components(openssl_r, openssl_s).unwrap();
        // let openssl_result = openssl_sig.verify(h.as_slice(), &openssl_pkey);
    }

    pub fn sign() {
        let scheme = EcdsaSecp256k1Sha256::new();
        let secret = PrivateKey(hex::hex2bin(PRIVATE_KEY).unwrap());
        let (_p, s) = scheme.keypair(Some(KeyGenOption::FromSecretKey(secret))).unwrap();
        scheme.sign(MESSAGE_1, &s);

        // match scheme.sign(MESSAGE_1, &s) {
        //     Ok(sig) => {
        //     scheme.verify(&MESSAGE_1, &sig, &p);

        //     //Check if libsecp256k1 signs the message and this module still can verify it
        //     //And that private keys can sign with other libraries
        //     let mut context = libsecp256k1::Secp256k1::new();
        //     let sk = libsecp256k1::key::SecretKey::from_slice(hex::hex2bin(PRIVATE_KEY).unwrap().as_slice()).unwrap();

        //     let h = sha2::Sha256::digest(&MESSAGE_1);

        //     let msg = libsecp256k1::Message::from_slice(h.as_slice()).unwrap();
        //     let sig_1 = context.sign(&msg, &sk).serialize_compact();

        //     let result = scheme.verify(&MESSAGE_1, &sig_1, &p);

        //     let openssl_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        //     let mut ctx = BigNumContext::new().unwrap();
        //     let openssl_point = EcPoint::from_bytes(&openssl_group, &scheme.public_key_uncompressed(&p)[..], &mut ctx).unwrap();
        //     let openssl_pkey = EcKey::from_public_key(&openssl_group, &openssl_point).unwrap();
        //     let openssl_skey = EcKey::from_private_components(&openssl_group, &BigNum::from_hex_str(PRIVATE_KEY).unwrap(), &openssl_point).unwrap();

        //     let openssl_sig = EcdsaSig::sign(h.as_slice(), &openssl_skey).unwrap();
        //     let openssl_result = openssl_sig.verify(h.as_slice(), &openssl_pkey);
        //     let mut temp_sig = Vec::new();
        //     temp_sig.extend(openssl_sig.r().to_vec());
        //     temp_sig.extend(openssl_sig.s().to_vec());

        //     //libsecp256k1 expects normalized "s"'s.
        //     scheme.normalize_s(temp_sig.as_mut_slice()).unwrap();
        //     let result = scheme.verify(&MESSAGE_1, temp_sig.as_slice(), &p);

        //     let (p, s) = scheme.keypair(None).unwrap();
        //     match scheme.sign(&MESSAGE_1, &s) {
        //         Ok(signed) => {
        //             let result = scheme.verify(&MESSAGE_1, &signed, &p);
        //             assert!(result.is_ok());
        //             assert!(result.unwrap());
        //         },
        //         Err(_) => panic!("Encountered error during signing.")
        //     }

        //     let signer = Signer::new(&scheme, &s);
        //     match signer.sign(&MESSAGE_1) {
        //         Ok(signed) => {
        //             let result = scheme.verify(&MESSAGE_1, &signed, &p);
        //             assert!(result.is_ok());
        //             assert!(result.unwrap());
        //         },
        //         Err(_) => panic!("Encountered error during signing.")
        //     }
        //     },
        //     Err(_) => panic!("Encountered error during signing.")
        // }
    }

    // pub fn publickey_compression() {
    //     let scheme = EcdsaSecp256k1Sha256::new();

    //     let pk = PublicKey(hex::hex2bin(PUBLIC_KEY).unwrap());

    //     let res = scheme.public_key_compressed(&pk);

    //     let res = scheme.public_key_uncompressed(&pk);
    //     let pk = PublicKey(res);

    //     let res = scheme.public_key_uncompressed(&pk);
    // }
}
