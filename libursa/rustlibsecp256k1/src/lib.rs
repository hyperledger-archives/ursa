extern crate secp256k1 as libsecp256k1;

pub fn sign(message: &[u8; 32], secret_key: &[u8; 32]) -> Result<[u8; 64], ()> {
    let msg = libsecp256k1::Message::parse(message);
    match libsecp256k1::SecretKey::parse(secret_key) {
        Ok(sk) => match libsecp256k1::sign(&msg, &sk) {
            Ok((sig, _)) => Ok(sig.serialize()),
            Err(_) => Err(())
        },
        Err(_) => Err(())
    }
}

pub fn verify(message: &[u8; 32], signature: &[u8; 64], public_key: &[u8; 65]) -> Result<bool, ()> {
    let msg = libsecp256k1::Message::parse(message);
    let sig = libsecp256k1::Signature::parse(signature);
    match libsecp256k1::PublicKey::parse(public_key) {
        Ok(pk) => Ok(libsecp256k1::verify(&msg, &sig, &pk)),
        Err(_) => Err(())
    }
}
