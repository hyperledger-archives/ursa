use errors::IndyCryptoError;
use pair::{GroupOrderElement, PointG2, PointG1, Pair};

use sha1::Sha1;

pub struct Bls {}

impl Bls {
    /// Creates and returns random generator point that satisfy BLS algorithm requirements.
    ///
    /// BLS algorithm requires choosing of generator point that must be known to all parties.
    /// The most of BLS methods require generator to be provided.
    ///
    /// # Example
    ///
    /// ```
    /// use indy_crypto::bls::Bls;
    /// let gen = Bls::create_generator().unwrap();
    /// assert!(gen.len() > 0);
    /// ```
    pub fn create_generator() -> Result<Vec<u8>, IndyCryptoError> {
        PointG2::new()?.to_bytes()
    }

    /// Generates and returns random (or known if seed provided) pair of sign and verification keys
    ///
    /// # Arguments
    ///
    /// * `gen` - Generator point
    /// * `seed` - Can be used to generate known keys
    ///
    /// # Example
    ///
    /// ```
    /// use indy_crypto::bls::Bls;
    /// let gen = Bls::create_generator().unwrap();
    ///
    /// // Generate random keys
    /// let (sign_key, ver_key) = Bls::generate_keys(&gen, None).unwrap();
    /// assert!(sign_key.len() > 0);
    /// assert!(ver_key.len() > 0);
    ///
    /// // Generate known keys based on seed
    /// let seed = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8];
    /// let (sign_key, ver_key) = Bls::generate_keys(&gen, Some(&seed)).unwrap();
    /// assert!(sign_key.len() > 0);
    /// assert!(ver_key.len() > 0);
    /// ```
    pub fn generate_keys(gen: &[u8], seed: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), IndyCryptoError> {
        let gen = PointG2::from_bytes(gen)?;

        let sign_key = match seed {
            Some(seed) => GroupOrderElement::new_from_seed(seed)?,
            _ => GroupOrderElement::new()?
        };

        let ver_key = gen.mul(&sign_key)?;
        Ok((sign_key.to_bytes()?, ver_key.to_bytes()?))
    }

    /// Signs the message and returns signature.
    ///
    /// # Arguments
    ///
    /// * `message` - Message to sign
    /// * `sign_key` - Sign key
    ///
    /// # Example
    ///
    /// ```
    /// use indy_crypto::bls::Bls;
    /// let gen = Bls::create_generator().unwrap();
    /// let (sign_key, _) = Bls::generate_keys(&gen, None).unwrap();
    /// let message = vec![1, 2, 3, 4, 5];
    ///
    /// let signature = Bls::sign(&message, &sign_key).unwrap();
    /// assert!(signature.len() > 0);
    /// ```
    pub fn sign(message: &[u8], sign_key: &[u8]) -> Result<Vec<u8>, IndyCryptoError> {
        let sign_key = GroupOrderElement::from_bytes(sign_key)?;
        Bls::_h(message)?.mul(&sign_key)?.to_bytes()
    }


    /// Generates and returns multi signature for provided list of signatures.
    ///
    /// # Arguments
    ///
    /// * `signatures` - List of signatures
    ///
    /// # Example
    ///
    /// ```
    /// use indy_crypto::bls::Bls;
    /// let gen = Bls::create_generator().unwrap();
    /// let (sign_key1, _) = Bls::generate_keys(&gen, None).unwrap();
    /// let (sign_key2, _) = Bls::generate_keys(&gen, None).unwrap();
    ///
    /// let message = vec![1, 2, 3, 4, 5];
    ///
    /// let signature1 = Bls::sign(&message, &sign_key1).unwrap();
    /// let signature2 = Bls::sign(&message, &sign_key2).unwrap();
    ///
    /// let signatures = vec![
    ///    signature1.as_slice(),
    ///    signature2.as_slice()
    /// ];
    ///
    /// let multi_sig = Bls::create_multi_sig(&signatures).unwrap();
    /// assert!(multi_sig.len() > 0);
    /// ```
    pub fn create_multi_sig(signatures: &[&[u8]]) -> Result<Vec<u8>, IndyCryptoError> {
        let mut signature_points: Vec<PointG1> = Vec::new();

        for s in signatures {
            signature_points.push(PointG1::from_bytes(&s)?)
        }

        let mut multi_sig = PointG1::new_inf()?;

        for signature in signature_points {
            multi_sig = multi_sig.add(&signature)?;
        }

        Ok(multi_sig.to_bytes()?)
    }

    /// Verifies the message signature and returns true - if signature valid or false otherwise.
    ///
    /// # Arguments
    ///
    /// * `signature` - Signature to verify
    /// * `message` - Message to verify
    /// * `ver_key` - Verification key
    /// * `gen` - Generator point
    ///
    /// # Example
    ///
    /// ```
    /// use indy_crypto::bls::Bls;
    /// let gen = Bls::create_generator().unwrap();
    /// let (sign_key, ver_key) = Bls::generate_keys(&gen, None).unwrap();
    /// let message = vec![1, 2, 3, 4, 5];
    /// let signature = Bls::sign(&message, &sign_key).unwrap();
    ///
    /// let valid = Bls::verify(&signature, &message, &ver_key, &gen).unwrap();
    /// assert!(valid);
    /// ```
    pub fn verify(signature: &[u8], message: &[u8], ver_key: &[u8], gen: &[u8]) -> Result<bool, IndyCryptoError> {
        let signature = PointG1::from_bytes(signature)?;
        let pk = PointG2::from_bytes(ver_key)?;
        let gen = PointG2::from_bytes(gen)?;
        let h = Bls::_h(message)?;

        Ok(Pair::pair(&signature, &gen)?.eq(&Pair::pair(&h, &pk)?))
    }

    /// Verifies the message multi signature and returns true - if signature valid or false otherwise.
    ///
    /// # Arguments
    ///
    /// * `multi_sig` - Multi signature to verify
    /// * `message` - Message to verify
    /// * `ver_keys` - List of verification keys
    /// * `gen` - Generator point
    ///
    /// # Example
    ///
    /// ```
    /// use indy_crypto::bls::Bls;
    /// let gen = Bls::create_generator().unwrap();
    ///
    /// let (sign_key1, ver_key1) = Bls::generate_keys(&gen, None).unwrap();
    /// let (sign_key2, ver_key2) = Bls::generate_keys(&gen, None).unwrap();
    ///
    /// let message = vec![1, 2, 3, 4, 5];
    ///
    /// let signature1 = Bls::sign(&message, &sign_key1).unwrap();
    /// let signature2 = Bls::sign(&message, &sign_key2).unwrap();
    ///
    /// let signatures = vec![
    ///    signature1.as_slice(),
    ///    signature2.as_slice()
    /// ];
    ///
    /// let multi_sig = Bls::create_multi_sig(&signatures).unwrap();
    ///
    /// let ver_keys = vec![
    ///   ver_key1.as_slice(), ver_key2.as_slice()
    /// ];
    ///
    /// let valid = Bls::verify_multi_sig(&multi_sig, &message, &ver_keys, &gen).unwrap();
    /// assert!(valid)
    /// ```
    pub fn verify_multi_sig(multi_sig: &[u8], message: &[u8], ver_keys: &[&[u8]], gen: &[u8]) -> Result<bool, IndyCryptoError> {
        let multi_sig = PointG1::from_bytes(multi_sig)?;
        let gen = PointG2::from_bytes(gen)?;

        let mut pks: Vec<PointG2> = Vec::new();
        for pk in ver_keys {
            pks.push(PointG2::from_bytes(pk)?)
        }

        let mut multi_sig_e_list: Vec<Pair> = Vec::new();
        for pk in pks {
            let h = Bls::_h(message)?;
            multi_sig_e_list.push(Pair::pair(&h, &pk)?);
        }

        let mut multi_sig_e = multi_sig_e_list.get(0).ok_or(IndyCryptoError::InvalidStructure(format!("Element not found")))?.clone();
        for e in multi_sig_e_list[1..].to_vec() {
            multi_sig_e = multi_sig_e.mul(&e)?;
        }

        Ok(Pair::pair(&multi_sig, &gen)?.eq(&multi_sig_e))
    }

    fn _h(message: &[u8]) -> Result<PointG1, IndyCryptoError> {
        let mut res = Sha1::new();
        res.update(message);

        Ok(PointG1::from_hash(&res.digest().bytes().to_vec())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_generator_works() {
        Bls::create_generator().unwrap();
    }

    #[test]
    fn generate_keys_works() {
        let gen = Bls::create_generator().unwrap();
        Bls::generate_keys(&gen, None).unwrap();
    }

    #[test]
    fn generate_keys_works_for_seed() {
        let gen = Bls::create_generator().unwrap();
        let seed = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8];
        Bls::generate_keys(&gen, Some(&seed)).unwrap();
    }

    #[test]
    fn sign_works() {
        let gen = Bls::create_generator().unwrap();
        let (sk, _) = Bls::generate_keys(&gen, None).unwrap();
        let message = vec![1, 2, 3, 4, 5];
        Bls::sign(&message, &sk).unwrap();
    }

    #[test]
    fn multi_sign_works() {
        let message = vec![1, 2, 3, 4, 5];

        let gen = Bls::create_generator().unwrap();
        let (sk1, _) = Bls::generate_keys(&gen, None).unwrap();
        let (sk2, _) = Bls::generate_keys(&gen, None).unwrap();

        let signature1 = Bls::sign(&message, &sk1).unwrap();
        let signature2 = Bls::sign(&message, &sk2).unwrap();

        let signatures = vec![
            signature1.as_slice(),
            signature2.as_slice()
        ];

        Bls::create_multi_sig(&signatures).unwrap();
    }

    #[test]
    fn verify_works() {
        let message = vec![1, 2, 3, 4, 5];

        let gen = Bls::create_generator().unwrap();
        let (sk, pk) = Bls::generate_keys(&gen, None).unwrap();
        let signature = Bls::sign(&message, &sk).unwrap();
        let valid = Bls::verify(&signature, &message, &pk, &gen).unwrap();

        assert!(valid)
    }

    #[test]
    fn verify_works_for_invalid_message() {
        let message = vec![1, 2, 3, 4, 5];
        let message_invalid = vec![1, 2, 3, 4, 5, 6];

        let gen = Bls::create_generator().unwrap();
        let (sk, pk) = Bls::generate_keys(&gen, None).unwrap();
        let signature = Bls::sign(&message, &sk).unwrap();

        let valid = Bls::verify(&signature, &message_invalid, &pk, &gen).unwrap();
        assert!(!valid)
    }

    #[test]
    fn verify_works_for_invalid_signature() {
        let message = vec![1, 2, 3, 4, 5];

        let gen = Bls::create_generator().unwrap();
        let (_, pk) = Bls::generate_keys(&gen, None).unwrap();
        let (sk, _) = Bls::generate_keys(&gen, None).unwrap();

        let signature_invalid = Bls::sign(&message, &sk).unwrap();

        let valid = Bls::verify(&signature_invalid, &message, &pk, &gen).unwrap();
        assert!(!valid)
    }

    #[test]
    fn verify_multi_sig_works() {
        let message = vec![1, 2, 3, 4, 5];

        let gen = Bls::create_generator().unwrap();
        let (sk1, pk1) = Bls::generate_keys(&gen, None).unwrap();
        let (sk2, pk2) = Bls::generate_keys(&gen, None).unwrap();

        let pks = vec![
            pk1.as_slice(), pk2.as_slice()
        ];

        let signature1 = Bls::sign(&message, &sk1).unwrap();
        let signature2 = Bls::sign(&message, &sk2).unwrap();

        let signatures = vec![
            signature1.as_slice(),
            signature2.as_slice()
        ];

        let multi_signature = Bls::create_multi_sig(&signatures).unwrap();
        let valid = Bls::verify_multi_sig(&multi_signature, &message, &pks, &gen).unwrap();

        assert!(valid)
    }

    #[test]
    fn verify_multi_sig_works_for_invalid_message() {
        let message = vec![1, 2, 3, 4, 5];
        let message_invalid = vec![1, 2, 3, 4, 5, 6];

        let gen = Bls::create_generator().unwrap();
        let (sk1, pk1) = Bls::generate_keys(&gen, None).unwrap();
        let (sk2, pk2) = Bls::generate_keys(&gen, None).unwrap();

        let pks = vec![
            pk1.as_slice(), pk2.as_slice()
        ];

        let signature1 = Bls::sign(&message, &sk1).unwrap();
        let signature2 = Bls::sign(&message, &sk2).unwrap();

        let signatures = vec![
            signature1.as_slice(),
            signature2.as_slice()
        ];

        let multi_signature = Bls::create_multi_sig(&signatures).unwrap();
        let valid = Bls::verify_multi_sig(&multi_signature, &message_invalid, &pks, &gen).unwrap();

        assert!(!valid)
    }

    #[test]
    fn verify_multi_sig_works_for_invalid_signature() {
        let message = vec![1, 2, 3, 4, 5];

        let gen = Bls::create_generator().unwrap();
        let (sk1, pk1) = Bls::generate_keys(&gen, None).unwrap();
        let (_, pk2) = Bls::generate_keys(&gen, None).unwrap();
        let (sk2, _) = Bls::generate_keys(&gen, None).unwrap();

        let pks = vec![
            pk1.as_slice(), pk2.as_slice()
        ];

        let signature1 = Bls::sign(&message, &sk1).unwrap();
        let signature2 = Bls::sign(&message, &sk2).unwrap();

        let signatures = vec![
            signature1.as_slice(),
            signature2.as_slice()
        ];

        let multi_signature_invalud = Bls::create_multi_sig(&signatures).unwrap();
        let valid = Bls::verify_multi_sig(&multi_signature_invalud, &message, &pks, &gen).unwrap();

        assert!(!valid)
    }
}