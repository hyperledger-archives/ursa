use errors::IndyCryptoError;
use pair::{GroupOrderElement, PointG2, PointG1, Pair};

use sha2::{Sha256, Digest};

/// BLS generator point.
/// BLS algorithm requires choosing of generator point that must be known to all parties.
/// The most of BLS methods require generator to be provided.
#[derive(Debug)]
pub struct Generator {
    point: PointG2,
    bytes: Vec<u8>
}

impl Generator {
    /// Creates and returns random generator point that satisfy BLS algorithm requirements.
    ///
    /// # Example
    ///
    /// ```
    /// use indy_crypto::bls::Generator;
    /// Generator::new().unwrap();
    /// ```
    pub fn new() -> Result<Generator, IndyCryptoError> {
        let point = PointG2::new()?;
        Ok(Generator {
            point: point,
            bytes: point.to_bytes()?
        })
    }

    /// Returns BLS generator point bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// use indy_crypto::bls::*;
    /// let gen = Generator::new().unwrap();
    /// let gen_bytes = gen.as_bytes();
    /// assert!(gen_bytes.len() > 0);
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Creates and returns generator point from bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// use indy_crypto::bls::Generator;
    /// let gen = Generator::new().unwrap();
    /// let gen_bytes = gen.as_bytes();
    /// Generator::from_bytes(gen_bytes).unwrap();
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Generator, IndyCryptoError> {
        Ok(
            Generator {
                point: PointG2::from_bytes(bytes)?,
                bytes: bytes.to_vec()
            }
        )
    }
}

/// BLS sign key.
#[derive(Debug)]
pub struct SignKey {
    group_order_element: GroupOrderElement,
    bytes: Vec<u8>
}

impl SignKey {
    /// Creates and returns random (or seeded from seed) BLS sign key algorithm requirements.
    ///
    /// # Example
    ///
    /// ```
    /// use indy_crypto::bls::Generator;
    /// Generator::new().unwrap();
    /// ```
    pub fn new(seed: Option<&[u8]>) -> Result<SignKey, IndyCryptoError> {
        let group_order_element = match seed {
            Some(seed) => GroupOrderElement::new_from_seed(seed)?,
            _ => GroupOrderElement::new()?
        };

        Ok(SignKey {
            group_order_element: group_order_element,
            bytes: group_order_element.to_bytes()?
        })
    }

    /// Returns BLS sign key bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// //TODO: Provide an example!
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Creates and returns BLS sign key from bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// //TODO: Provide an example!
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<SignKey, IndyCryptoError> {
        Ok(
            SignKey {
                group_order_element: GroupOrderElement::from_bytes(bytes)?,
                bytes: bytes.to_vec()
            }
        )
    }
}

/// BLS verification key.
#[derive(Debug)]
pub struct VerKey {
    point: PointG2,
    bytes: Vec<u8>
}

impl VerKey {
    /// Creates and returns BLS ver key that corresponds to sign key.
    ///
    /// # Example
    ///
    /// ```
    /// use indy_crypto::bls::Generator;
    /// Generator::new().unwrap();
    /// ```
    pub fn new(gen: &Generator, sign_key: &SignKey) -> Result<VerKey, IndyCryptoError> {
        let point = gen.point.mul(&sign_key.group_order_element)?;

        Ok(VerKey {
            point: point,
            bytes: point.to_bytes()?
        })
    }

    /// Converts BLS verification key to bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// //TODO: Provide an example!
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Creates and returns BLS verification key from bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// //TODO: Provide an example!
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<VerKey, IndyCryptoError> {
        let point = PointG2::from_bytes(bytes)?;
        Ok(
            VerKey {
                point,
                bytes: bytes.to_vec()
            }
        )
    }
}

/// BLS signature.
#[derive(Debug)]
pub struct Signature {
    point: PointG1,
    bytes: Vec<u8>,
}

impl Signature {
    /// Converts BLS signature to bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// //TODO: Provide an example!
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Creates and returns BLS signature from bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// //TODO: Provide an example!
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Signature, IndyCryptoError> {
        let point = PointG1::from_bytes(bytes)?;
        Ok(
            Signature {
                point,
                bytes: bytes.to_vec()
            }
        )
    }
}

/// BLS multi signature.
#[derive(Debug)]
pub struct MultiSignature {
    point: PointG1,
    bytes: Vec<u8>,
}

impl MultiSignature {
    /// Generates and returns multi signature for provided list of signatures.
   ///
   /// # Arguments
   ///
   /// * `signatures` - List of signatures
   ///
   /// # Example
   ///
   /// ```
   /// use indy_crypto::bls::*;
   /// let sign_key1 = SignKey::new(None).unwrap();
   /// let sign_key2 = SignKey::new(None).unwrap();
   ///
   /// let message = vec![1, 2, 3, 4, 5];
   ///
   /// let signature1 = Bls::sign(&message, &sign_key1).unwrap();
   /// let signature2 = Bls::sign(&message, &sign_key2).unwrap();
   ///
   /// let signatures = vec![
   ///    &signature1,
   ///    &signature2
   /// ];
   ///
   /// MultiSignature::new(&signatures).unwrap();
   /// ```
    pub fn new(signatures: &[&Signature]) -> Result<MultiSignature, IndyCryptoError> {
        let mut point = PointG1::new_inf()?;

        for signature in signatures {
            point = point.add(&signature.point)?;
        }

        Ok(MultiSignature {
            point,
            bytes: point.to_bytes()?
        })
    }

    /// Returns BLS multi signature bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// //TODO: Provide an example!
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Creates and returns BLS multi signature from bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// //TODO: Provide an example!
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<MultiSignature, IndyCryptoError> {
        let point = PointG1::from_bytes(bytes)?;
        Ok(
            MultiSignature {
                point: point,
                bytes: bytes.to_vec()
            }
        )
    }
}

pub struct Bls {}

impl Bls {

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
    /// use indy_crypto::bls::*;
    /// let message = vec![1, 2, 3, 4, 5];
    /// let sign_key = SignKey::new(None).unwrap();
    /// Bls::sign(&message, &sign_key).unwrap();
    /// ```
    pub fn sign(message: &[u8], sign_key: &SignKey) -> Result<Signature, IndyCryptoError> {
        let point = Bls::_hash(message)?.mul(&sign_key.group_order_element)?;
        Ok(Signature {
            point,
            bytes: point.to_bytes()?
        })
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
    /// use indy_crypto::bls::*;
    /// let gen = Generator::new().unwrap();
    /// let sign_key = SignKey::new(None).unwrap();
    /// let ver_key = VerKey::new(&gen, &sign_key).unwrap();
    /// let message = vec![1, 2, 3, 4, 5];
    /// let signature = Bls::sign(&message, &sign_key).unwrap();
    ///
    /// let valid = Bls::verify(&signature, &message, &ver_key, &gen).unwrap();
    /// assert!(valid);
    /// ```
    pub fn verify(signature: &Signature, message: &[u8], ver_key: &VerKey, gen: &Generator) -> Result<bool, IndyCryptoError> {
        let h = Bls::_hash(message)?;
        Ok(Pair::pair(&signature.point, &gen.point)?.eq(&Pair::pair(&h, &ver_key.point)?))
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
    /// use indy_crypto::bls::*;
    /// let gen = Generator::new().unwrap();
    ///
    /// let sign_key1 = SignKey::new(None).unwrap();
    /// let ver_key1 = VerKey::new(&gen, &sign_key1).unwrap();
    /// let sign_key2 = SignKey::new(None).unwrap();
    /// let ver_key2 = VerKey::new(&gen, &sign_key2).unwrap();
    ///
    /// let message = vec![1, 2, 3, 4, 5];
    ///
    /// let signature1 = Bls::sign(&message, &sign_key1).unwrap();
    /// let signature2 = Bls::sign(&message, &sign_key2).unwrap();
    ///
    /// let signatures = vec![
    ///    &signature1,
    ///    &signature2
    /// ];
    ///
    /// let multi_sig = MultiSignature::new(&signatures).unwrap();
    ///
    /// let ver_keys = vec![
    ///   &ver_key1, &ver_key2
    /// ];
    ///
    /// let valid = Bls::verify_multi_sig(&multi_sig, &message, &ver_keys, &gen).unwrap();
    /// assert!(valid)
    /// ```
    pub fn verify_multi_sig(multi_sig: &MultiSignature, message: &[u8], ver_keys: &[&VerKey], gen: &Generator) -> Result<bool, IndyCryptoError> {
        let mut multi_sig_e_list: Vec<Pair> = Vec::new();
        for ver_key in ver_keys {
            let h = Bls::_hash(message)?;
            multi_sig_e_list.push(Pair::pair(&h, &ver_key.point)?);
        }

        let mut multi_sig_e = multi_sig_e_list.get(0).ok_or(IndyCryptoError::InvalidStructure(format!("Element not found")))?.clone();
        for e in multi_sig_e_list[1..].to_vec() {
            multi_sig_e = multi_sig_e.mul(&e)?;
        }

        Ok(Pair::pair(&multi_sig.point, &gen.point)?.eq(&multi_sig_e))
    }

    fn _hash(message: &[u8]) -> Result<PointG1, IndyCryptoError> {
        let mut hasher = Sha256::default();
        hasher.input(message);

        Ok(PointG1::from_hash(hasher.result().as_slice())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_new_works() {
        Generator::new().unwrap();
    }

    #[test]
    fn sign_key_new_works() {
        SignKey::new(None).unwrap();
    }

    #[test]
    fn sign_key_new_works_for_seed() {
        let seed = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8];
        SignKey::new(Some(&seed)).unwrap();
    }

    #[test]
    fn ver_key_new_works() {
        let gen = Generator::new().unwrap();
        let sign_key = SignKey::new(None).unwrap();
        VerKey::new(&gen, &sign_key).unwrap();
    }

    #[test]
    fn bls_sign_works() {
        let sign_key = SignKey::new(None).unwrap();
        let message = vec![1, 2, 3, 4, 5];

        Bls::sign(&message, &sign_key).unwrap();
    }

    #[test]
    fn multi_signature_new_works() {
        let message = vec![1, 2, 3, 4, 5];

        let sign_key1 = SignKey::new(None).unwrap();
        let sign_key2 = SignKey::new(None).unwrap();

        let signature1 = Bls::sign(&message, &sign_key1).unwrap();
        let signature2 = Bls::sign(&message, &sign_key2).unwrap();

        let signatures = vec![
            &signature1,
            &signature2
        ];

        MultiSignature::new(&signatures).unwrap();
    }

    #[test]
    fn verify_works() {
        let message = vec![1, 2, 3, 4, 5];

        let gen = Generator::new().unwrap();
        let sign_key = SignKey::new(None).unwrap();
        let ver_key = VerKey::new(&gen, &sign_key).unwrap();
        let signature = Bls::sign(&message, &sign_key).unwrap();

        let valid = Bls::verify(&signature, &message, &ver_key, &gen).unwrap();
        assert!(valid)
    }

    #[test]
    fn verify_works_for_invalid_message() {
        let message = vec![1, 2, 3, 4, 5];
        let message_invalid = vec![1, 2, 3, 4, 5, 6];

        let gen = Generator::new().unwrap();
        let sign_key = SignKey::new(None).unwrap();
        let ver_key = VerKey::new(&gen, &sign_key).unwrap();
        let signature = Bls::sign(&message, &sign_key).unwrap();

        let valid = Bls::verify(&signature, &message_invalid, &ver_key, &gen).unwrap();
        assert!(!valid)
    }

    #[test]
    fn verify_works_for_invalid_signature() {
        let message = vec![1, 2, 3, 4, 5];

        let gen = Generator::new().unwrap();
        let sign_key = SignKey::new(None).unwrap();
        let ver_key = VerKey::new(&gen, &SignKey::new(None).unwrap()).unwrap();

        let signature_invalid = Bls::sign(&message, &sign_key).unwrap();

        let valid = Bls::verify(&signature_invalid, &message, &ver_key, &gen).unwrap();
        assert!(!valid)
    }

    #[test]
    fn verify_multi_sig_works() {
        let message = vec![1, 2, 3, 4, 5];

        let gen = Generator::new().unwrap();
        let sign_key1 = SignKey::new(None).unwrap();
        let ver_key1 = VerKey::new(&gen, &sign_key1).unwrap();
        let sign_key2 = SignKey::new(None).unwrap();
        let ver_key2 = VerKey::new(&gen, &sign_key2).unwrap();

        let ver_keys = vec![
            &ver_key1,
            &ver_key2
        ];

        let signature1 = Bls::sign(&message, &sign_key1).unwrap();
        let signature2 = Bls::sign(&message, &sign_key2).unwrap();

        let signatures = vec![
            &signature1,
            &signature2
        ];

        let multi_signature = MultiSignature::new(&signatures).unwrap();
        let valid = Bls::verify_multi_sig(&multi_signature, &message, &ver_keys, &gen).unwrap();

        assert!(valid)
    }

    #[test]
    fn verify_multi_sig_works_for_invalid_message() {
        let message = vec![1, 2, 3, 4, 5];
        let message_invalid = vec![1, 2, 3, 4, 5, 6];

        let gen = Generator::new().unwrap();
        let sign_key1 = SignKey::new(None).unwrap();
        let ver_key1 = VerKey::new(&gen, &sign_key1).unwrap();
        let sign_key2 = SignKey::new(None).unwrap();
        let ver_key2 = VerKey::new(&gen, &sign_key2).unwrap();

        let ver_keys = vec![
            &ver_key1,
            &ver_key2
        ];

        let signature1 = Bls::sign(&message, &sign_key1).unwrap();
        let signature2 = Bls::sign(&message, &sign_key2).unwrap();

        let signatures = vec![
            &signature1,
            &signature2
        ];

        let multi_signature = MultiSignature::new(&signatures).unwrap();
        let valid = Bls::verify_multi_sig(&multi_signature, &message_invalid, &ver_keys, &gen).unwrap();

        assert!(!valid)
    }

    #[test]
    fn verify_multi_sig_works_for_invalid_signature() {
        let message = vec![1, 2, 3, 4, 5];

        let gen = Generator::new().unwrap();

        let sign_key1 = SignKey::new(None).unwrap();
        let ver_key1 = VerKey::new(&gen, &sign_key1).unwrap();
        let sign_key2 = SignKey::new(None).unwrap();
        let ver_key2 = VerKey::new(&gen, &SignKey::new(None).unwrap()).unwrap();

        let ver_keys = vec![
            &ver_key1,
            &ver_key2
        ];

        let signature1 = Bls::sign(&message, &sign_key1).unwrap();
        let signature2 = Bls::sign(&message, &sign_key2).unwrap();

        let signatures = vec![
            &signature1,
            &signature2
        ];

        let multi_signature_invalud = MultiSignature::new(&signatures).unwrap();
        let valid = Bls::verify_multi_sig(&multi_signature_invalud, &message, &ver_keys, &gen).unwrap();

        assert!(!valid)
    }
}