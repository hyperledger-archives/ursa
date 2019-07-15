use errors::prelude::*;
use pair::{GroupOrderElement, Pair, PointG1, PointG2};

use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// BLS generator point.
/// BLS algorithm requires choosing of generator point that must be known to all parties.
/// The most of BLS methods require generator to be provided.
#[derive(Debug, Serialize, Deserialize)]
pub struct Generator {
    point: PointG2,
    bytes: Vec<u8>,
}

impl Generator {
    /// Creates and returns random generator point that satisfies BLS algorithm requirements.
    ///
    /// # Example
    ///
    /// ```
    /// use ursa::bls::Generator;
    /// Generator::new().unwrap();
    /// ```
    pub fn new() -> UrsaCryptoResult<Generator> {
        let point = PointG2::new()?;
        Ok(Generator {
            point,
            bytes: point.to_bytes()?,
        })
    }

    /// Returns BLS generator point bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// use ursa::bls::*;
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
    /// use ursa::bls::Generator;
    /// let gen = Generator::new().unwrap();
    /// let gen_bytes = gen.as_bytes();
    /// Generator::from_bytes(gen_bytes).unwrap();
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> UrsaCryptoResult<Generator> {
        Ok(Generator {
            point: PointG2::from_bytes(bytes)?,
            bytes: bytes.to_vec(),
        })
    }
}

/// BLS sign key.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignKey {
    group_order_element: GroupOrderElement,
    bytes: Vec<u8>,
}

impl SignKey {
    /// Creates and returns random (or seeded from seed) BLS sign key algorithm requirements.
    ///
    /// # Example
    ///
    /// ```
    /// use ursa::bls::SignKey;
    /// SignKey::new(None).unwrap();
    /// ```
    pub fn new(seed: Option<&[u8]>) -> UrsaCryptoResult<SignKey> {
        let group_order_element = match seed {
            Some(seed) => GroupOrderElement::new_from_seed(seed)?,
            _ => GroupOrderElement::new()?,
        };

        Ok(SignKey {
            group_order_element,
            bytes: group_order_element.to_bytes()?,
        })
    }

    /// Returns BLS sign key bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// use ursa::bls::SignKey;
    /// let sign_key = SignKey::new(None).unwrap();
    /// let bytes = sign_key.as_bytes();
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Creates and returns BLS sign key from bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// use ursa::bls::SignKey;
    /// let sign_key = SignKey::new(None).unwrap();
    /// let bytes = sign_key.as_bytes();
    /// let sign_key = SignKey::from_bytes(bytes).unwrap();
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> UrsaCryptoResult<SignKey> {
        Ok(SignKey {
            group_order_element: GroupOrderElement::from_bytes(bytes)?,
            bytes: bytes.to_vec(),
        })
    }
}

/// BLS verification key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerKey {
    point: PointG2,
    bytes: Vec<u8>,
}

impl VerKey {
    /// Creates and returns BLS ver key that corresponds to sign key.
    ///
    /// # Example
    ///
    /// ```
    /// use ursa::bls::{Generator, SignKey, VerKey};
    /// let gen = Generator::new().unwrap();
    /// let sign_key = SignKey::new(None).unwrap();
    /// VerKey::new(&gen, &sign_key).unwrap();
    /// ```
    pub fn new(gen: &Generator, sign_key: &SignKey) -> UrsaCryptoResult<VerKey> {
        let point = gen.point.mul(&sign_key.group_order_element)?;

        Ok(VerKey {
            point,
            bytes: point.to_bytes()?,
        })
    }

    /// Returns BLS verification key to bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// use ursa::bls::{Generator, SignKey, VerKey};
    /// let gen = Generator::new().unwrap();
    /// let sign_key = SignKey::new(None).unwrap();
    /// let ver_key = VerKey::new(&gen, &sign_key).unwrap();
    /// let bytes = ver_key.as_bytes();
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Creates and returns BLS verification key from bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// use ursa::bls::{Generator, SignKey, VerKey};
    /// let gen = Generator::new().unwrap();
    /// let sign_key = SignKey::new(None).unwrap();
    /// let ver_key = VerKey::new(&gen, &sign_key).unwrap();
    /// let bytes = ver_key.as_bytes();
    /// let ver_key2 = VerKey::from_bytes(bytes).unwrap();
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> UrsaCryptoResult<VerKey> {
        let point = PointG2::from_bytes(bytes)?;
        Ok(VerKey {
            point,
            bytes: bytes.to_vec(),
        })
    }
}

/// Proof of possession for BLS verification key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfPossession {
    point: PointG1,
    bytes: Vec<u8>,
}

impl ProofOfPossession {
    /// Creates and returns BLS proof of possession that corresponds to ver key.
    ///
    /// # Arguments
    ///
    /// * `ver_key` - Ver key
    /// * `sign_key` - Sign key
    ///
    /// # Example
    ///
    /// ```
    /// use ursa::bls::{Generator, SignKey, VerKey, ProofOfPossession};
    /// let gen = Generator::new().unwrap();
    /// let sign_key = SignKey::new(None).unwrap();
    /// let ver_key = VerKey::new(&gen, &sign_key).unwrap();
    /// ProofOfPossession::new(&ver_key, &sign_key).unwrap();
    /// ```
    pub fn new(ver_key: &VerKey, sign_key: &SignKey) -> UrsaCryptoResult<ProofOfPossession> {
        let point = Bls::_gen_signature(&ver_key.bytes, sign_key, Keccak256::default())?;

        Ok(ProofOfPossession {
            point,
            bytes: point.to_bytes()?,
        })
    }

    /// Returns BLS proof of possession to bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// use ursa::bls::{Generator, SignKey, VerKey, ProofOfPossession};
    /// let gen = Generator::new().unwrap();
    /// let sign_key = SignKey::new(None).unwrap();
    /// let ver_key = VerKey::new(&gen, &sign_key).unwrap();
    /// let signature = ProofOfPossession::new(&ver_key, &sign_key).unwrap();
    /// let bytes = signature.as_bytes();
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Creates and returns BLS proof of possession from bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// use ursa::bls::{Generator, SignKey, VerKey, ProofOfPossession};
    /// let gen = Generator::new().unwrap();
    /// let sign_key = SignKey::new(None).unwrap();
    /// let ver_key = VerKey::new(&gen, &sign_key).unwrap();
    /// let signature = ProofOfPossession::new(&ver_key, &sign_key).unwrap();
    /// let bytes = signature.as_bytes();
    /// let signature2 = ProofOfPossession::from_bytes(bytes).unwrap();
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> UrsaCryptoResult<ProofOfPossession> {
        let point = PointG1::from_bytes(bytes)?;
        Ok(ProofOfPossession {
            point,
            bytes: bytes.to_vec(),
        })
    }
}

/// BLS signature.
#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    point: PointG1,
    bytes: Vec<u8>,
}

impl Signature {
    /// Returns BLS signature to bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// use ursa::bls::{SignKey, Signature, Bls};
    /// let sign_key = SignKey::new(None).unwrap();
    /// let message = vec![1, 2, 3, 4, 5];
    /// let signature = Bls::sign(&message, &sign_key).unwrap();
    /// let bytes = signature.as_bytes();
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Creates and returns BLS signature from bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// use ursa::bls::{SignKey, Signature, Bls};
    /// let sign_key = SignKey::new(None).unwrap();
    /// let message = vec![1, 2, 3, 4, 5];
    /// let signature = Bls::sign(&message, &sign_key).unwrap();
    /// let bytes = signature.as_bytes();
    /// let signature2 = Signature::from_bytes(bytes).unwrap();
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> UrsaCryptoResult<Signature> {
        let point = PointG1::from_bytes(bytes)?;
        Ok(Signature {
            point,
            bytes: bytes.to_vec(),
        })
    }
}

/// BLS multi signature.
#[derive(Debug, Serialize, Deserialize)]
pub struct MultiSignature {
    point: PointG1,
    bytes: Vec<u8>,
}

impl MultiSignature {
    /// Creates and returns multi signature for provided list of signatures.
    ///
    /// # Arguments
    ///
    /// * `signatures` - List of signatures
    ///
    /// # Example
    ///
    /// ```
    /// use ursa::bls::*;
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
    pub fn new(signatures: &[&Signature]) -> UrsaCryptoResult<MultiSignature> {
        let mut point = PointG1::new_inf()?;

        for signature in signatures {
            point = point.add(&signature.point)?;
        }

        Ok(MultiSignature {
            point,
            bytes: point.to_bytes()?,
        })
    }

    /// Returns BLS multi signature bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// use ursa::bls::{SignKey, Bls, MultiSignature};
    /// let message = vec![1, 2, 3, 4, 5];
    /// let sign_key1 = SignKey::new(None).unwrap();
    /// let sign_key2 = SignKey::new(None).unwrap();
    /// let signature1 = Bls::sign(&message, &sign_key1).unwrap();
    /// let signature2 = Bls::sign(&message, &sign_key2).unwrap();
    /// let signatures = vec![&signature1, &signature2];
    /// let multi_signature = MultiSignature::new(&signatures).unwrap();
    /// let bytes = multi_signature.as_bytes();
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Creates and returns BLS multi signature from bytes representation.
    ///
    /// # Example
    ///
    /// ```
    /// use ursa::bls::{SignKey, Bls, MultiSignature};
    /// let message = vec![1, 2, 3, 4, 5];
    /// let sign_key1 = SignKey::new(None).unwrap();
    /// let sign_key2 = SignKey::new(None).unwrap();
    /// let signature1 = Bls::sign(&message, &sign_key1).unwrap();
    /// let signature2 = Bls::sign(&message, &sign_key2).unwrap();
    /// let signatures = vec![&signature1, &signature2];
    /// let multi_signature = MultiSignature::new(&signatures).unwrap();
    /// let bytes = multi_signature.as_bytes();
    /// let multi_signature2 = MultiSignature::from_bytes(bytes).unwrap();
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> UrsaCryptoResult<MultiSignature> {
        let point = PointG1::from_bytes(bytes)?;
        Ok(MultiSignature {
            point,
            bytes: bytes.to_vec(),
        })
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
    /// use ursa::bls::*;
    /// let message = vec![1, 2, 3, 4, 5];
    /// let sign_key = SignKey::new(None).unwrap();
    /// Bls::sign(&message, &sign_key).unwrap();
    /// ```
    pub fn sign(message: &[u8], sign_key: &SignKey) -> UrsaCryptoResult<Signature> {
        let point = Bls::_gen_signature(message, sign_key, Sha256::default())?;

        Ok(Signature {
            point,
            bytes: point.to_bytes()?,
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
    /// use ursa::bls::*;
    /// let gen = Generator::new().unwrap();
    /// let sign_key = SignKey::new(None).unwrap();
    /// let ver_key = VerKey::new(&gen, &sign_key).unwrap();
    /// let message = vec![1, 2, 3, 4, 5];
    /// let signature = Bls::sign(&message, &sign_key).unwrap();
    ///
    /// let valid = Bls::verify(&signature, &message, &ver_key, &gen).unwrap();
    /// assert!(valid);
    /// ```
    pub fn verify(
        signature: &Signature,
        message: &[u8],
        ver_key: &VerKey,
        gen: &Generator,
    ) -> UrsaCryptoResult<bool> {
        Bls::_verify_signature(
            &signature.point,
            message,
            &ver_key.point,
            gen,
            Sha256::default(),
        )
    }

    /// Verifies the proof of possession and returns true - if valid or false otherwise.
    ///
    /// # Arguments
    ///
    /// * `pop` - Proof of possession
    /// * `ver_key` - Verification key
    /// * `gen` - Generator point
    ///
    /// # Example
    ///
    /// ```
    /// use ursa::bls::*;
    /// let gen = Generator::new().unwrap();
    /// let sign_key = SignKey::new(None).unwrap();
    /// let ver_key = VerKey::new(&gen, &sign_key).unwrap();
    /// let pop = ProofOfPossession::new(&ver_key, &sign_key).unwrap();
    ///
    /// let valid = Bls::verify_proof_of_posession(&pop, &ver_key, &gen).unwrap();
    /// assert!(valid);
    /// ```
    pub fn verify_proof_of_posession(
        pop: &ProofOfPossession,
        ver_key: &VerKey,
        gen: &Generator,
    ) -> UrsaCryptoResult<bool> {
        Bls::_verify_signature(
            &pop.point,
            &ver_key.bytes,
            &ver_key.point,
            gen,
            Keccak256::default(),
        )
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
    /// use ursa::bls::*;
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
    pub fn verify_multi_sig(
        multi_sig: &MultiSignature,
        message: &[u8],
        ver_keys: &[&VerKey],
        gen: &Generator,
    ) -> UrsaCryptoResult<bool> {
        // Since each signer (identified by a Verkey) has signed the same message, the public keys
        // can be added together to form the aggregated verkey
        let mut aggregated_verkey = PointG2::new_inf()?;
        for ver_key in ver_keys {
            aggregated_verkey = aggregated_verkey.add(&ver_key.point)?;
        }

        // TODO: Add a new method that takes a message and an aggregated verkey and expose using
        // the C API. Verifiers can thus cache the aggregated verkey and avoid several EC point additions.
        // The code below should be moved to such method.

        Bls::_verify_signature(
            &multi_sig.point,
            message,
            &aggregated_verkey,
            gen,
            Sha256::default(),
        )
    }

    fn _gen_signature<T>(message: &[u8], sign_key: &SignKey, hasher: T) -> UrsaCryptoResult<PointG1>
    where
        T: Digest,
    {
        Bls::_hash(message, hasher)?.mul(&sign_key.group_order_element)
    }

    pub fn _verify_signature<T>(
        signature: &PointG1,
        message: &[u8],
        ver_key: &PointG2,
        gen: &Generator,
        hasher: T,
    ) -> UrsaCryptoResult<bool>
    where
        T: Digest,
    {
        let h = Bls::_hash(message, hasher)?;
        // e(&signature, &gen.point) == e(&h, &ver_key) => 1 == e(&h, &ver_key)*e(&signature, &gen.point)^-1 == e(&h, &ver_key)*e(&signature, -&gen.point)
        Pair::pair2(&signature, &gen.point.neg()?, &h, &ver_key)?.is_unity()
    }

    fn _hash<T>(message: &[u8], mut hasher: T) -> UrsaCryptoResult<PointG1>
    where
        T: Digest,
    {
        hasher.input(message);
        Ok(PointG1::from_hash(hasher.result().as_slice())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test Generator
    #[test]
    fn generator_new_works() {
        Generator::new().unwrap();
    }

    // Test SignKey
    #[test]
    fn sign_key_new_works() {
        SignKey::new(None).unwrap();
    }

    #[test]
    fn sign_key_new_works_for_seed() {
        let seed = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 2, 3, 4, 5, 6, 7, 8, 9, 10, 21, 2, 3, 4, 5, 6, 7, 8,
            9, 10, 31, 32,
        ];
        SignKey::new(Some(&seed)).unwrap();
    }

    #[test]
    fn sign_key_as_bytes_works() {
        let sign_key = SignKey::new(None).unwrap();
        let bytes = sign_key.as_bytes();
        assert!(bytes.len() > 0);
    }

    #[test]
    fn sign_key_from_bytes_works() {
        let sign_key = SignKey::new(None).unwrap();
        let bytes = sign_key.as_bytes();
        SignKey::from_bytes(bytes).unwrap();
    }

    // Test VerKey
    #[test]
    fn ver_key_new_works() {
        let gen = Generator::new().unwrap();
        let sign_key = SignKey::new(None).unwrap();
        VerKey::new(&gen, &sign_key).unwrap();
    }

    #[test]
    fn ver_key_as_bytes_works() {
        let gen = Generator::new().unwrap();
        let sign_key = SignKey::new(None).unwrap();
        let ver_key = VerKey::new(&gen, &sign_key).unwrap();
        let bytes = ver_key.as_bytes();
        assert!(bytes.len() == ver_key.bytes.len());
    }

    #[test]
    fn ver_key_from_bytes_works() {
        let gen = Generator::new().unwrap();
        let sign_key = SignKey::new(None).unwrap();
        let ver_key = VerKey::new(&gen, &sign_key).unwrap();
        let bytes = ver_key.as_bytes();
        let ver_key2 = VerKey::from_bytes(bytes).unwrap();
        assert!(ver_key2.point == ver_key.point);
    }

    // Test ProofOfPossession
    #[test]
    fn proof_of_possession_new_works() {
        let gen = Generator::new().unwrap();
        let sign_key = SignKey::new(None).unwrap();
        let ver_key = VerKey::new(&gen, &sign_key).unwrap();
        ProofOfPossession::new(&ver_key, &sign_key).unwrap();
    }

    #[test]
    fn proof_of_possession_as_bytes_works() {
        let gen = Generator::new().unwrap();
        let sign_key = SignKey::new(None).unwrap();
        let ver_key = VerKey::new(&gen, &sign_key).unwrap();
        let signature = ProofOfPossession::new(&ver_key, &sign_key).unwrap();
        let bytes = signature.as_bytes();
        assert!(bytes.len() == signature.bytes.len());
    }

    #[test]
    fn proof_of_possession_from_bytes_works() {
        let gen = Generator::new().unwrap();
        let sign_key = SignKey::new(None).unwrap();
        let ver_key = VerKey::new(&gen, &sign_key).unwrap();
        let signature = ProofOfPossession::new(&ver_key, &sign_key).unwrap();
        let bytes = signature.as_bytes();
        let signature2 = ProofOfPossession::from_bytes(bytes).unwrap();
        assert!(signature2.point == signature.point);
    }

    // Test Bls
    #[test]
    fn bls_sign_works() {
        let sign_key = SignKey::new(None).unwrap();
        let message = vec![1, 2, 3, 4, 5];

        Bls::sign(&message, &sign_key).unwrap();
    }

    #[test]
    fn signature_as_bytes_works() {
        let sign_key = SignKey::new(None).unwrap();
        let message = vec![1, 2, 3, 4, 5];
        let signature = Bls::sign(&message, &sign_key).unwrap();
        let bytes = signature.as_bytes();
        assert!(bytes.len() == signature.bytes.len());
    }

    #[test]
    fn signature_from_bytes_works() {
        let sign_key = SignKey::new(None).unwrap();
        let message = vec![1, 2, 3, 4, 5];
        let signature = Bls::sign(&message, &sign_key).unwrap();
        let bytes = signature.as_bytes();
        let signature2 = Signature::from_bytes(bytes).unwrap();
        assert!(signature2.point == signature.point);
    }

    #[test]
    fn multi_signature_new_works() {
        let message = vec![1, 2, 3, 4, 5];

        let sign_key1 = SignKey::new(None).unwrap();
        let sign_key2 = SignKey::new(None).unwrap();

        let signature1 = Bls::sign(&message, &sign_key1).unwrap();
        let signature2 = Bls::sign(&message, &sign_key2).unwrap();

        let signatures = vec![&signature1, &signature2];

        MultiSignature::new(&signatures).unwrap();
    }

    #[test]
    fn multi_signature_as_bytes_works() {
        let message = vec![1, 2, 3, 4, 5];

        let sign_key1 = SignKey::new(None).unwrap();
        let sign_key2 = SignKey::new(None).unwrap();

        let signature1 = Bls::sign(&message, &sign_key1).unwrap();
        let signature2 = Bls::sign(&message, &sign_key2).unwrap();

        let signatures = vec![&signature1, &signature2];

        let multi_signature = MultiSignature::new(&signatures).unwrap();
        let bytes = multi_signature.as_bytes();
        assert!(bytes.len() == multi_signature.bytes.len());
    }

    #[test]
    fn multi_signature_from_bytes_works() {
        let message = vec![1, 2, 3, 4, 5];

        let sign_key1 = SignKey::new(None).unwrap();
        let sign_key2 = SignKey::new(None).unwrap();

        let signature1 = Bls::sign(&message, &sign_key1).unwrap();
        let signature2 = Bls::sign(&message, &sign_key2).unwrap();

        let signatures = vec![&signature1, &signature2];

        let multi_signature = MultiSignature::new(&signatures).unwrap();
        let bytes = multi_signature.as_bytes();
        let multi_signature2 = MultiSignature::from_bytes(bytes).unwrap();
        assert!(multi_signature2.point == multi_signature.point);
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
    fn verify_pop_works() {
        let gen = Generator::new().unwrap();
        let sign_key = SignKey::new(None).unwrap();
        let ver_key = VerKey::new(&gen, &sign_key).unwrap();
        let pop = ProofOfPossession::new(&ver_key, &sign_key).unwrap();

        let valid = Bls::verify_proof_of_posession(&pop, &ver_key, &gen).unwrap();
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

        let ver_keys = vec![&ver_key1, &ver_key2];

        let signature1 = Bls::sign(&message, &sign_key1).unwrap();
        let signature2 = Bls::sign(&message, &sign_key2).unwrap();

        let signatures = vec![&signature1, &signature2];

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

        let ver_keys = vec![&ver_key1, &ver_key2];

        let signature1 = Bls::sign(&message, &sign_key1).unwrap();
        let signature2 = Bls::sign(&message, &sign_key2).unwrap();

        let signatures = vec![&signature1, &signature2];

        let multi_signature = MultiSignature::new(&signatures).unwrap();
        let valid =
            Bls::verify_multi_sig(&multi_signature, &message_invalid, &ver_keys, &gen).unwrap();

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

        let ver_keys = vec![&ver_key1, &ver_key2];

        let signature1 = Bls::sign(&message, &sign_key1).unwrap();
        let signature2 = Bls::sign(&message, &sign_key2).unwrap();

        let signatures = vec![&signature1, &signature2];

        let multi_signature_invalid = MultiSignature::new(&signatures).unwrap();
        let valid =
            Bls::verify_multi_sig(&multi_signature_invalid, &message, &ver_keys, &gen).unwrap();

        assert!(!valid)
    }
}
