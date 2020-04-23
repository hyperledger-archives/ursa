//! Proof of knowledge of committed values in a vector Pedersen commitment––Commit and Prove scheme.
//!
//! `ProverCommitting` will contains vectors of generators and random values.
//! `ProverCommitting` has a `commit` method that optionally takes a value as blinding, if not provided, it creates its own.
//! `ProverCommitting` has a `finish` method that results in creation of `ProverCommitted` object after consuming `ProverCommitting`
//! `ProverCommitted` marks the end of commitment phase and has the final commitment.
//! `ProverCommitted` has a method to generate the challenge by hashing all generators and commitment. It is optional
//! to use this method as the challenge may come from a super-protocol or from verifier. It takes a vector of bytes that it includes for hashing for computing the challenge
//! `ProverCommitted` has a method `gen_proof` to generate proof. It takes the secrets and the challenge to generate responses.
//! During response generation `ProverCommitted` is consumed to create `Proof` object containing the commitments and responses.
//! `Proof` can then be verified by the verifier.

use crate::prelude::*;

use amcl_wrapper::constants::{
    CURVE_ORDER_ELEMENT_SIZE, FIELD_ORDER_ELEMENT_SIZE, GROUP_G1_SIZE, GROUP_G2_SIZE,
};
use amcl_wrapper::curve_order_elem::CurveOrderElement;
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use amcl_wrapper::group_elem_g2::{G2Vector, G2};
use failure::{Backtrace, Context, Fail};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Convenience importing module
pub mod prelude {
    pub use super::{PoKVCError, PoKVCErrorKind, ProofG1, ProverCommittedG1, ProverCommittingG1};
}

/// The errors that can happen when creating a proof of knowledge of a signature
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum PoKVCErrorKind {
    /// When the number of exponents and bases is out of sync
    #[fail(
        display = "Same no of bases and exponents required. {} bases and {} exponents",
        bases, exponents
    )]
    UnequalNoOfBasesExponents {
        /// The number of found bases
        bases: usize,
        /// The number of found exponents
        exponents: usize,
    },

    /// A generic error
    #[fail(display = "Error with message {:?}", msg)]
    GeneralError {
        /// The error message
        msg: String,
    },
}

/// Wrapper to hold the kind of error and a backtrace
#[derive(Debug)]
pub struct PoKVCError {
    inner: Context<PoKVCErrorKind>,
}

impl PoKVCError {
    /// Get the inner error kind
    pub fn kind(&self) -> PoKVCErrorKind {
        self.inner.get_context().clone()
    }

    /// Wrap an error kind
    pub fn from_kind(kind: PoKVCErrorKind) -> Self {
        Self {
            inner: Context::new("").context(kind),
        }
    }
}

impl From<PoKVCErrorKind> for PoKVCError {
    fn from(kind: PoKVCErrorKind) -> Self {
        Self {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<PoKVCErrorKind>> for PoKVCError {
    fn from(inner: Context<PoKVCErrorKind>) -> Self {
        Self { inner }
    }
}

impl Fail for PoKVCError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for PoKVCError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

/// Macro that creates all the classes used for Signature proofs of knowledge
/// We do this as a macro because we may want abstract this for other signatures
#[macro_export]
macro_rules! impl_PoK_VC {
    ( $ProverCommitting:ident, $ProverCommitted:ident, $Proof:ident, $group_element:ident, $group_element_vec:ident, $group_element_size:expr, $group_element_compressed_size:expr ) => {
        /// Proof of knowledge of messages in a vector commitment.
        /// Commit for each message or blinding factor used
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct $ProverCommitting {
            /// The generators to use as the bases
            pub gens: $group_element_vec,
            blindings: SignatureMessageVector,
        }

        /// Receive or generate challenge. Compute response and proof
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct $ProverCommitted {
            /// The generators to use as the bases
            pub gens: $group_element_vec,
            blindings: SignatureMessageVector,
            /// The commitment to be verified as part of the proof
            pub commitment: $group_element,
        }

        /// A proof of knowledge of a signature and hidden messages
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct $Proof {
            /// The proof commitment of all base_0*exp_0+base_1*exp_1
            pub commitment: $group_element,
            /// s values in the fiat shamir protocol
            pub responses: SignatureMessageVector,
        }

        impl $ProverCommitting {
            /// Create a new prover committing struct
            pub fn new() -> Self {
                Self {
                    gens: $group_element_vec::new(0),
                    blindings: SignatureMessageVector::new(0),
                }
            }

            /// Commit a base point with a blinding factor.
            /// The blinding factor is generated randomly if none is supplied
            /// generate a new random blinding if None provided
            pub fn commit(
                &mut self,
                gen: &$group_element,
                blinding: Option<&CurveOrderElement>,
            ) -> usize {
                let blinding = match blinding {
                    Some(b) => b.clone(),
                    None => CurveOrderElement::random(),
                };
                let idx = self.gens.len();
                self.gens.push(gen.clone());
                self.blindings.push(blinding);
                idx
            }

            /// Add pairwise product of (`self.gens`, self.blindings). Uses multi-exponentiation.
            pub fn finish(self) -> $ProverCommitted {
                let commitment = self
                    .gens
                    .multi_scalar_mul_const_time(self.blindings.as_slice())
                    .unwrap();
                $ProverCommitted {
                    gens: self.gens,
                    blindings: self.blindings,
                    commitment,
                }
            }

            /// Return the generator and blinding factor at `idx`
            pub fn get_index(
                &self,
                idx: usize,
            ) -> Result<(&$group_element, &CurveOrderElement), PoKVCError> {
                if idx >= self.gens.len() {
                    return Err(PoKVCErrorKind::GeneralError {
                        msg: format!("index {} greater than size {}", idx, self.gens.len()),
                    }
                    .into());
                }
                Ok((&self.gens[idx], &self.blindings[idx]))
            }
        }

        impl Default for $ProverCommitting {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $ProverCommitted {
            /// Convert the committed values to a byte array. Use for generating the fiat-shamir challenge
            pub fn to_bytes(&self) -> Vec<u8> {
                let mut bytes = vec![];
                for b in self.gens.as_slice() {
                    bytes.append(&mut b.to_vec());
                }
                bytes.append(&mut self.commitment.to_vec());
                bytes
            }

            /// This step will be done by the main protocol for which this PoK is a sub-protocol
            pub fn gen_challenge(&self, mut extra: Vec<u8>) -> CurveOrderElement {
                let mut bytes = self.to_bytes();
                bytes.append(&mut extra);
                CurveOrderElement::from_msg_hash(&bytes)
            }

            /// For each secret, generate a response as self.blinding[i] - challenge*secrets[i].
            pub fn gen_proof(
                self,
                challenge: &CurveOrderElement,
                secrets: &[CurveOrderElement],
            ) -> Result<$Proof, PoKVCError> {
                if secrets.len() != self.gens.len() {
                    return Err(PoKVCErrorKind::UnequalNoOfBasesExponents {
                        bases: self.gens.len(),
                        exponents: secrets.len(),
                    }
                    .into());
                }
                let mut responses = SignatureMessageVector::with_capacity(self.gens.len());
                for i in 0..self.gens.len() {
                    responses.push(&self.blindings[i] - (challenge * &secrets[i]));
                }
                Ok($Proof {
                    commitment: self.commitment,
                    responses,
                })
            }
        }

        impl $Proof {
            /// Computes the piece that goes into verifying the overall proof component
            /// by computing the c == H(U || \widehat{U} || nonce)
            /// This returns the \widehat{U}
            /// commitment is U
            pub fn get_challenge_contribution(
                &self,
                bases: &[$group_element],
                commitment: &$group_element,
                challenge: &CurveOrderElement,
            ) -> Result<$group_element, PoKVCError> {
                // bases[0]^responses[0] * bases[0]^responses[0] * ... bases[i]^responses[i] * commitment^challenge == random_commitment
                // =>
                // bases[0]^responses[0] * bases[0]^responses[0] * ... bases[i]^responses[i] * commitment^challenge * random_commitment^-1 == 1
                if bases.len() != self.responses.len() {
                    return Err(PoKVCErrorKind::UnequalNoOfBasesExponents {
                        bases: bases.len(),
                        exponents: self.responses.len(),
                    }
                    .into());
                }
                let mut points = $group_element_vec::from(bases);
                let mut scalars = self.responses.clone();
                points.push(commitment.clone());
                scalars.push(challenge.clone());
                let pr = points
                    .multi_scalar_mul_var_time(scalars.as_slice())
                    .unwrap();
                Ok(pr)
            }

            /// Verify that bases[0]^responses[0] * bases[0]^responses[0] * ... bases[i]^responses[i] * commitment^challenge == random_commitment
            pub fn verify(
                &self,
                bases: &[$group_element],
                commitment: &$group_element,
                challenge: &CurveOrderElement,
            ) -> Result<bool, PoKVCError> {
                let pr = self.get_challenge_contribution(bases, commitment, challenge)?
                    - &self.commitment;
                Ok(pr.is_identity())
            }

            /// Assumes this is the entire proof and is not a sub proof
            /// Used primarily during 2-PC signature creation
            pub fn verify_complete_proof(
                &self,
                bases: &[$group_element],
                commitment: &$group_element,
                challenge: &CurveOrderElement,
                nonce: &[u8],
            ) -> Result<bool, PoKVCError> {
                if bases.len() != self.responses.len() {
                    return Err(PoKVCErrorKind::UnequalNoOfBasesExponents {
                        bases: bases.len(),
                        exponents: self.responses.len(),
                    }
                    .into());
                }
                let mut points = $group_element_vec::from(bases);
                let mut scalars = self.responses.clone();
                points.push(commitment.clone());
                scalars.push(challenge.clone());
                let pr = points
                    .multi_scalar_mul_var_time(scalars.as_slice())
                    .unwrap();
                let mut pr_bytes = Vec::new();
                for b in bases.iter() {
                    pr_bytes.append(&mut b.to_vec())
                }
                pr_bytes.append(&mut pr.to_vec());
                pr_bytes.extend_from_slice(commitment.to_vec().as_slice());
                pr_bytes.extend_from_slice(nonce);
                let hash = CurveOrderElement::from_msg_hash(pr_bytes.as_slice()) - challenge;
                let pr = pr - &self.commitment;
                Ok(pr.is_identity() && hash.is_zero())
            }

            /// Convert to raw bytes
            pub fn to_bytes(&self) -> Vec<u8> {
                let mut result = self.commitment.to_vec();
                let len: u32 = self.responses.len() as u32;
                result.extend_from_slice(&len.to_be_bytes()[..]);
                for r in self.responses.iter() {
                    result.extend_from_slice(&r.to_bytes()[..]);
                }
                result
            }

            /// Convert from raw bytes
            pub fn from_bytes(data: &[u8]) -> Result<Self, PoKVCError> {
                if data.len() < $group_element_size + 4 {
                    return Err(PoKVCErrorKind::GeneralError {
                        msg: format!("Invalid length"),
                    }
                    .into());
                }
                let commitment =
                    $group_element::from_slice(&data[..$group_element_size]).map_err(|_| {
                        PoKVCErrorKind::GeneralError {
                            msg: format!("Invalid Length"),
                        }
                    })?;

                let mut offset = $group_element_size;

                let length = u32::from_be_bytes(*array_ref![data, offset, 4]) as usize;
                offset += 4;

                if data.len() < offset + length * FIELD_ORDER_ELEMENT_SIZE {
                    return Err(PoKVCErrorKind::GeneralError {
                        msg: format!("Invalid length"),
                    }
                    .into());
                }

                let mut responses = SignatureMessageVector::with_capacity(length);

                for _ in 0..length {
                    let end = offset + FIELD_ORDER_ELEMENT_SIZE;
                    let r =
                        CurveOrderElement::from(array_ref![data, offset, FIELD_ORDER_ELEMENT_SIZE]);
                    responses.push(r);
                    offset = end;
                }
                Ok(Self {
                    commitment,
                    responses,
                })
            }

            /// Convert to compressed raw bytes form. Use when sending over the wire
            pub fn to_compressed_bytes(&self) -> Vec<u8> {
                let responses_len = self.responses.len() as u32;
                let mut output = Vec::with_capacity(
                    $group_element_compressed_size
                        + self.responses.len() * CURVE_ORDER_ELEMENT_SIZE
                        + 4,
                );

                output.extend_from_slice(&self.commitment.to_compressed_bytes()[..]);
                output.extend_from_slice(&responses_len.to_be_bytes()[..]);
                for r in self.responses.iter() {
                    output.extend_from_slice(&r.to_compressed_bytes()[..]);
                }
                output
            }

            /// Convert from compressed bytes. Use when sending over the wire
            pub fn from_compressed_bytes(data: &[u8]) -> Result<Self, PoKVCError> {
                if data.len() < $group_element_compressed_size + 4 {
                    return Err(PoKVCErrorKind::GeneralError {
                        msg: format!("Invalid length"),
                    }
                    .into());
                }

                let commitment =
                    $group_element::from(array_ref![data, 0, $group_element_compressed_size]);
                let responses_len =
                    u32::from_be_bytes(*array_ref![data, $group_element_compressed_size, 4])
                        as usize;

                let mut offset = $group_element_compressed_size + 4;
                let mut responses_vec = Vec::with_capacity(responses_len);
                for _ in 0..responses_len {
                    let response =
                        SignatureMessage::from(array_ref![data, offset, CURVE_ORDER_ELEMENT_SIZE]);
                    responses_vec.push(response);
                    offset += CURVE_ORDER_ELEMENT_SIZE;
                }
                let responses = responses_vec.into();
                Ok(Self {
                    commitment,
                    responses,
                })
            }
        }

        impl CompressedBytes for $Proof {
            type Output = $Proof;
            type Error = PoKVCError;

            /// Convert to compressed raw bytes form. Use when sending over the wire
            fn to_compressed_bytes(&self) -> Vec<u8> {
                let responses_len = self.responses.len() as u32;
                let mut output = Vec::with_capacity(
                    $group_element_compressed_size
                        + self.responses.len() * CURVE_ORDER_ELEMENT_SIZE
                        + 4,
                );

                output.extend_from_slice(&self.commitment.to_compressed_bytes()[..]);
                output.extend_from_slice(&responses_len.to_be_bytes()[..]);
                for r in self.responses.iter() {
                    output.extend_from_slice(&r.to_compressed_bytes()[..]);
                }
                output
            }

            /// Convert from compressed bytes. Use when sending over the wire
            fn from_compressed_bytes<I: AsRef<[u8]>>(data: I) -> Result<Self, PoKVCError> {
                let data = data.as_ref();
                if data.len() < $group_element_compressed_size + 4 {
                    return Err(PoKVCErrorKind::GeneralError {
                        msg: format!("Invalid length"),
                    }
                    .into());
                }

                let commitment =
                    $group_element::from(array_ref![data, 0, $group_element_compressed_size]);
                let responses_len =
                    u32::from_be_bytes(*array_ref![data, $group_element_compressed_size, 4])
                        as usize;

                let mut offset = $group_element_compressed_size + 4;
                let mut responses_vec = Vec::with_capacity(responses_len);
                for _ in 0..responses_len {
                    let response =
                        SignatureMessage::from(array_ref![data, offset, CURVE_ORDER_ELEMENT_SIZE]);
                    responses_vec.push(response);
                    offset += CURVE_ORDER_ELEMENT_SIZE;
                }
                let responses = responses_vec.into();
                Ok(Self {
                    commitment,
                    responses,
                })
            }
        }
    };
}

#[cfg(test)]
macro_rules! test_PoK_VC {
    ( $n:ident, $ProverCommitting:ident, $ProverCommitted:ident, $Proof:ident, $group_element:ident, $group_element_vec:ident ) => {
        let mut gens = $group_element_vec::with_capacity($n);
        let mut secrets = SignatureMessageVector::with_capacity($n);
        let mut commiting = $ProverCommitting::new();
        for _ in 0..$n - 1 {
            let g = $group_element::random();
            commiting.commit(&g, None);
            gens.push(g);
            secrets.push(CurveOrderElement::random());
        }

        // Add one of the blindings externally
        let g = $group_element::random();
        let r = CurveOrderElement::random();
        commiting.commit(&g, Some(&r));
        let (g_, r_) = commiting.get_index($n - 1).unwrap();
        assert_eq!(g, *g_);
        assert_eq!(r, *r_);
        gens.push(g);
        secrets.push(CurveOrderElement::random());

        // Bound check for get_index
        assert!(commiting.get_index($n).is_err());
        assert!(commiting.get_index($n + 1).is_err());

        let committed = commiting.finish();
        let commitment = gens
            .multi_scalar_mul_const_time(secrets.as_slice())
            .unwrap();
        let challenge = committed.gen_challenge(committed.to_bytes());
        let proof = committed.gen_proof(&challenge, secrets.as_slice()).unwrap();

        assert!(proof
            .verify(gens.as_slice(), &commitment, &challenge)
            .unwrap());

        let proof_bytes = proof.to_bytes();
        assert_eq!(
            proof_bytes.len(),
            $group_element::random().to_vec().len()
                + 4
                + FIELD_ORDER_ELEMENT_SIZE * proof.responses.len()
        );
        let res_proof_cp = $Proof::from_bytes(&proof_bytes);
        assert!(res_proof_cp.is_ok());

        // Unequal number of generators and responses
        let mut gens_1 = gens.clone();
        let g1 = $group_element::random();
        gens_1.push(g1);
        // More generators
        assert!(proof
            .verify(gens_1.as_slice(), &commitment, &challenge)
            .is_err());

        let mut gens_2 = gens.clone();
        gens_2.pop();
        // Less generators
        assert!(proof
            .verify(gens_2.as_slice(), &commitment, &challenge)
            .is_err());

        // Wrong commitment fails to verify
        assert!(!proof
            .verify(gens.as_slice(), &$group_element::random(), &challenge)
            .unwrap());
        // Wrong challenge fails to verify
        assert!(!proof
            .verify(gens.as_slice(), &commitment, &CurveOrderElement::random())
            .unwrap());
    };
}

// Proof of knowledge of committed values in a vector commitment. The commitment lies in group G1.
impl_PoK_VC!(
    ProverCommittingG1,
    ProverCommittedG1,
    ProofG1,
    G1,
    G1Vector,
    GROUP_G1_SIZE,
    FIELD_ORDER_ELEMENT_SIZE
);

// Proof of knowledge of committed values in a vector commitment. The commitment lies in group G2.
impl_PoK_VC!(
    ProverCommittingG2,
    ProverCommittedG2,
    ProofG2,
    G2,
    G2Vector,
    GROUP_G2_SIZE,
    2 * FIELD_ORDER_ELEMENT_SIZE
);

#[cfg(test)]
mod tests {
    use super::*;
    use amcl_wrapper::curve_order_elem::CurveOrderElement;
    use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
    use amcl_wrapper::group_elem_g1::{G1Vector, G1};
    use amcl_wrapper::group_elem_g2::{G2Vector, G2};

    #[test]
    fn test_pok_vc_g1() {
        let n = 5;
        test_PoK_VC!(
            n,
            ProverCommittingG1,
            ProverCommittedG1,
            ProofG1,
            G1,
            G1Vector
        );
    }

    #[test]
    fn test_pok_vc_g2() {
        let n = 5;
        test_PoK_VC!(
            n,
            ProverCommittingG2,
            ProverCommittedG2,
            ProofG2,
            G2,
            G2Vector
        );
    }
}
