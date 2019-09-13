// Proof of knowledge of committed values in a vector Pedersen commitment.

// `ProverCommitting` will contains vectors of generators and random values.
// `ProverCommitting` has a `commit` method that optionally takes a value as blinding, if not provided, it creates its own.
// `ProverCommitting` has a `finish` method that results in creation of `ProverCommitted` object after consuming `ProverCommitting`
// `ProverCommitted` marks the end of commitment phase and has the final commitment.
// `ProverCommitted` has a method to generate the challenge by hashing all generators and commitment. It is optional
// to use this method as the challenge may come from a super-protocol or from verifier. It takes a vector of bytes that it includes for hashing for computing the challenge
// `ProverCommitted` has a method `gen_proof` to generate proof. It takes the secrets and the challenge to generate responses.
// During response generation `ProverCommitted` is consumed to create `Proof` object containing the commitments and responses.
// `Proof` can then be verified by the verifier.

use failure::{Backtrace, Context, Fail};
use std::fmt;

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum PoKVCErrorKind {
    #[fail(
        display = "Same no of bases and exponents required. {} bases and {} exponents",
        bases, exponents
    )]
    UnequalNoOfBasesExponents { bases: usize, exponents: usize },

    #[fail(display = "Error with message {:?}", msg)]
    GeneralError { msg: String },
}

#[derive(Debug)]
pub struct PoKVCError {
    inner: Context<PoKVCErrorKind>,
}

impl PoKVCError {
    pub fn kind(&self) -> PoKVCErrorKind {
        self.inner.get_context().clone()
    }

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

#[macro_export]
macro_rules! impl_PoK_VC {
    ( $ProverCommitting:ident, $ProverCommitted:ident, $Proof:ident, $group_element:ident, $group_element_vec:ident ) => {
        /// Proof of knowledge of messages in a vector commitment.
        /// Commit for each message.
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct $ProverCommitting {
            pub gens: $group_element_vec,
            blindings: FieldElementVector,
        }

        /// Receive or generate challenge. Compute response and proof
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct $ProverCommitted {
            pub gens: $group_element_vec,
            blindings: FieldElementVector,
            pub commitment: $group_element,
        }

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct $Proof {
            pub commitment: $group_element,
            pub responses: FieldElementVector,
        }

        impl $ProverCommitting {
            pub fn new() -> Self {
                Self {
                    gens: $group_element_vec::new(0),
                    blindings: FieldElementVector::new(0),
                }
            }

            /// generate a new random blinding if None provided
            pub fn commit(
                &mut self,
                gen: &$group_element,
                blinding: Option<&FieldElement>,
            ) -> usize {
                let blinding = match blinding {
                    Some(b) => b.clone(),
                    None => FieldElement::random(),
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
                    .multi_scalar_mul_const_time(&self.blindings)
                    .unwrap();
                $ProverCommitted {
                    gens: self.gens,
                    blindings: self.blindings,
                    commitment,
                }
            }

            pub fn get_index(
                &self,
                idx: usize,
            ) -> Result<(&$group_element, &FieldElement), PoKVCError> {
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
            pub fn to_bytes(&self) -> Vec<u8> {
                let mut bytes = vec![];
                for b in self.gens.as_slice() {
                    bytes.append(&mut b.to_bytes());
                }
                bytes.append(&mut self.commitment.to_bytes());
                bytes
            }

            /// This step will be done by the main protocol for which this PoK is a sub-protocol
            pub fn gen_challenge(&self, mut extra: Vec<u8>) -> FieldElement {
                let mut bytes = self.to_bytes();
                bytes.append(&mut extra);
                FieldElement::from_msg_hash(&bytes)
            }

            /// For each secret, generate a response as self.blinding[i] - challenge*secrets[i].
            pub fn gen_proof(
                self,
                challenge: &FieldElement,
                secrets: &[FieldElement],
            ) -> Result<$Proof, PoKVCError> {
                if secrets.len() != self.gens.len() {
                    return Err(PoKVCErrorKind::UnequalNoOfBasesExponents {
                        bases: self.gens.len(),
                        exponents: secrets.len(),
                    }
                    .into());
                }
                let mut responses = FieldElementVector::with_capacity(self.gens.len());
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
            /// Verify that bases[0]^responses[0] * bases[0]^responses[0] * ... bases[i]^responses[i] * commitment^challenge == random_commitment
            pub fn verify(
                &self,
                bases: &[$group_element],
                commitment: &$group_element,
                challenge: &FieldElement,
            ) -> Result<bool, PoKVCError> {
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
                let pr = points.multi_scalar_mul_var_time(&scalars).unwrap() - &self.commitment;
                Ok(pr.is_identity())
            }
        }
    };
}

#[cfg(test)]
macro_rules! test_PoK_VC {
    ( $n:ident, $ProverCommitting:ident, $ProverCommitted:ident, $Proof:ident, $group_element:ident, $group_element_vec:ident ) => {
        let mut gens = $group_element_vec::with_capacity($n);
        let mut secrets = FieldElementVector::with_capacity($n);
        let mut commiting = $ProverCommitting::new();
        for _ in 0..$n - 1 {
            let g = $group_element::random();
            commiting.commit(&g, None);
            gens.push(g);
            secrets.push(FieldElement::random());
        }

        // Add one of the blindings externally
        let g = $group_element::random();
        let r = FieldElement::random();
        commiting.commit(&g, Some(&r));
        let (g_, r_) = commiting.get_index($n - 1).unwrap();
        assert_eq!(g, *g_);
        assert_eq!(r, *r_);
        gens.push(g);
        secrets.push(FieldElement::random());

        // Bound check for get_index
        assert!(commiting.get_index($n).is_err());
        assert!(commiting.get_index($n + 1).is_err());

        let committed = commiting.finish();
        let commitment = gens.multi_scalar_mul_const_time(&secrets).unwrap();
        let challenge = committed.gen_challenge(commitment.to_bytes());
        let proof = committed.gen_proof(&challenge, secrets.as_slice()).unwrap();

        assert!(proof
            .verify(gens.as_slice(), &commitment, &challenge)
            .unwrap());

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
            .verify(gens.as_slice(), &commitment, &FieldElement::random())
            .unwrap());
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
    use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
    use amcl_wrapper::group_elem_g1::{G1Vector, G1};
    use amcl_wrapper::group_elem_g2::{G2Vector, G2};

    #[test]
    fn test_pok_vc_g1() {
        // Proof of knowledge of committed values in a vector commitment. The commitment lies in group G1.
        impl_PoK_VC!(ProverCommittingG1, ProverCommittedG1, ProofG1, G1, G1Vector);

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
        // Proof of knowledge of committed values in a vector commitment. The commitment lies in group G2.
        impl_PoK_VC!(ProverCommittingG2, ProverCommittedG2, ProofG2, G2, G2Vector);

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
