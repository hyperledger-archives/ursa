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

#[macro_export]
macro_rules! impl_PoK_VC {
    ( $ProverCommitting:ident, $ProverCommitted:ident, $Proof:ident, $group_element:ident, $group_element_vec:ident ) => {
        /// Proof of knowledge of messages in a vector commitment.
        /// Commit for each message.
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct $ProverCommitting {
            gens: $group_element_vec,
            blindings: FieldElementVector,
        }

        /// Receive or generate challenge. Compute response and proof
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct $ProverCommitted {
            gens: $group_element_vec,
            blindings: FieldElementVector,
            commitment: $group_element,
        }

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct $Proof {
            commitment: $group_element,
            responses: FieldElementVector,
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
            ) -> Result<(&$group_element, &FieldElement), PSError> {
                if idx >= self.gens.len() {
                    return Err(PSError::GeneralError {
                        msg: format!("index {} greater than size {}", idx, self.gens.len()),
                    });
                }
                Ok((&self.gens[idx], &self.blindings[idx]))
            }
        }

        impl $ProverCommitted {
            /// This step will be done by the main protocol for which this PoK is a sub-protocol
            pub fn gen_challenge(&self, mut extra: Vec<u8>) -> FieldElement {
                let mut bytes = vec![];
                for b in self.gens.as_slice() {
                    bytes.append(&mut b.to_bytes());
                }
                bytes.append(&mut self.commitment.to_bytes());
                bytes.append(&mut extra);
                FieldElement::from_msg_hash(&bytes)
            }

            /// For each secret, generate a response as self.blinding[i] - challenge*secrets[i].
            pub fn gen_proof(
                self,
                challenge: &FieldElement,
                secrets: &[FieldElement],
            ) -> Result<$Proof, PSError> {
                if secrets.len() != self.gens.len() {
                    return Err(PSError::UnequalNoOfBasesExponents {
                        bases: self.gens.len(),
                        exponents: secrets.len(),
                    });
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
            ) -> Result<bool, PSError> {
                // bases[0]^responses[0] * bases[0]^responses[0] * ... bases[i]^responses[i] * commitment^challenge == random_commitment
                // =>
                // bases[0]^responses[0] * bases[0]^responses[0] * ... bases[i]^responses[i] * commitment^challenge * random_commitment^-1 == 1
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
#[macro_export]
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

        let committed = commiting.finish();
        let commitment = gens.multi_scalar_mul_const_time(&secrets).unwrap();
        let challenge = committed.gen_challenge(commitment.to_bytes());
        let proof = committed.gen_proof(&challenge, secrets.as_slice()).unwrap();

        assert!(proof
            .verify(gens.as_slice(), &commitment, &challenge)
            .unwrap());
        // Wrong challenge or commitment fails to verify
        assert!(!proof
            .verify(gens.as_slice(), &$group_element::random(), &challenge)
            .unwrap());
        assert!(!proof
            .verify(gens.as_slice(), &commitment, &FieldElement::random())
            .unwrap());
    };
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    // XXX: Error for VC should be independent of PS
    use crate::errors::PSError;
    use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
    use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
    use amcl_wrapper::group_elem_g1::{G1Vector, G1};
    use amcl_wrapper::group_elem_g2::{G2Vector, G2};

    #[test]
    fn test_PoK_VC_G1() {
        // Proof of knowledge of committed values in a vector commitment. The committment lies in group G1.
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
    fn test_PoK_VC_G2() {
        // Proof of knowledge of committed values in a vector commitment. The committment lies in group G2.
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
