/*
    SPDX-License-Identifier: Apache-2.0 OR MIT
*/

use crate::errors::{BulletproofError, BulletproofErrorKind};
use crate::transcript::TranscriptProtocol;
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::GroupElementVector;
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use core::iter;
use merlin::Transcript;

// The following protocol is taken from Dalek's implementation. The code has inline
// comments but for a detailed documentation, check following links:
// https://doc-internal.dalek.rs/bulletproofs/inner_product_proof/index.html
// https://doc-internal.dalek.rs/bulletproofs/notes/inner_product_proof/index.html
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct InnerProductArgumentProof {
    pub L: G1Vector,
    pub R: G1Vector,
    pub a: FieldElement,
    pub b: FieldElement,
}

pub struct IPP {}

impl IPP {
    /// Create an inner-product proof. Adaptation of Protocol 2 from the paper.
    /// G_factors and H_factors are the element-wise multiplicands (scalar multiplication) of vectors
    /// G and H. The proof is created with respect to the bases G', H', where G'_i = G_i.G_factors_i
    /// and H'_i = H_i.H_factors_i. Simplistically looking, vector G and H can be transformed to
    /// G' and H' in the beginning but that causes extra scalar multiplication. To avoid this, the
    /// (G/H)_factors are accommodated with other scalars (a, b). G_factors and H_factors are needed
    /// when the outer protocol needs to do the inner product proof over modified vectors.
    /// G_factors and H_factors are not described in the paper but were introduced in Dalek's
    /// implementation.
    /// The `transcript` is passed in as a parameter so that the
    /// challenges depend on the *entire* transcript (including parent
    /// protocols).
    ///
    /// The lengths of the vectors must all be the same, and must all be
    /// power of 2.
    pub fn create_ipp(
        transcript: &mut Transcript,
        u: &G1,
        G_factors: &FieldElementVector,
        H_factors: &FieldElementVector,
        G_vec: &G1Vector,
        H_vec: &G1Vector,
        a_vec: &FieldElementVector,
        b_vec: &FieldElementVector,
    ) -> InnerProductArgumentProof {
        let mut n = G_vec.len();

        // All of the input vectors must have a length that is a power of two.
        assert!(n.is_power_of_two());

        // All of the input vectors must have the same length.
        assert_eq!(H_vec.len(), n);
        assert_eq!(a_vec.len(), n);
        assert_eq!(b_vec.len(), n);
        assert_eq!(G_factors.len(), n);
        assert_eq!(H_factors.len(), n);

        let mut G = G_vec.clone();
        let mut H = H_vec.clone();
        let mut a = a_vec.clone();
        let mut b = b_vec.clone();

        transcript.innerproduct_domain_sep(n as u64);

        let lg_n = n.next_power_of_two().trailing_zeros() as usize;
        let mut L_vec = G1Vector::with_capacity(lg_n);
        let mut R_vec = G1Vector::with_capacity(lg_n);

        // Keeps track of whether G_factors and H_factors have been accommodated which are done in
        // the first iteration of the loop. G_factors and H_factors are not used in subsequent iterations
        let mut factors_accommodated = false;

        // Split `G_factors`, `H_factors` in half
        let (G_factors_L, G_factors_R) = G_factors.split_at(n / 2);
        let (H_factors_L, H_factors_R) = H_factors.split_at(n / 2);
        // For a_L o G_factors_R
        let mut a_L_G_R: FieldElementVector;
        // For b_R o H_factors_L
        let mut b_R_H_L: FieldElementVector;
        // For a_R o G_factors_L
        let mut a_R_G_L: FieldElementVector;
        // For b_L o H_factors_R
        let mut b_L_H_R: FieldElementVector;

        // As algorithm 2 in the paper.
        while n != 1 {
            n = n / 2;

            // Split vectors `a`, `b`, `G`, `H`, in half, first half has suffix `_L`,
            // second half has suffix `_R`, so `a_L`, `a_R` would be the 2 halves of vector `a`.
            let (mut a_L, a_R) = a.split_at(n);
            let (mut b_L, b_R) = b.split_at(n);
            let (mut G_L, G_R) = G.split_at(n);
            let (mut H_L, H_R) = H.split_at(n);

            // c_L = a_L * b_R
            let c_L = a_L.inner_product(&b_R).unwrap();
            // c_R = a_R * b_L
            let c_R = a_R.inner_product(&b_L).unwrap();

            let mut L_0 = vec![];
            if !factors_accommodated {
                // a_L o G_factors_R
                a_L_G_R = a_L.hadamard_product(&G_factors_R).unwrap();
                L_0.extend(a_L_G_R.as_slice());
                // b_R o H_factors_L
                b_R_H_L = b_R.hadamard_product(&H_factors_L).unwrap();
                L_0.extend(b_R_H_L.as_slice());
            } else {
                L_0.extend(a_L.iter());
                L_0.extend(b_R.iter());
            }

            L_0.push(&c_L);

            let mut L_1 = vec![];
            L_1.extend(G_R.iter());
            L_1.extend(H_L.iter());
            L_1.push(&u);

            // While computing L and R below, variable time scalar multiplication is used.
            // This is because the protocol is not zero-knowledge and a zero-knowledge protocol
            // using this technique will have already blinded the vectors `a` and `b` in some way.

            // L = G_R^(a_L o G_factors_R) * H_L^(b_R o H_factors_L) * Q^c_L
            let L = G1Vector::inner_product_var_time_with_ref_vecs(L_1, L_0).unwrap();

            let mut R_0 = vec![];
            if !factors_accommodated {
                // a_R o G_factors_L
                a_R_G_L = a_R.hadamard_product(&G_factors_L).unwrap();
                R_0.extend(a_R_G_L.as_slice());
                // b_L o H_factors_R
                b_L_H_R = b_L.hadamard_product(&H_factors_R).unwrap();
                R_0.extend(b_L_H_R.as_slice());
            } else {
                R_0.extend(a_R.iter());
                R_0.extend(b_L.iter());
            }

            R_0.push(&c_R);

            let mut R_1 = vec![];
            R_1.extend(G_L.iter());
            R_1.extend(H_R.iter());
            R_1.push(&u);

            // R = G_R^(a_R o G_factors_L) * H_R^(b_L o H_factors_R) * Q^c_R
            let R = G1Vector::inner_product_var_time_with_ref_vecs(R_1, R_0).unwrap();

            transcript.commit_point(b"L", &L);
            transcript.commit_point(b"R", &R);

            L_vec.push(L);
            R_vec.push(R);

            // Generate challenge for Fiat-Shamir
            let x = transcript.challenge_scalar(b"x");
            let x_inv = x.inverse();

            // Prepare vectors and generators for next round of recursion
            for i in 0..n {
                a_L[i] = &a_L[i] * &x + &x_inv * &a_R[i];
                b_L[i] = &b_L[i] * &x_inv + &x * &b_R[i];
                if !factors_accommodated {
                    // G_L[i] = (x_inv * G_factors_L[i])*G_L[i] + (x * G_factors_R[i])* G_R[i];
                    G_L[i] = G_L[i].binary_scalar_mul(
                        &G_R[i],
                        &(&x_inv * &G_factors_L[i]),
                        &(&x * &G_factors_R[i]),
                    );
                    // H_L[i] = (x * H_factors_L[i])*H_L[i] + (x_inv * H_factors_R[i])*H_R[i];
                    H_L[i] = H_L[i].binary_scalar_mul(
                        &H_R[i],
                        &(&x * &H_factors_L[i]),
                        &(&x_inv * &H_factors_R[i]),
                    );
                } else {
                    // G_L[i] = (x_inv * G_L[i]) + (x * G_R[i]);
                    G_L[i] = G_L[i].binary_scalar_mul(&G_R[i], &x_inv, &x);
                    // H_L[i] = (x * H_L[i]) + (x_inv * H_R[i]);
                    H_L[i] = H_L[i].binary_scalar_mul(&H_R[i], &x, &x_inv);
                }
            }

            factors_accommodated = true;
            a = a_L;
            b = b_L;
            G = G_L;
            H = H_L;
        }

        InnerProductArgumentProof {
            L: L_vec,
            R: R_vec,
            a: a[0].clone(),
            b: b[0].clone(),
        }
    }

    /// Verification of inner product proof. For explanation of G_factors and H_factors,
    /// look at docs for creating proof
    pub fn verify_ipp(
        n: usize,
        transcript: &mut Transcript,
        G_factors: &FieldElementVector,
        H_factors: &FieldElementVector,
        P: &G1,
        u: &G1,
        G_vec: &G1Vector,
        H_vec: &G1Vector,
        a: &FieldElement,
        b: &FieldElement,
        L_vec: &G1Vector,
        R_vec: &G1Vector,
    ) -> Result<(), BulletproofError> {
        // The prover does not have access to all the challenges in the beginning but the verifier does.
        // The verifier uses all the challenges to compute scalars such that it can efficiently compute
        // the final g, h, L^{x^2}, L^{x^-2}
        let (x_sq, x_inv_sq, s) = Self::verification_scalars(L_vec, R_vec, n, transcript).unwrap();

        let g_times_a_times_s = G_factors
            .iter()
            .zip(s.iter())
            .map(|(g_i, s_i)| (a * s_i) * g_i)
            .take(G_vec.len());

        // 1/s[i] is s[!i], and !i runs from n-1 to 0 as i runs from 0 to n-1
        let inv_s = s.iter().rev();

        let h_times_b_div_s = H_factors
            .iter()
            .zip(inv_s)
            .map(|(h_i, s_i_inv)| (b * s_i_inv) * h_i);

        let neg_x_sq = x_sq.iter().map(|x| -x);
        let neg_x_inv_sq = x_inv_sq.iter().map(|x| -x);

        // expected_P = Q^{a*b} * G_vec^{a*s*G_factors} * H_vec^{b*inv_s*H_factors} * L_vec^neg_u_sq * R_vec^neg_u_inv_sq
        let exponents: Vec<FieldElement> = iter::once(a * b)
            .chain(g_times_a_times_s)
            .chain(h_times_b_div_s)
            .chain(neg_x_sq)
            .chain(neg_x_inv_sq)
            .collect();
        let mut bases = G1Vector::with_capacity(exponents.len());
        bases.push(u.clone());
        bases.append(&mut G_vec.clone());
        bases.append(&mut H_vec.clone());
        bases.append(&mut L_vec.clone());
        bases.append(&mut R_vec.clone());

        let expected_P = G1Vector::from(bases)
            .multi_scalar_mul_var_time(exponents.as_slice())
            .unwrap();

        if expected_P == *P {
            Ok(())
        } else {
            Err(BulletproofErrorKind::IPPVerificationError.into())
        }
    }

    /// Return `x^2`s, `x^-2`s and s. From section 3.1 of the paper
    pub fn verification_scalars(
        L_vec: &G1Vector,
        R_vec: &G1Vector,
        n: usize,
        transcript: &mut Transcript,
    ) -> Result<(Vec<FieldElement>, Vec<FieldElement>, Vec<FieldElement>), BulletproofError> {
        // lg_n is the number of rounds of recursion
        let lg_n = L_vec.len();
        if lg_n >= 32 {
            // 2 billion (2^31) multiplications should be enough for anyone
            // and this check prevents overflow in 1<<lg_n below.
            return Err(BulletproofErrorKind::IPPVerificationError.into());
        }
        if n != (1 << lg_n) {
            // n is not a power of 2
            return Err(BulletproofErrorKind::IPPVerificationError.into());
        }

        transcript.innerproduct_domain_sep(n as u64);

        // 1. Recompute x_k,...,x_1 based on the proof transcript. x_k is the challenge for the
        // first round of recursion whereas x_1 is the challenge from the last round.

        let mut challenges = Vec::with_capacity(lg_n);
        for (L, R) in L_vec.iter().zip(R_vec.iter()) {
            transcript.commit_point(b"L", L);
            transcript.commit_point(b"R", R);
            let x = transcript.challenge_scalar(b"x");
            challenges.push(x);
        }

        // 2. Compute x_k^2...x_1^2, 1/(x_k...x_1), 1/x_k^2, ..., 1/x_1^2

        // challenges_sq = [x_k^2, x_{k-1}^2..., x_1^2]
        let mut challenges_sq = Vec::with_capacity(lg_n);
        // challenges_inv_sq = [1/x_k^2, 1/x_{k-1}^2..., 1/x_1^2]
        let mut challenges_inv_sq = Vec::with_capacity(lg_n);

        // challenges_inv = [1/x_k, 1/x_{k-1}..., 1/x_1]
        // product_chal_inv = 1/(x_k*x_{k-1}*...x_1)
        let product_chal_inv = if lg_n > 0 {
            let (challenges_inv, product_chal_inv) = FieldElement::batch_invert(&challenges);
            for i in 0..challenges.len() {
                challenges_sq.push(challenges[i].square());
                challenges_inv_sq.push(challenges_inv[i].square());
            }
            product_chal_inv
        } else {
            FieldElement::one()
        };

        // 3. Compute s values inductively.

        let mut s = Vec::with_capacity(n);
        s.push(product_chal_inv);
        for i in 1..n {
            // From "Computing scalars" in section 6.2 of the paper
            let lg_i = (i as f32).log2() as usize;
            let k = 1 << lg_i;
            // The challenges are stored in "creation order" as [x_k,...,x_1],
            // so x_{lg(i)+1} is indexed by (lg_n-1) - lg_i. Choosing challenges_sq since there is
            // inverse of the challenge in the multiplicand element of s.
            let j = (lg_n - 1) - lg_i;
            let x_lg_i_sq = &challenges_sq[j];
            s.push(&s[i - k] * x_lg_i_sq);
        }

        Ok((challenges_sq, challenges_inv_sq, s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::get_generators;
    use merlin::Transcript;
    use std::time::Instant;

    #[test]
    fn test_ipp() {
        use crate::amcl_wrapper::group_elem::GroupElement;

        let n = 8;
        let G: G1Vector = get_generators("g", n).into();
        let H: G1Vector = get_generators("h", n).into();
        let u = G1::from_msg_hash("u".as_bytes());

        let mut a = FieldElementVector::random(n);
        let b = FieldElementVector::random(n);

        let G_factors: FieldElementVector = vec![FieldElement::one(); n].into();

        // y_inv is (the inverse of) a random challenge
        let y_inv = FieldElement::random();
        let H_factors = FieldElementVector::new_vandermonde_vector(&y_inv, n);

        let mut new_trans = Transcript::new(b"innerproduct");
        let start = Instant::now();
        let ipp_proof = IPP::create_ipp(&mut new_trans, &u, &G_factors, &H_factors, &G, &H, &a, &b);
        println!(
            "Time for create inner product proof for vectors with {} items is {:?}",
            n,
            start.elapsed()
        );

        let b_prime: Vec<FieldElement> = b
            .iter()
            .zip(H_factors.iter())
            .map(|(bi, yi)| bi * yi)
            .collect();
        let c = a.inner_product(&b).unwrap();

        let mut _1 = FieldElementVector::new(0);
        _1.append(&mut a);
        _1.append(&mut b_prime.into());
        _1.push(c);

        let mut _2 = G1Vector::new(0);
        _2.append(&mut G.clone());
        _2.append(&mut H.clone());
        _2.push(u.clone());
        let P = G1Vector::from(_2)
            .multi_scalar_mul_var_time(_1.as_slice())
            .unwrap();

        let mut new_trans1 = Transcript::new(b"innerproduct");
        IPP::verify_ipp(
            n,
            &mut new_trans1,
            &G_factors,
            &H_factors,
            &P,
            &u,
            &G,
            &H,
            &ipp_proof.a,
            &ipp_proof.b,
            &ipp_proof.L,
            &ipp_proof.R,
        )
        .unwrap();
    }
}
