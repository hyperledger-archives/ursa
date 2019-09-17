/*
    SPDX-License-Identifier: Apache-2.0 OR MIT
*/

use crate::errors::R1CSError;
use crate::transcript::TranscriptProtocol;
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use core::iter;
use merlin::Transcript;

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
    /// Create an inner-product proof.
    ///
    /// The proof is created with respect to the bases G', H',
    /// where G'_i = G_i.G_factors_i and H'_i = H_i.H_factors_i.
    ///
    /// The `transcript` is passed in as a parameter so that the
    /// challenges depend on the *entire* transcript (including parent
    /// protocols).
    ///
    /// The lengths of the vectors must all be the same, and must all be
    /// power of 2.
    pub fn create_ipp(
        transcript: &mut Transcript,
        Q: &G1,
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

        if n != 1 {
            n = n / 2;
            let (mut a_L, a_R) = a.split_at(n);
            let (mut b_L, b_R) = b.split_at(n);
            let (mut G_L, G_R) = G.split_at(n);
            let (mut H_L, H_R) = H.split_at(n);
            let (G_factors_L, G_factors_R) = G_factors.split_at(n);
            let (H_factors_L, H_factors_R) = H_factors.split_at(n);

            let c_L = a_L.inner_product(&b_R).unwrap();
            let c_R = a_R.inner_product(&b_L).unwrap();

            let mut L_0 = vec![];
            L_0.extend(a_L.hadamard_product(&G_factors_R).unwrap());
            L_0.extend(b_R.hadamard_product(&H_factors_L).unwrap());
            L_0.push(c_L);

            let mut L_1 = vec![];
            L_1.extend(G_R.iter());
            L_1.extend(H_L.iter());
            L_1.push(&Q);

            let L_0: Vec<&FieldElement> = L_0.iter().map(|f| f).collect();
            let L = G1Vector::inner_product_var_time_with_ref_vecs(L_1, L_0).unwrap();

            let mut R_0: Vec<FieldElement> = vec![];
            R_0.extend(a_R.hadamard_product(&G_factors_L).unwrap());
            R_0.extend(b_L.hadamard_product(&H_factors_R).unwrap());
            R_0.push(c_R);

            let mut R_1 = vec![];
            R_1.extend(G_L.iter());
            R_1.extend(H_R.iter());
            R_1.push(&Q);

            let R_0: Vec<&FieldElement> = R_0.iter().map(|f| f).collect();
            let R = G1Vector::inner_product_var_time_with_ref_vecs(R_1, R_0).unwrap();

            transcript.commit_point(b"L", &L);
            transcript.commit_point(b"R", &R);

            L_vec.push(L);
            R_vec.push(R);

            let u = transcript.challenge_scalar(b"u");
            let u_inv = u.inverse();

            for i in 0..n {
                a_L[i] = &a_L[i] * &u + &u_inv * &a_R[i];
                b_L[i] = &b_L[i] * &u_inv + &u * &b_R[i];
                // G_L[i] = (u_inv * G_factors_L[i])*G_L[i] + (u * G_factors_R[i])* G_R[i];
                G_L[i] = G_L[i].binary_scalar_mul(
                    &G_R[i],
                    &(&u_inv * &G_factors_L[i]),
                    &(&u * &G_factors_R[i]),
                );
                // H_L[i] = (u * H_factors_L[i])*H_L[i] + (u_inv * H_factors_R[i])*H_R[i];
                H_L[i] = H_L[i].binary_scalar_mul(
                    &H_R[i],
                    &(&u * &H_factors_L[i]),
                    &(&u_inv * &H_factors_R[i]),
                );
            }

            a = a_L;
            b = b_L;
            G = G_L;
            H = H_L;
        }

        while n != 1 {
            n = n / 2;
            let (mut a_L, a_R) = a.split_at(n);
            let (mut b_L, b_R) = b.split_at(n);
            let (mut G_L, G_R) = G.split_at(n);
            let (mut H_L, H_R) = H.split_at(n);

            let c_L = a_L.inner_product(&b_R).unwrap();
            let c_R = a_R.inner_product(&b_L).unwrap();

            let mut L_1 = vec![];
            L_1.extend(G_R.iter());
            L_1.extend(H_L.iter());
            L_1.push(&Q);
            let mut L_0 = vec![];
            L_0.extend(a_L.iter());
            L_0.extend(b_R.iter());
            L_0.push(&c_L);

            // Inner product of L_1, L_0
            let L = G1Vector::inner_product_var_time_with_ref_vecs(L_1, L_0).unwrap();

            let mut R_1 = vec![];
            R_1.extend(G_L.iter());
            R_1.extend(H_R.iter());
            R_1.push(&Q);
            let mut R_0 = vec![];
            R_0.extend(a_R.iter());
            R_0.extend(b_L.iter());
            R_0.push(&c_R);

            // Inner product of R_1, R_0
            let R = G1Vector::inner_product_var_time_with_ref_vecs(R_1, R_0).unwrap();

            transcript.commit_point(b"L", &L);
            transcript.commit_point(b"R", &R);

            L_vec.push(L);
            R_vec.push(R);

            let u = transcript.challenge_scalar(b"u");
            let u_inv = u.inverse();

            for i in 0..n {
                a_L[i] = &a_L[i] * &u + &u_inv * &a_R[i];
                b_L[i] = &b_L[i] * &u_inv + &u * &b_R[i];
                // G_L[i] = (u_inv * G_L[i]) + (u * G_R[i]);
                G_L[i] = G_L[i].binary_scalar_mul(&G_R[i], &u_inv, &u);
                // H_L[i] = (u * H_L[i]) + (u_inv * H_R[i]);
                H_L[i] = H_L[i].binary_scalar_mul(&H_R[i], &u, &u_inv);
            }

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

    pub fn verify_ipp(
        n: usize,
        transcript: &mut Transcript,
        G_factors: &FieldElementVector,
        H_factors: &FieldElementVector,
        P: &G1,
        Q: &G1,
        G: &G1Vector,
        H: &G1Vector,
        a: &FieldElement,
        b: &FieldElement,
        L_vec: &G1Vector,
        R_vec: &G1Vector,
    ) -> Result<(), R1CSError> {
        let (u_sq, u_inv_sq, s) = Self::verification_scalars(L_vec, R_vec, n, transcript).unwrap();

        let g_times_a_times_s = G_factors
            .iter()
            .zip(s.iter())
            .map(|(g_i, s_i)| (a * s_i) * g_i)
            .take(G.len());

        // 1/s[i] is s[!i], and !i runs from n-1 to 0 as i runs from 0 to n-1
        let inv_s = s.iter().rev();

        let h_times_b_div_s = H_factors
            .iter()
            .zip(inv_s)
            .map(|(h_i, s_i_inv)| (b * s_i_inv) * h_i);

        let neg_u_sq = u_sq.iter().map(|u| u.negation());
        let neg_u_inv_sq = u_inv_sq.iter().map(|u| u.negation());

        let _1: Vec<FieldElement> = iter::once(a * b)
            .chain(g_times_a_times_s)
            .chain(h_times_b_div_s)
            .chain(neg_u_sq)
            .chain(neg_u_inv_sq)
            .collect();

        let mut _2 = G1Vector::new(0);
        _2.push(Q.clone());
        _2.append(&mut G.clone());
        _2.append(&mut H.clone());
        _2.append(&mut L_vec.clone());
        _2.append(&mut R_vec.clone());

        let expected_P = G1Vector::from(_2)
            .multi_scalar_mul_var_time(&_1.into())
            .unwrap();

        if expected_P == *P {
            Ok(())
        } else {
            Err(R1CSError::VerificationError)
        }
    }

    pub fn verification_scalars(
        L_vec: &G1Vector,
        R_vec: &G1Vector,
        n: usize,
        transcript: &mut Transcript,
    ) -> Result<(Vec<FieldElement>, Vec<FieldElement>, Vec<FieldElement>), R1CSError> {
        let lg_n = L_vec.len();
        if lg_n >= 32 {
            // 4 billion multiplications should be enough for anyone
            // and this check prevents overflow in 1<<lg_n below.
            return Err(R1CSError::VerificationError);
        }
        if n != (1 << lg_n) {
            return Err(R1CSError::VerificationError);
        }

        transcript.innerproduct_domain_sep(n as u64);

        // 1. Recompute x_k,...,x_1 based on the proof transcript

        let mut challenges = Vec::with_capacity(lg_n);
        for (L, R) in L_vec.iter().zip(R_vec.iter()) {
            transcript.commit_point(b"L", L);
            transcript.commit_point(b"R", R);
            let u = transcript.challenge_scalar(b"u");
            challenges.push(u);
        }

        // 2. Compute u_k^2...u_1^2, 1/(u_k...u_1), 1/u_k^2, ..., 1/u_1^2

        let mut challenges_sq = Vec::with_capacity(lg_n);
        let mut challenges_inv_sq = Vec::with_capacity(lg_n);

        let (challenges_inv, product_chal_inv) = FieldElement::batch_invert(&challenges);
        for i in 0..challenges.len() {
            challenges_sq.push(challenges[i].square());
            challenges_inv_sq.push(challenges_inv[i].square());
        }

        // 3. Compute s values inductively.

        let mut s = Vec::with_capacity(n);
        s.push(product_chal_inv);
        for i in 1..n {
            let lg_i = (32 - 1 - (i as u32).leading_zeros()) as usize;
            let k = 1 << lg_i;
            // The challenges are stored in "creation order" as [u_k,...,u_1],
            // so u_{lg(i)+1} = is indexed by (lg_n-1) - lg_i
            let u_lg_i_sq = &challenges_sq[(lg_n - 1) - lg_i];
            s.push(&s[i - k] * u_lg_i_sq);
        }

        Ok((challenges_sq, challenges_inv_sq, s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::get_generators;
    use merlin::Transcript;

    #[test]
    fn test_ipp() {
        let n = 4;
        let G: G1Vector = get_generators("g", n).into();
        let H: G1Vector = get_generators("h", n).into();
        let Q = G1::from_msg_hash("Q".as_bytes());

        let mut a: FieldElementVector = vec![1, 2, 3, 4]
            .iter()
            .map(|i| FieldElement::from(*i as u8))
            .collect::<Vec<FieldElement>>()
            .into();
        let b: FieldElementVector = vec![5, 6, 7, 8]
            .iter()
            .map(|i| FieldElement::from(*i as u8))
            .collect::<Vec<FieldElement>>()
            .into();

        let G_factors: FieldElementVector = vec![FieldElement::one(); n].into();

        // y_inv is (the inverse of) a random challenge
        let y_inv = FieldElement::random();
        let H_factors = FieldElementVector::new_vandermonde_vector(&y_inv, n);

        let mut new_trans = Transcript::new(b"innerproduct");
        let ipp_proof = IPP::create_ipp(&mut new_trans, &Q, &G_factors, &H_factors, &G, &H, &a, &b);

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
        _2.push(Q.clone());
        let P = G1Vector::from(_2).multi_scalar_mul_var_time(&_1).unwrap();

        let mut new_trans1 = Transcript::new(b"innerproduct");
        IPP::verify_ipp(
            n,
            &mut new_trans1,
            &G_factors,
            &H_factors,
            &P,
            &Q,
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
