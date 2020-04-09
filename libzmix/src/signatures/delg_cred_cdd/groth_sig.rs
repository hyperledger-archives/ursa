// Groth signatures, Groth1 and Groth2. Section 2.4.1 of the paper

use super::errors::{DelgCredCDDErrorKind, DelgCredCDDResult};
use crate::commitments::pok_vc::{
    ProofG1, ProofG2, ProverCommittedG1, ProverCommittedG2, ProverCommittingG1, ProverCommittingG2,
};
use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::{G1LookupTable, G1Vector, G1};
use amcl_wrapper::group_elem_g2::{G2Vector, G2};

pub type GrothSigkey = FieldElement;

macro_rules! impl_GrothS {
    ( $GrothSetupParams:ident, $GrothVerkey:ident, $GrothSig:ident, $GrothS:ident, $vk_group:ident, $msg_group:ident,
        $GVector:ident, $ProverCommitting:ident, $ProverCommitted:ident, $Proof:ident, $g:ident ) => {
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct $GrothSetupParams {
            pub g1: G1,
            pub g2: G2,
            pub y: $GVector,
        }

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct $GrothVerkey(pub $vk_group);

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct $GrothSig {
            pub R: $vk_group,
            pub S: $msg_group,
            pub T: $GVector,
        }

        pub struct $GrothS {}

        impl $GrothVerkey {
            /// Schnorr protocol for proof of knowledge of secret key since public key is of the
            /// form g^sk
            pub fn initiate_proof_of_knowledge_of_sigkey(
                setup_params: &$GrothSetupParams,
            ) -> $ProverCommitted {
                let mut commiting = $ProverCommitting::new();
                commiting.commit(&setup_params.$g, None);
                commiting.finish()
            }

            pub fn finish_proof_of_knowledge_of_sigkey(
                committed: $ProverCommitted,
                sig_key: GrothSigkey,
                challenge: &FieldElement,
            ) -> $Proof {
                committed.gen_proof(&challenge, &[sig_key]).unwrap()
            }

            pub fn verify_proof_of_knowledge_of_sigkey(
                proof: &$Proof,
                verkey: &$GrothVerkey,
                setup_params: &$GrothSetupParams,
                challenge: &FieldElement,
            ) -> DelgCredCDDResult<bool> {
                let r = proof.verify(&[setup_params.$g.clone()], &verkey.0, &challenge)?;
                Ok(r)
            }
        }
    };
}

macro_rules! impl_GrothS_setup {
    ( $GrothSetupParams:ident, $msg_group:ident, $GVector:ident ) => {
        /// Corresponds to Groth sig's "Setup" from the paper
        pub fn setup(count_messages: usize, label: &[u8]) -> $GrothSetupParams {
            // NUMS for g1 and g2
            let g1 = G1::from_msg_hash(&[label, " : g1".as_bytes()].concat());
            let g2 = G2::from_msg_hash(&[label, " : g2".as_bytes()].concat());
            let mut y = $GVector::with_capacity(count_messages);
            for i in 0..count_messages {
                // // NUMS for y. construct a group element from hashing label||y||i for each i
                let yi = $msg_group::from_msg_hash(
                    &[label, " : y".as_bytes(), i.to_string().as_bytes()].concat(),
                );
                y.push(yi);
            }
            $GrothSetupParams { g1, g2, y }
        }
    };
}

macro_rules! impl_GrothSig_new {
    ( $messages:ident, $sk:ident, $y:expr, $g_r:expr, $g_s:expr, $msg_group_vec:ident ) => {{
        if $messages.len() > $y.len() {
            return Err(DelgCredCDDErrorKind::UnsupportedNoOfMessages {
                expected: $y.len(),
                given: $messages.len(),
            }
            .into());
        }
        let r = FieldElement::random();
        let r_inv = r.inverse();
        let R = &$g_r * &r;
        let S = (&$y[0] + (&$g_s * $sk)) * &r_inv;
        let mut T = $msg_group_vec::with_capacity($messages.len());
        for i in 0..$messages.len() {
            T.push(&$messages[i] + (&$y[i] * $sk));
        }
        T.scale(&r_inv);
        Ok(Self { R, S, T })
    }};
}

macro_rules! impl_GrothSig_randomize {
    (  ) => {
        /// This multiplication randomizes the signature making it indistinguishable from previous
        /// usages of this signature.
        /// Corresponds to Groth sig's "Rand" from the paper
        pub fn randomize(&self, r_prime: &FieldElement) -> Self {
            let r_prime_inv = r_prime.inverse();
            let R = &self.R * r_prime;
            let S = &self.S * &r_prime_inv;
            Self {
                R,
                S,
                T: self.T.scaled_by(&r_prime_inv),
            }
        }
    };
}

impl_GrothS!(
    Groth1SetupParams,
    Groth1Verkey,
    Groth1Sig,
    GrothS1,
    G2,
    G1,
    G1Vector,
    ProverCommittingG2,
    ProverCommittedG2,
    ProofG2,
    g2
);

impl_GrothS!(
    Groth2SetupParams,
    Groth2Verkey,
    Groth2Sig,
    GrothS2,
    G1,
    G2,
    G2Vector,
    ProverCommittingG1,
    ProverCommittedG1,
    ProofG1,
    g1
);

/// Returns tuple of groups elements where the elements are result of scalar multiplication involving the same field element. Uses w-NAF
#[macro_export]
macro_rules! var_time_mul_scl_mul_with_same_field_element {
    ( $group:ident, $group_elem_table: ident, $field_elem:expr, $( $group_elem:expr ),* ) => {{
        let wnaf = $field_elem.to_wnaf(5);
        (
            $(
            $group::wnaf_mul(&$group_elem_table::from($group_elem), &wnaf),
            )*
        )
    }}
}

impl GrothS1 {
    impl_GrothS_setup!(Groth1SetupParams, G1, G1Vector);

    /// Corresponds to Groth sig's "Gen" from the paper
    pub fn keygen(setup_params: &Groth1SetupParams) -> (GrothSigkey, Groth1Verkey) {
        let sk = FieldElement::random();
        let vk = &setup_params.g2 * &sk;
        (sk, Groth1Verkey(vk))
    }
}

impl Groth1Sig {
    /// Corresponds to Groth sig's "Sign" from the paper
    pub fn new(
        messages: &[G1],
        sk: &GrothSigkey,
        setup_params: &Groth1SetupParams,
    ) -> DelgCredCDDResult<Self> {
        impl_GrothSig_new!(
            messages,
            sk,
            setup_params.y,
            setup_params.g2,
            setup_params.g1,
            G1Vector
        )
    }

    impl_GrothSig_randomize!();

    /// Corresponds to Groth sig's "Verify" from the paper
    pub fn verify(
        &self,
        messages: &[G1],
        verkey: &Groth1Verkey,
        setup_params: &Groth1SetupParams,
    ) -> DelgCredCDDResult<bool> {
        if messages.len() > setup_params.y.len() {
            return Err(DelgCredCDDErrorKind::UnsupportedNoOfMessages {
                expected: setup_params.y.len(),
                given: messages.len(),
            }
            .into());
        }

        // e(S, R) == e(y_0, g2) * (g1, V) => e(y_0, g2) * (g1, V) * e(S, R)^-1 == 1 => e(y_0, g2) * (g1, V) * e(S^-1, R) == 1
        let negS = self.S.negation();
        let e0 = GT::ate_multi_pairing(vec![
            (&setup_params.y[0], &setup_params.g2),
            (&setup_params.g1, &verkey.0),
            (&negS, &self.R),
        ]);
        if !e0.is_one() {
            return Ok(false);
        }

        let negR = self.R.negation();
        for i in 0..messages.len() {
            // e(T_i, R) == e(m_i, g2) * e(y_i, V) => 1 == e(m_i, g2) * e(y_i, V) * e(T_i, R)^-1 = 1 == e(m_i, g2) * e(y_i, V) * e(T_i, R^-1)
            let e = GT::ate_multi_pairing(vec![
                (&messages[i], &setup_params.g2),
                (&setup_params.y[i], &verkey.0),
                (&self.T[i], &negR),
            ]);
            if !e.is_one() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Verify n pairing checks with a single one using batch verification of pairings. This is a slight modification
    /// of the small-exponents technique described in "Practical Short Signature Batch Verification"(https://eprint.iacr.org/2008/015).
    /// Rather than selecting n random values, degrees of a single random value like r,r^2,r^3,..r^{n-1{ are used.
    /// if a verifier had to check that all 3 values a, b and c are 0, he could pick a random value r in {Z_p}* and check that a + b*r + c*r^2 equals 0
    /// in a pairing situation if verifier had to check if e(a,b) = 1, e(c, d) = 1 and e(f, g) = 1, pick a random value r in {Z_p}* and check e(a,b) * e(c,d)^r * e(f,g)^{r^2} equals 1
    /// e(a,b) * e(c,d)^r * e(f,g)^{r^2} = e(a,b) * e(c^r, d) * e(f^{r^2}, g). Exponent moved to 1st element of pairing since computation in group G1 is cheaper
    /// Now use a single multi-pairing rather than 3 pairings to compute e(a,b) * e(c^r, d) * e(f^{r^2}, g)
    /// Using the above idea for signature verification =>
    /// e(-S, R)*e(y1, g2)*e(g1, V) * {e(m1, g2)*e(y1, V)*e(T1, -R)}^r * {e(m2, g2)*e(y2, V)*e(T2, -R)}^{r^2} * ... == 1
    /// e(-S, R)*e(y1, g2)*e(g1, V) * e(m1, g2)^r*e(y1, V)^r*e(T1, -R)^r * e(m2, g2)^{r^2}*e(y2, V)^{r^2}*e(T2, -R)^{r^2} * ... == 1
    /// e(-S, R)*e(y1, g2)*e(g1, V) * e(m1^r, g2)*e(y1^r, V)*e(T1^r, -R) * e(m2^{r^2}, g1)*e(y2^{r^2}, V)*e(T2^{r^2}, -R) * ... == 1
    pub fn verify_batch(
        &self,
        messages: &[G1],
        verkey: &Groth1Verkey,
        setup_params: &Groth1SetupParams,
    ) -> DelgCredCDDResult<bool> {
        if messages.len() > setup_params.y.len() {
            return Err(DelgCredCDDErrorKind::UnsupportedNoOfMessages {
                expected: setup_params.y.len(),
                given: messages.len(),
            }
            .into());
        }

        let mut pairing_elems: Vec<(G1, G2)> = vec![];
        let r = FieldElement::random();
        let r_vec = FieldElementVector::new_vandermonde_vector(&r, messages.len() + 1);

        Self::prepare_for_pairing_checks(
            &mut pairing_elems,
            &r_vec,
            0,
            &self,
            messages,
            &verkey,
            setup_params,
        );
        let e = GT::ate_multi_pairing(
            pairing_elems
                .iter()
                .map(|p| (&p.0, &p.1))
                .collect::<Vec<_>>(),
        );
        Ok(e.is_one())
    }

    /// Prepare a vector which will be the argument of the multi-pairing
    pub(crate) fn prepare_for_pairing_checks(
        pairing_elems: &mut Vec<(G1, G2)>,
        r_vec: &FieldElementVector,
        r_vec_offset: usize,
        sig: &Groth1Sig,
        messages: &[G1],
        verkey: &Groth1Verkey,
        setup_params: &Groth1SetupParams,
    ) {
        // TODO: There are lot of clonings happening below. Find a better way.

        let negR = sig.R.negation();
        let negS = sig.S.negation();

        let (p_0, p_1, p_2) = if r_vec_offset == 0 {
            (setup_params.y[0].clone(), setup_params.g1.clone(), negS)
        } else {
            var_time_mul_scl_mul_with_same_field_element!(
                G1,
                G1LookupTable,
                r_vec[r_vec_offset],
                &setup_params.y[0],
                &setup_params.g1,
                &negS
            )
        };

        pairing_elems.push((p_0, setup_params.g2.clone()));
        pairing_elems.push((p_1, verkey.0.clone()));
        pairing_elems.push((p_2, sig.R.clone()));
        let mut temp: Vec<(G1, G1, G1)> = vec![];
        for i in 0..messages.len() {
            // The next code block will perform several scalar multiplications with the same field element, i.e. m_i * r, y_i * r, T_i * r
            // m_i * r, y_i * r, T_i * r
            temp.push(var_time_mul_scl_mul_with_same_field_element!(
                G1,
                G1LookupTable,
                r_vec[r_vec_offset + i + 1],
                &messages[i],
                &setup_params.y[i],
                &sig.T[i]
            ));
        }

        for _ in 0..messages.len() {
            let t = temp.remove(0);
            pairing_elems.push((t.0, setup_params.g2.clone()));
            pairing_elems.push((t.1, verkey.0.clone()));
            pairing_elems.push((t.2, negR.clone()))
        }
    }
}

impl GrothS2 {
    impl_GrothS_setup!(Groth2SetupParams, G2, G2Vector);

    /// Corresponds to Groth sig's "Gen" from the paper
    pub fn keygen(setup_params: &Groth2SetupParams) -> (GrothSigkey, Groth2Verkey) {
        let sk = FieldElement::random();
        let vk = &setup_params.g1 * &sk;
        (sk, Groth2Verkey(vk))
    }
}

impl Groth2Sig {
    /// Corresponds to Groth sig's "Sign" from the paper
    pub fn new(
        messages: &[G2],
        sk: &GrothSigkey,
        setup_params: &Groth2SetupParams,
    ) -> DelgCredCDDResult<Self> {
        impl_GrothSig_new!(
            messages,
            sk,
            setup_params.y,
            setup_params.g1,
            setup_params.g2,
            G2Vector
        )
    }

    impl_GrothSig_randomize!();

    /// Corresponds to Groth sig's "Verify" from the paper
    pub fn verify(
        &self,
        messages: &[G2],
        verkey: &Groth2Verkey,
        setup_params: &Groth2SetupParams,
    ) -> DelgCredCDDResult<bool> {
        if messages.len() > setup_params.y.len() {
            return Err(DelgCredCDDErrorKind::UnsupportedNoOfMessages {
                expected: setup_params.y.len(),
                given: messages.len(),
            }
            .into());
        }

        // e(R, S) == e(g1, y_0) * (V, g2) => 1 == e(g1, y_0) * (V, g2) * e(R, S)^-1 => 1 == e(g1, y_0) * (V, g2) * e(R^-1, S)
        let negR = self.R.negation();
        let e0 = GT::ate_multi_pairing(vec![
            (&setup_params.g1, &setup_params.y[0]),
            (&verkey.0, &setup_params.g2),
            (&negR, &self.S),
        ]);
        if !e0.is_one() {
            return Ok(false);
        }

        for i in 0..messages.len() {
            // e(R, T_i) == e(g1, m_i) * e(V, y_i) => 1 == e(g1, m_i) * e(V, y_i) * e(R, T_i)^-1 => 1 == e(g1, m_i) * e(V, y_i) * e(R^-1, T_i)
            let e = GT::ate_multi_pairing(vec![
                (&setup_params.g1, &messages[i]),
                (&verkey.0, &setup_params.y[i]),
                (&negR, &self.T[i]),
            ]);
            if !e.is_one() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Verify n pairing checks with a single one using batch verification of pairings. This is a slight modification
    /// of the small-exponents technique described in "Practical Short Signature Batch Verification"(https://eprint.iacr.org/2008/015).
    /// Rather than selecting n random values, degrees of a single random value like r,r^2,r^3,..r^{n-1{ are used.
    /// if a verifier had to check that all 3 values a, b and c are 0, he could pick a random value r in {Z_p}* and check that a + b*r + c*r^2 equals 0
    /// in a pairing situation if verifier had to check if e(a,b) = 1, e(c, d) = 1 and e(f, g) = 1, pick a random value r in {Z_p}* and check e(a,b) * e(c,d)^r * e(f,g)^{r^2} equals 1
    /// e(a,b) * e(c,d)^r * e(f,g)^{r^2} = e(a,b) * e(c^r, d) * e(f^{r^2}, g). Exponent moved to 1st element of pairing since computation in group G1 is cheaper
    /// Now use a single multi-pairing rather than 3 pairings to compute e(a,b) * e(c^r, d) * e(f^{r^2}, g)
    /// Using the above idea for signature verification =>
    /// e(-R, S)*e(g1, y1)*e(V, g2) * {e(g1, m1)*e(V, y1)*e(-R, T1)}^r * {e(g1, m2)*e(V, y2)*e(-R, T2)}^{r^2} * ... == 1
    /// e(-R, S)*e(g1, y1)*e(V, g2) * e(g1, m1)^r*e(V, y1)^r*e(-R, T1)^r * e(g1, m2)^{r^2}*e(V, y2)^{r^2}*e(-R, T2)^{r^2} * ... == 1
    /// e(-R, S)*e(g1, y1)*e(V, g2) * e(g1^r, m1)*e(V^r, y1)*e(-R^r, T1) * e(g1^{r^2}, m2)*e(V^{r^2}, y2)*e(-R^{r^2}, T2) * ... == 1
    pub fn verify_batch(
        &self,
        messages: &[G2],
        verkey: &Groth2Verkey,
        setup_params: &Groth2SetupParams,
    ) -> DelgCredCDDResult<bool> {
        if messages.len() > setup_params.y.len() {
            return Err(DelgCredCDDErrorKind::UnsupportedNoOfMessages {
                expected: setup_params.y.len(),
                given: messages.len(),
            }
            .into());
        }

        let mut pairing_elems: Vec<(G1, G2)> = vec![];
        let r = FieldElement::random();
        let r_vec = FieldElementVector::new_vandermonde_vector(&r, messages.len() + 1);

        Self::prepare_for_pairing_checks(
            &mut pairing_elems,
            &r_vec,
            0,
            &self,
            messages,
            &verkey,
            setup_params,
        );
        let e = GT::ate_multi_pairing(
            pairing_elems
                .iter()
                .map(|p| (&p.0, &p.1))
                .collect::<Vec<_>>(),
        );
        Ok(e.is_one())
    }

    /// Prepare a vector which will be the argument of the multi-pairing
    pub(crate) fn prepare_for_pairing_checks(
        pairing_elems: &mut Vec<(G1, G2)>,
        r_vec: &FieldElementVector,
        r_vec_offset: usize,
        sig: &Groth2Sig,
        messages: &[G2],
        verkey: &Groth2Verkey,
        setup_params: &Groth2SetupParams,
    ) {
        let negR = sig.R.negation();

        let (p_0, p_1, p_2) = if r_vec_offset == 0 {
            (setup_params.g1.clone(), verkey.0.clone(), negR.clone())
        } else {
            var_time_mul_scl_mul_with_same_field_element!(
                G1,
                G1LookupTable,
                r_vec[r_vec_offset],
                &setup_params.g1,
                &verkey.0,
                &negR
            )
        };

        pairing_elems.push((p_0, setup_params.y[0].clone()));
        pairing_elems.push((p_1, setup_params.g2.clone()));
        pairing_elems.push((p_2, sig.S.clone()));

        // The next code block will perform several scalar multiplications with the same bases for the same field element (in each iteration), i.e. g1 * r, V * r, R * r
        let mut temp: Vec<(G1, G1, G1)> = vec![];
        for i in 0..messages.len() {
            // g1 * r, V * r, R * r
            temp.push(var_time_mul_scl_mul_with_same_field_element!(
                G1,
                G1LookupTable,
                r_vec[i + 1],
                &setup_params.g1,
                &verkey.0,
                &negR
            ));
        }

        for i in 0..messages.len() {
            let t = temp.remove(0);
            pairing_elems.push((t.0, messages[i].clone()));
            pairing_elems.push((t.1, setup_params.y[i].clone()));
            pairing_elems.push((t.2, sig.T[i].clone()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // For benchmarking
    use std::time::Instant;

    #[test]
    fn test_groth1_sig_verification() {
        let count_msgs = 10;
        let label = "test".as_bytes();
        let params = GrothS1::setup(count_msgs, label);
        assert_eq!(params.y.len(), count_msgs);
        let (sk, vk) = GrothS1::keygen(&params);

        let msgs = (0..count_msgs).map(|_| G1::random()).collect::<Vec<G1>>();
        let sig = Groth1Sig::new(msgs.as_slice(), &sk, &params).unwrap();

        let start = Instant::now();
        assert!(sig.verify(msgs.as_slice(), &vk, &params).unwrap());
        println!("Naive verify takes {:?}", start.elapsed());

        let start = Instant::now();
        assert!(sig.verify_batch(msgs.as_slice(), &vk, &params).unwrap());
        println!("Fast verify takes {:?}", start.elapsed());

        let r = FieldElement::random();
        let sig_randomized = sig.randomize(&r);
        assert!(sig_randomized
            .verify(msgs.as_slice(), &vk, &params)
            .unwrap());
        assert!(sig_randomized
            .verify_batch(msgs.as_slice(), &vk, &params)
            .unwrap());
    }

    #[test]
    fn test_groth2_sig_verification() {
        let count_msgs = 10;
        let label = "test".as_bytes();
        let params = GrothS2::setup(count_msgs, label);
        assert_eq!(params.y.len(), count_msgs);
        let (sk, vk) = GrothS2::keygen(&params);

        let msgs = (0..count_msgs).map(|_| G2::random()).collect::<Vec<G2>>();
        let sig = Groth2Sig::new(msgs.as_slice(), &sk, &params).unwrap();

        let start = Instant::now();
        assert!(sig.verify(msgs.as_slice(), &vk, &params).unwrap());
        println!("Naive verify takes {:?}", start.elapsed());

        let start = Instant::now();
        assert!(sig.verify_batch(msgs.as_slice(), &vk, &params).unwrap());
        println!("Fast verify takes {:?}", start.elapsed());

        let r = FieldElement::random();
        let sig_randomized = sig.randomize(&r);
        assert!(sig_randomized
            .verify(msgs.as_slice(), &vk, &params)
            .unwrap());
        assert!(sig_randomized
            .verify_batch(msgs.as_slice(), &vk, &params)
            .unwrap());
    }

    #[test]
    fn test_proof_of_knowledge_of_groth1_sigkey() {
        let count_msgs = 3;
        let label = "test".as_bytes();
        let params = GrothS1::setup(count_msgs, label);
        let (sk, vk) = GrothS1::keygen(&params);

        let committed = Groth1Verkey::initiate_proof_of_knowledge_of_sigkey(&params);
        let challenge = FieldElement::from_msg_hash(&vk.0.to_bytes());
        let proof =
            Groth1Verkey::finish_proof_of_knowledge_of_sigkey(committed, sk.clone(), &challenge);
        assert!(
            Groth1Verkey::verify_proof_of_knowledge_of_sigkey(&proof, &vk, &params, &challenge)
                .unwrap()
        )
    }

    #[test]
    fn test_proof_of_knowledge_of_groth2_sigkey() {
        let count_msgs = 3;
        let label = "test".as_bytes();
        let params = GrothS2::setup(count_msgs, label);
        let (sk, vk) = GrothS2::keygen(&params);

        let committed = Groth2Verkey::initiate_proof_of_knowledge_of_sigkey(&params);
        let challenge = FieldElement::from_msg_hash(&vk.0.to_bytes());
        let proof =
            Groth2Verkey::finish_proof_of_knowledge_of_sigkey(committed, sk.clone(), &challenge);
        assert!(
            Groth2Verkey::verify_proof_of_knowledge_of_sigkey(&proof, &vk, &params, &challenge)
                .unwrap()
        )
    }
}
