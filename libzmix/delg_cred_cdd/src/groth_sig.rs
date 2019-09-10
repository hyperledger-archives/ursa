use crate::errors::{DelgError, DelgResult};
use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::{G1LookupTable, G1Vector, G1};
use amcl_wrapper::group_elem_g2::{G2Vector, G2};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrothSigkey(pub FieldElement);

macro_rules! impl_GrothS {
    ( $GrothSetupParams:ident, $GrothVerkey:ident, $GrothSig:ident, $GrothS:ident, $vk_group:ident, $msg_group:ident, $GVector:ident ) => {
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
    };
}

macro_rules! impl_GrothS_setup {
    ( $GrothSetupParams:ident, $msg_group:ident, $GVector:ident ) => {
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
            return Err(DelgError::UnsupportedNoOfMessages {
                expected: $y.len(),
                given: $messages.len(),
            });
        }
        let r = FieldElement::random();
        let r_inv = r.inverse();
        let R = &$g_r * &r;
        let S = (&$y[0] + (&$g_s * &$sk.0)) * &r_inv;
        let mut T = $msg_group_vec::with_capacity($messages.len());
        for i in 0..$messages.len() {
            T.push(&$messages[i] + (&$y[i] * &$sk.0));
        }
        T.scale(&r_inv);
        Ok(Self { R, S, T })
    }};
}

macro_rules! impl_GrothSig_randomize {
    (  ) => {
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
    }
}

impl_GrothS!(
    Groth1SetupParams,
    Groth1Verkey,
    Groth1Sig,
    GrothS1,
    G2,
    G1,
    G1Vector
);

impl_GrothS!(
    Groth2SetupParams,
    Groth2Verkey,
    Groth2Sig,
    GrothS2,
    G1,
    G2,
    G2Vector
);

/// Returns tuple of groups elements where the elements are result of scalar multiplication involving the same field element. Uses w-NAF
#[macro_export]
macro_rules! var_time_mul_scl_mul_with_same_field_element {
    ( $group:ident, $field_elem:expr, $( $group_elem_table:expr ),* ) => {{
        let wnaf = $field_elem.to_wnaf(5);
        (
            $(
            $group::wnaf_mul(&$group_elem_table, &wnaf),
            )*
        )
    }}
}

impl GrothS1 {
    impl_GrothS_setup!(Groth1SetupParams, G1, G1Vector);

    pub fn keygen(setup_params: &Groth1SetupParams) -> (GrothSigkey, Groth1Verkey) {
        let sk = FieldElement::random();
        let vk = &setup_params.g2 * &sk;
        (GrothSigkey(sk), Groth1Verkey(vk))
    }
}

impl Groth1Sig {
    pub fn new(
        messages: &[G1],
        sk: &GrothSigkey,
        setup_params: &Groth1SetupParams,
    ) -> DelgResult<Self> {
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

    pub fn verify(
        &self,
        messages: &[G1],
        verkey: &Groth1Verkey,
        setup_params: &Groth1SetupParams,
    ) -> DelgResult<bool> {
        if messages.len() > setup_params.y.len() {
            return Err(DelgError::UnsupportedNoOfMessages {
                expected: setup_params.y.len(),
                given: messages.len(),
            });
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

    pub fn verify_fast(
        &self,
        messages: &[G1],
        verkey: &Groth1Verkey,
        setup_params: &Groth1SetupParams,
    ) -> DelgResult<bool> {
        // Verify n pairing checks with a single one.
        // if a verifier had to check that all 3 values a, b and c are 0, he could pick a random value r in {Z_p}* and check that a + b*r + c*r^2 equals 0
        // in a pairing situation if verifier had to check if e(a,b) = 1, e(c, d) = 1 and e(f, g) = 1, pick a random value r in {Z_p}* and check e(a,b) * e(c,d)^r * e(f,g)^{r^2} equals 1
        // e(a,b) * e(c,d)^r * e(f,g)^{r^2} = e(a,b) * e(c^r, d) * e(f^{r^2}, g). Exponent moved to 1st element of pairing since computation in group G1 is cheaper
        // Now use a single multi-pairing rather than 3 pairings to compute e(a,b) * e(c^r, d) * e(f^{r^2}, g)
        // Using the above idea for signature verification =>
        // e(-S, R)*e(y1, g2)*e(g1, V) * {e(m1, g2)*e(y1, V)*e(T1, -R)}^r * {e(m2, g2)*e(y2, V)*e(T2, -R)}^{r^2} * ... == 1
        // e(-S, R)*e(y1, g2)*e(g1, V) * e(m1, g2)^r*e(y1, V)^r*e(T1, -R)^r * e(m2, g2)^{r^2}*e(y2, V)^{r^2}*e(T2, -R)^{r^2} * ... == 1
        // e(-S, R)*e(y1, g2)*e(g1, V) * e(m1^r, g2)*e(y1^r, V)*e(T1^r, -R) * e(m2^{r^2}, g1)*e(y2^{r^2}, V)*e(T2^{r^2}, -R) * ... == 1

        if messages.len() > setup_params.y.len() {
            return Err(DelgError::UnsupportedNoOfMessages {
                expected: setup_params.y.len(),
                given: messages.len(),
            });
        }

        let r = FieldElement::random();
        let r_vec = FieldElementVector::new_vandermonde_vector(&r, messages.len() + 1);
        let negR = self.R.negation();
        let negS = self.S.negation();

        let mut pairing_elems: Vec<(&G1, &G2)> = vec![
            (&setup_params.y[0], &setup_params.g2),
            (&setup_params.g1, &verkey.0),
            (&negS, &self.R),
        ];

        let mut temp: Vec<(G1, G1, G1)> = vec![];
        for i in 0..messages.len() {
            // The next code block will perform several scalar multiplications with the same field element, i.e. m_i * r, y_i * r, T_i * r
            let table_m = G1LookupTable::from(&messages[i]);
            let table_y = G1LookupTable::from(&setup_params.y[i]);
            let table_T = G1LookupTable::from(&self.T[i]);
            // m_i * r, y_i * r, T_i * r
            temp.push(var_time_mul_scl_mul_with_same_field_element!(
                G1,
                r_vec[i + 1],
                table_m,
                table_y,
                table_T
            ));
        }

        for i in 0..messages.len() {
            pairing_elems.push((&temp[i].0, &setup_params.g2));
            pairing_elems.push((&temp[i].1, &verkey.0));
            pairing_elems.push((&temp[i].2, &negR))
        }

        let e = GT::ate_multi_pairing(pairing_elems);
        Ok(e.is_one())
    }
}

impl GrothS2 {
    impl_GrothS_setup!(Groth2SetupParams, G2, G2Vector);

    pub fn keygen(setup_params: &Groth2SetupParams) -> (GrothSigkey, Groth2Verkey) {
        let sk = FieldElement::random();
        let vk = &setup_params.g1 * &sk;
        (GrothSigkey(sk), Groth2Verkey(vk))
    }
}

impl Groth2Sig {
    pub fn new(
        messages: &[G2],
        sk: &GrothSigkey,
        setup_params: &Groth2SetupParams,
    ) -> DelgResult<Self> {
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

    pub fn verify(
        &self,
        messages: &[G2],
        verkey: &Groth2Verkey,
        setup_params: &Groth2SetupParams,
    ) -> DelgResult<bool> {
        if messages.len() > setup_params.y.len() {
            return Err(DelgError::UnsupportedNoOfMessages {
                expected: setup_params.y.len(),
                given: messages.len(),
            });
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

    pub fn verify_fast(
        &self,
        messages: &[G2],
        verkey: &Groth2Verkey,
        setup_params: &Groth2SetupParams,
    ) -> DelgResult<bool> {
        // Verify n pairing checks with a single one.
        // if a verifier had to check that all 3 values a, b and c are 0, he could pick a random value r in {Z_p}* and check that a + b*r + c*r^2 equals 0
        // in a pairing situation if verifier had to check if e(a,b) = 1, e(c, d) = 1 and e(f, g) = 1, pick a random value r in {Z_p}* and check e(a,b) * e(c,d)^r * e(f,g)^{r^2} equals 1
        // e(a,b) * e(c,d)^r * e(f,g)^{r^2} = e(a,b) * e(c^r, d) * e(f^{r^2}, g). Exponent moved to 1st element of pairing since computation in group G1 is cheaper
        // Now use a single multi-pairing rather than 3 pairings to compute e(a,b) * e(c^r, d) * e(f^{r^2}, g)
        // Using the above idea for signature verification =>
        // e(-R, S)*e(g1, y1)*e(V, g2) * {e(g1, m1)*e(V, y1)*e(-R, T1)}^r * {e(g1, m2)*e(V, y2)*e(-R, T2)}^{r^2} * ... == 1
        // e(-R, S)*e(g1, y1)*e(V, g2) * e(g1, m1)^r*e(V, y1)^r*e(-R, T1)^r * e(g1, m2)^{r^2}*e(V, y2)^{r^2}*e(-R, T2)^{r^2} * ... == 1
        // e(-R, S)*e(g1, y1)*e(V, g2) * e(g1^r, m1)*e(V^r, y1)*e(-R^r, T1) * e(g1^{r^2}, m2)*e(V^{r^2}, y2)*e(-R^{r^2}, T2) * ... == 1

        if messages.len() > setup_params.y.len() {
            return Err(DelgError::UnsupportedNoOfMessages {
                expected: setup_params.y.len(),
                given: messages.len(),
            });
        }

        let r = FieldElement::random();
        let r_vec = FieldElementVector::new_vandermonde_vector(&r, messages.len() + 1);
        let negR = self.R.negation();

        let mut pairing_elems: Vec<(&G1, &G2)> = vec![
            (&setup_params.g1, &setup_params.y[0]),
            (&verkey.0, &setup_params.g2),
            (&negR, &self.S),
        ];

        // The next code block will perform several scalar multiplications with the same bases for the same field element (in each iteration), i.e. g1 * r, V * r, R * r
        let mut temp: Vec<(G1, G1, G1)> = vec![];
        let table_g1 = G1LookupTable::from(&setup_params.g1);
        let table_vk = G1LookupTable::from(&verkey.0);
        let table_R = G1LookupTable::from(&negR);
        for i in 0..messages.len() {
            // g1 * r, V * r, R * r
            temp.push(var_time_mul_scl_mul_with_same_field_element!(
                G1,
                r_vec[i + 1],
                table_g1,
                table_vk,
                table_R
            ));
        }

        for i in 0..messages.len() {
            pairing_elems.push((&temp[i].0, &messages[i]));
            pairing_elems.push((&temp[i].1, &setup_params.y[i]));
            pairing_elems.push((&temp[i].2, &self.T[i]))
        }

        let e = GT::ate_multi_pairing(pairing_elems);
        Ok(e.is_one())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // For benchmarking
    use std::time::{Duration, Instant};

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
        assert!(sig.verify_fast(msgs.as_slice(), &vk, &params).unwrap());
        println!("Fast verify takes {:?}", start.elapsed());

        let r = FieldElement::random();
        let sig_randomized = sig.randomize(&r);
        assert!(sig_randomized
            .verify(msgs.as_slice(), &vk, &params)
            .unwrap());
        assert!(sig_randomized
            .verify_fast(msgs.as_slice(), &vk, &params)
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
        assert!(sig.verify_fast(msgs.as_slice(), &vk, &params).unwrap());
        println!("Fast verify takes {:?}", start.elapsed());

        let r = FieldElement::random();
        let sig_randomized = sig.randomize(&r);
        assert!(sig_randomized
            .verify(msgs.as_slice(), &vk, &params)
            .unwrap());
        assert!(sig_randomized
            .verify_fast(msgs.as_slice(), &vk, &params)
            .unwrap());
    }
}
