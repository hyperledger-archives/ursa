// A presenter is an entity holding a CredChain which does proof of attribute tokens
// Protocol described in Figure 4 and Figure 5 of section 5.3 of the paper. Some corrections were
// made which are commented inline with the code.

use super::errors::{DelgCredCDDError, DelgCredCDDErrorKind, DelgCredCDDResult};
use super::groth_sig::{Groth1SetupParams, Groth1Sig, Groth1Verkey, Groth2SetupParams, Groth2Sig};
use super::issuer::{CredChain, EvenLevelVerkey, OddLevelVerkey};
use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::{G1LookupTable, G1Vector, G1};
use amcl_wrapper::group_elem_g2::{G2LookupTable, G2Vector, G2};
use std::collections::{HashMap, HashSet};

pub type OddLevelAttribute = G1;
pub type EvenLevelAttribute = G2;

// Assumes that chain has already been verified using `CredChain::verify_delegations`
#[derive(Clone, Debug)]
pub struct AttributeToken<'a> {
    L: usize,
    cred_chain: &'a CredChain,
    setup_params_1: &'a Groth1SetupParams,
    setup_params_2: &'a Groth2SetupParams,
    odd_level_blinded_sigs: Vec<Groth1Sig>,
    even_level_blinded_sigs: Vec<Groth2Sig>,
    blindings_sigs: FieldElementVector,
    blindings_vk: FieldElementVector,
    blindings_s: FieldElementVector,
    blindings_t: Vec<FieldElementVector>,
    blindings_a: Vec<FieldElementVector>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttributeTokenComm {
    pub odd_level_blinded_r: G2Vector,
    pub even_level_blinded_r: G1Vector,
    pub comms_s: Vec<GT>,
    pub comms_t: Vec<Vec<GT>>,
    pub odd_level_revealed_attributes: Vec<HashMap<usize, OddLevelAttribute>>,
    pub even_level_revealed_attributes: Vec<HashMap<usize, EvenLevelAttribute>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttributeTokenResp {
    pub resp_csk: FieldElement,
    pub odd_level_resp_vk: G1Vector,
    pub even_level_resp_vk: G2Vector,
    pub odd_level_resp_s: G1Vector,
    pub even_level_resp_s: G2Vector,
    pub odd_level_resp_t: Vec<G1Vector>,
    pub even_level_resp_t: Vec<G2Vector>,
    pub odd_level_resp_a: Vec<G1Vector>,
    pub even_level_resp_a: Vec<G2Vector>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrecompOnSetupParams {
    // In practice, e(g1, g2)^-1 in both Groth1 and Groth2 can be same
    // e(g1, g2)^-1 when g1 and g2 are part of Groth1 params
    pub pairing_inv_groth1_g1_g2: GT,
    // e(g1, g2)^-1 when g1 and g2 are part of Groth2 params
    pub pairing_inv_groth2_g1_g2: GT,
    // e(-y_i, g1) when g2 and y_i are part of Groth1 params
    pub groth1_neg_y_g2: Vec<GT>,
    // e(-g1, y_i) when g1 and y_i are part of Groth2 params
    pub groth2_neg_g1_y: Vec<GT>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrecompOnCredChain {
    pub pairing_g_r: Vec<GT>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrecompForCommitmentReconstitution {
    // In practice, e(g1, g2)^-1 in both Groth1 and Groth2 can be same
    // e(g1, g2)^-1 when g1 and g2 are part of Groth1 params
    pub pairing_inv_groth1_g1_g2: GT,
    // e(g1, g2)^-1 when g1 and g2 are part of Groth2 params
    pub pairing_inv_groth2_g1_g2: GT,
    pub groth1_y0_g2: GT,
    pub groth2_g1_y0: GT,
    pub groth1_g1_ipk: GT,
    pub groth1_y_ipk: Vec<GT>,
}

impl PrecompOnSetupParams {
    pub fn new(setup_params_1: &Groth1SetupParams, setup_params_2: &Groth2SetupParams) -> Self {
        // e(-g1, g2) and e(g1, -g2) are equal and same as e(g1, g2)^-1.
        // Not computing e(g1, g2)^-1 as computing inverse is more expensive than negating a group element
        // Negating element of G1 is cheaper than G2
        let pairing_inv_groth1_g1_g2 =
            GT::ate_pairing(&setup_params_1.g1.negation(), &setup_params_1.g2);
        let pairing_inv_groth2_g1_g2 =
            GT::ate_pairing(&setup_params_2.g1.negation(), &setup_params_2.g2);
        let mut groth1_y_g2 = Vec::<GT>::with_capacity(setup_params_1.y.len());
        let mut groth2_g1_y = Vec::<GT>::with_capacity(setup_params_2.y.len());
        let neg_g2 = -&setup_params_1.g2;
        let neg_g1 = -&setup_params_2.g1;
        for y in setup_params_1.y.iter() {
            groth1_y_g2.push(GT::ate_pairing(y, &neg_g2));
        }
        for y in setup_params_2.y.iter() {
            groth2_g1_y.push(GT::ate_pairing(&neg_g1, y));
        }
        Self {
            pairing_inv_groth1_g1_g2,
            pairing_inv_groth2_g1_g2,
            groth1_neg_y_g2: groth1_y_g2,
            groth2_neg_g1_y: groth2_g1_y,
        }
    }
}

impl PrecompOnCredChain {
    pub fn new(
        cred_chain: &CredChain,
        setup_params_1: &Groth1SetupParams,
        setup_params_2: &Groth2SetupParams,
    ) -> DelgCredCDDResult<Self> {
        let mut pairing_g_r = vec![];
        for i in 1..=cred_chain.size() {
            if i % 2 == 1 {
                // Odd levels
                let link = cred_chain.get_odd_link(i / 2)?;
                // e(g1, r_i)
                pairing_g_r.push(GT::ate_pairing(&setup_params_1.g1, &link.signature.R));
            } else {
                // Even levels
                let link = cred_chain.get_even_link((i / 2) - 1)?;
                // e(r_i, g2)
                pairing_g_r.push(GT::ate_pairing(&link.signature.R, &setup_params_2.g2));
            }
        }
        Ok(Self { pairing_g_r })
    }
}

impl PrecompForCommitmentReconstitution {
    pub fn new(
        ipk: &EvenLevelVerkey,
        setup_params_1: &Groth1SetupParams,
        setup_params_2: &Groth2SetupParams,
    ) -> Self {
        let pairing_inv_groth1_g1_g2 =
            GT::ate_pairing(&setup_params_1.g1.negation(), &setup_params_1.g2);
        let pairing_inv_groth2_g1_g2 =
            GT::ate_pairing(&setup_params_2.g1.negation(), &setup_params_2.g2);
        let groth1_y0_g2 = GT::ate_pairing(&setup_params_1.y[0], &setup_params_1.g2);
        let groth2_g1_y0 = GT::ate_pairing(&setup_params_2.g1, &setup_params_2.y[0]);
        let groth1_g1_ipk = GT::ate_pairing(&setup_params_1.g1, &ipk.0);
        let mut groth1_y_ipk = vec![];
        for y in setup_params_1.y.iter() {
            groth1_y_ipk.push(GT::ate_pairing(y, &ipk.0));
        }
        Self {
            pairing_inv_groth1_g1_g2,
            pairing_inv_groth2_g1_g2,
            groth1_y0_g2,
            groth2_g1_y0,
            groth1_g1_ipk,
            groth1_y_ipk,
        }
    }
}

macro_rules! check_blindings_count {
    ( $self:ident, $i: ident, $link:ident, $unrevealed_attr_count:ident ) => {{
        if $self.blindings_t[$i - 1].len() != $link.signature.T.len() {
            Err(DelgCredCDDError::from_kind(
                DelgCredCDDErrorKind::GeneralError {
                    msg: format!("t blindings count unequal to t count"),
                },
            ))
        } else if $link.attribute_count() != $link.signature.T.len() {
            Err(DelgCredCDDError::from_kind(
                DelgCredCDDErrorKind::GeneralError {
                    msg: format!("attribute count unequal to t count"),
                },
            ))
        } else if $self.blindings_a[$i - 1].len() != $unrevealed_attr_count {
            Err(DelgCredCDDError::from_kind(
                DelgCredCDDErrorKind::GeneralError {
                    msg: format!("attribute blidnding count unequal to unrevealed attribute count"),
                },
            ))
        } else {
            Ok(())
        }
    }};
}

impl<'a> AttributeToken<'a> {
    pub fn new(
        cred_chain: &'a CredChain,
        setup_params_1: &'a Groth1SetupParams,
        setup_params_2: &'a Groth2SetupParams,
    ) -> Self {
        let L = cred_chain.size();
        Self {
            L,
            cred_chain,
            setup_params_1,
            setup_params_2,
            odd_level_blinded_sigs: Vec::<Groth1Sig>::new(),
            even_level_blinded_sigs: Vec::<Groth2Sig>::new(),
            blindings_sigs: FieldElementVector::with_capacity(L),
            blindings_vk: FieldElementVector::with_capacity(L),
            blindings_s: FieldElementVector::with_capacity(L),
            blindings_t: Vec::<FieldElementVector>::with_capacity(L),
            blindings_a: Vec::<FieldElementVector>::with_capacity(L),
        }
    }

    /// Corresponds to commitment phase of Figure 4 from the paper
    /// Assuming that chain has already been verified using `CredChain::verify_delegations`
    pub fn commitment(
        &mut self,
        revealed: Vec<HashSet<usize>>,
    ) -> DelgCredCDDResult<AttributeTokenComm> {
        let precomputed_setup_vals =
            PrecompOnSetupParams::new(&self.setup_params_1, &self.setup_params_2);
        let precomputed_sig_vals =
            PrecompOnCredChain::new(&self.cred_chain, &self.setup_params_1, &self.setup_params_2)?;
        self.commitment_with_precomputation(
            revealed,
            &precomputed_setup_vals,
            &precomputed_sig_vals,
        )
    }

    /// Corresponds to response phase of Figure 4 from the paper
    pub fn response(
        &self,
        at: &AttributeTokenComm,
        sig_key: &FieldElement,
        challenge: &FieldElement,
        even_level_vks: Vec<&EvenLevelVerkey>,
        odd_level_vks: Vec<&OddLevelVerkey>,
    ) -> DelgCredCDDResult<AttributeTokenResp> {
        at.validate(self.L)?;

        let mut resp_csk = FieldElement::zero();
        let mut odd_level_resp_vk = G1Vector::new(0);
        let mut even_level_resp_vk = G2Vector::new(0);
        let mut odd_level_resp_s = G1Vector::new(0);
        let mut even_level_resp_s = G2Vector::new(0);
        let mut odd_level_resp_t = Vec::<G1Vector>::new();
        let mut even_level_resp_t = Vec::<G2Vector>::new();
        let mut odd_level_resp_a = Vec::<G1Vector>::new();
        let mut even_level_resp_a = Vec::<G2Vector>::new();

        for i in 1..=self.L {
            if i % 2 == 1 {
                let link = self.cred_chain.get_odd_link(i / 2)?;
                // Different from paper here, paper uses `s` from the signature but `s` from blind signature should be used.
                // g1^s_blinding * s'^challenge
                odd_level_resp_s.push(self.setup_params_1.g1.binary_scalar_mul(
                    &self.odd_level_blinded_sigs[i / 2].S,
                    &self.blindings_s[i - 1],
                    challenge,
                ));

                if i != self.L {
                    odd_level_resp_vk.push(self.setup_params_1.g1.binary_scalar_mul(
                        &odd_level_vks[i / 2].0,
                        &self.blindings_vk[i - 1],
                        challenge,
                    ));
                } else {
                    resp_csk = &self.blindings_vk[i - 1] + (challenge * sig_key);
                }

                // Total messages - revealed attributes - last message (for verkey)
                let unrevealed_attr_count =
                    link.attribute_count() - at.odd_level_revealed_attributes[i / 2].len() - 1;

                check_blindings_count!(self, i, link, unrevealed_attr_count)?;

                let mut resp_t = G1Vector::with_capacity(link.attribute_count());
                let mut resp_a = G1Vector::with_capacity(unrevealed_attr_count);
                let mut k = 0;
                for j in 0..link.attribute_count() {
                    // Different from paper here, paper uses `t` from the signature but `t` from blind signature should be used.
                    resp_t.push(self.setup_params_1.g1.binary_scalar_mul(
                        &self.odd_level_blinded_sigs[i / 2].T[j],
                        &self.blindings_t[i - 1][j],
                        challenge,
                    ));
                    // If attribute is not revealed. Last attribute is verkey so ignore.
                    if j != (link.attribute_count() - 1)
                        && !at.odd_level_revealed_attributes[i / 2].contains_key(&j)
                    {
                        resp_a.push(self.setup_params_1.g1.binary_scalar_mul(
                            &link.attributes[j],
                            &self.blindings_a[i - 1][k],
                            challenge,
                        ));
                        k += 1;
                    }
                }
                debug_assert_eq!(resp_a.len(), unrevealed_attr_count);

                odd_level_resp_t.push(resp_t);
                odd_level_resp_a.push(resp_a);
            } else {
                let link = self.cred_chain.get_even_link((i / 2) - 1)?;

                even_level_resp_s.push(binary_scalar_mul_g2(
                    &self.setup_params_2.g2,
                    &self.even_level_blinded_sigs[(i / 2) - 1].S,
                    &self.blindings_s[i - 1],
                    challenge,
                ));

                if i != self.L {
                    even_level_resp_vk.push(binary_scalar_mul_g2(
                        &self.setup_params_2.g2,
                        &even_level_vks[(i / 2) - 1].0,
                        &self.blindings_vk[i - 1],
                        challenge,
                    ));
                } else {
                    resp_csk = &self.blindings_vk[i - 1] + (challenge * sig_key);
                }

                // Total messages - revealed attributes - last message (for verkey)
                let unrevealed_attr_count = link.attribute_count()
                    - at.even_level_revealed_attributes[(i / 2) - 1].len()
                    - 1;

                check_blindings_count!(self, i, link, unrevealed_attr_count)?;

                let mut resp_t = G2Vector::with_capacity(link.attribute_count());
                let mut resp_a = G2Vector::with_capacity(unrevealed_attr_count);
                let mut k = 0;
                for j in 0..link.attribute_count() {
                    resp_t.push(binary_scalar_mul_g2(
                        &self.setup_params_2.g2,
                        &self.even_level_blinded_sigs[(i / 2) - 1].T[j],
                        &self.blindings_t[i - 1][j],
                        challenge,
                    ));
                    // If attribute is not revealed. Last attribute is verkey so ignore.
                    if j != (link.attribute_count() - 1)
                        && !at.even_level_revealed_attributes[(i / 2) - 1].contains_key(&j)
                    {
                        resp_a.push(binary_scalar_mul_g2(
                            &self.setup_params_2.g2,
                            &link.attributes[j],
                            &self.blindings_a[i - 1][k],
                            challenge,
                        ));
                        k += 1;
                    }
                }
                debug_assert_eq!(resp_a.len(), unrevealed_attr_count);

                even_level_resp_t.push(resp_t);
                even_level_resp_a.push(resp_a);
            }
        }

        Ok(AttributeTokenResp {
            resp_csk,
            odd_level_resp_vk,
            even_level_resp_vk,
            odd_level_resp_s,
            even_level_resp_s,
            odd_level_resp_t,
            even_level_resp_t,
            odd_level_resp_a,
            even_level_resp_a,
        })
    }

    /// `extra` can be used to sign a message `m`. Just put the byte representation of `m` in `extra`
    pub fn gen_challenge(
        at: &AttributeTokenComm,
        ipk: &Groth1Verkey,
        mut extra: Vec<u8>,
    ) -> FieldElement {
        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&ipk.0.to_bytes());
        bytes.extend_from_slice(&at.to_bytes());
        bytes.append(&mut extra);
        FieldElement::from_msg_hash(&bytes)
    }

    /// Corresponds to Figure 5 from the paper
    pub fn reconstruct_commitment(
        L: usize,
        comm: &AttributeTokenComm,
        resp: &AttributeTokenResp,
        challenge: &FieldElement,
        revealed: Vec<HashSet<usize>>,
        ipk: &Groth1Verkey,
        setup_params_1: &Groth1SetupParams,
        setup_params_2: &Groth2SetupParams,
    ) -> DelgCredCDDResult<AttributeTokenComm> {
        comm.validate(L)?;
        resp.validate(L)?;

        let mut comms_s = Vec::<GT>::with_capacity(L);
        let mut comms_t = Vec::<Vec<GT>>::with_capacity(L);

        // In practice, g1 and g2 in both Groth1 and Groth2 can be same
        // The following can be precomputed if performance is critical
        let groth1_neg_g1 = -&setup_params_1.g1;
        let groth1_neg_g2 = -&setup_params_1.g2;
        let groth2_neg_g1 = -&setup_params_2.g1;
        let groth2_neg_g2 = -&setup_params_2.g2;

        let challenge_neg = -challenge;
        let challenge_neg_wnaf = challenge_neg.to_wnaf(5);

        let groth2_g1_table = G1LookupTable::from(&setup_params_2.g1);
        let groth1_g2_table = G2LookupTable::from(&setup_params_1.g2);
        let ipk_table = G2LookupTable::from(&ipk.0);

        // g1^-c
        let groth2_g1_c = G1::wnaf_mul(&groth2_g1_table, &challenge_neg_wnaf);
        // g2^-c
        let groth1_g2_c = G2::wnaf_mul(&groth1_g2_table, &challenge_neg_wnaf);
        // ipk^-c
        let ipk_c = G2::wnaf_mul(&ipk_table, &challenge_neg_wnaf);

        // e(y0, g2)^{-c}
        let y0_g2_c = GT::ate_pairing(&setup_params_1.y[0], &groth1_g2_c);
        // e(g1, y0)^{-c} = e(g1^{-c}, y0)
        let g1_y0_c = GT::ate_pairing(&groth2_g1_c, &setup_params_2.y[0]);

        for i in 1..=L {
            if i % 2 == 1 {
                // Odd level
                let attr_count = comm.comms_t[i - 1].len();
                let unrevealed_attr_count = attr_count - revealed[i - 1].len();
                if attr_count > setup_params_1.y.len() {
                    return Err(DelgCredCDDErrorKind::MoreAttributesThanExpected {
                        expected: setup_params_1.y.len() + 1,
                        given: attr_count,
                    }
                    .into());
                }
                // Skipping 1 for verkey
                if (unrevealed_attr_count - 1) > resp.odd_level_resp_a[i / 2].len() {
                    return Err(DelgCredCDDErrorKind::MoreUnrevealedAttributesThanExpected {
                        expected: resp.odd_level_resp_a[i / 2].len(),
                        given: unrevealed_attr_count,
                    }
                    .into());
                }

                // e(y[j], ipk)^-c can be changed to e(y[j], ipk^-c) and ipk^-c can be computed once for all odd levels.
                // Then e(y[j], ipk)^-c can then be used in a multi-pairing.
                let com_i_s = if i == 1 {
                    // e(resp_s_i, r'_i) * e(g1, ipk)^-c
                    // e(g1, ipk)^-c = e(g1, ipk^-c) => e(resp_s_i, r'_i) * e(g1, ipk^-c)
                    let e_1 = GT::ate_2_pairing(
                        &resp.odd_level_resp_s[i / 2],
                        &comm.odd_level_blinded_r[i / 2],
                        &setup_params_1.g1,
                        &ipk_c,
                    );
                    // e(resp_s_i, r'_i) * ( e(g1, ipk) * e(y0, g2) )^-c
                    &e_1 * &y0_g2_c
                } else {
                    // e(resp_s_i, r'_i) * e(-g1, resp_vk_{i-1})
                    let e_1 = GT::ate_2_pairing(
                        &resp.odd_level_resp_s[i / 2],
                        &comm.odd_level_blinded_r[i / 2],
                        &groth1_neg_g1,
                        &resp.even_level_resp_vk[(i / 2) - 1],
                    );
                    // e(resp_s_i, r'_i) * e(-g1, resp_vk_{i-1}) * e(y_0, g2)^-c
                    &e_1 * &y0_g2_c
                };
                comms_s.push(com_i_s);

                let mut com_t = Vec::<GT>::with_capacity(comm.comms_t[i - 1].len());
                let mut k = 0;

                // Last attribute is the verkey so skip for now
                for j in 0..(attr_count - 1) {
                    if !revealed[i - 1].contains(&j) {
                        if i == 1 {
                            com_t.push(GT::ate_multi_pairing(vec![
                                (
                                    &resp.odd_level_resp_t[i / 2][j],
                                    &comm.odd_level_blinded_r[i / 2],
                                ),
                                (&resp.odd_level_resp_a[i / 2][k], &groth1_neg_g2),
                                (&setup_params_1.y[j], &ipk_c),
                            ]));
                        } else {
                            com_t.push(GT::ate_multi_pairing(vec![
                                (
                                    &resp.odd_level_resp_t[i / 2][j],
                                    &comm.odd_level_blinded_r[i / 2],
                                ),
                                (&resp.odd_level_resp_a[i / 2][k], &groth1_neg_g2),
                                (
                                    &(-&setup_params_1.y[j]),
                                    &resp.even_level_resp_vk[(i / 2) - 1],
                                ),
                            ]));
                        }
                        k += 1;
                    } else {
                        if i == 1 {
                            com_t.push(GT::ate_multi_pairing(vec![
                                (
                                    &resp.odd_level_resp_t[i / 2][j],
                                    &comm.odd_level_blinded_r[i / 2],
                                ),
                                (&comm.odd_level_revealed_attributes[i / 2][&j], &groth1_g2_c),
                                (&setup_params_1.y[j], &ipk_c),
                            ]));
                        } else {
                            com_t.push(GT::ate_multi_pairing(vec![
                                (
                                    &resp.odd_level_resp_t[i / 2][j],
                                    &comm.odd_level_blinded_r[i / 2],
                                ),
                                (
                                    &(-&setup_params_1.y[j]),
                                    &resp.even_level_resp_vk[(i / 2) - 1],
                                ),
                                (&comm.odd_level_revealed_attributes[i / 2][&j], &groth1_g2_c),
                            ]));
                        }
                    }
                }

                // For verkey
                let com_i_vk = if i == 1 {
                    if i != L {
                        GT::ate_multi_pairing(vec![
                            (
                                &resp.odd_level_resp_t[i / 2][attr_count - 1],
                                &comm.odd_level_blinded_r[i / 2],
                            ),
                            (&resp.odd_level_resp_vk[i / 2], &groth1_neg_g2),
                            (&setup_params_1.y[attr_count - 1], &ipk_c),
                        ])
                    } else {
                        GT::ate_multi_pairing(vec![
                            (
                                &resp.odd_level_resp_t[i / 2][attr_count - 1],
                                &comm.odd_level_blinded_r[i / 2],
                            ),
                            (&(&setup_params_1.g1 * &resp.resp_csk), &groth1_neg_g2),
                            (&setup_params_1.y[attr_count - 1], &ipk_c),
                        ])
                    }
                } else {
                    if i != L {
                        GT::ate_multi_pairing(vec![
                            (
                                &resp.odd_level_resp_t[i / 2][attr_count - 1],
                                &comm.odd_level_blinded_r[i / 2],
                            ),
                            (
                                &(-&setup_params_1.y[attr_count - 1]),
                                &resp.even_level_resp_vk[(i / 2) - 1],
                            ),
                            (&resp.odd_level_resp_vk[i / 2], &groth1_neg_g2),
                        ])
                    } else {
                        GT::ate_multi_pairing(vec![
                            (
                                &resp.odd_level_resp_t[i / 2][attr_count - 1],
                                &comm.odd_level_blinded_r[i / 2],
                            ),
                            (
                                &(-&setup_params_1.y[attr_count - 1]),
                                &resp.even_level_resp_vk[(i / 2) - 1],
                            ),
                            (&(&setup_params_1.g1 * &resp.resp_csk), &groth1_neg_g2),
                        ])
                    }
                };
                com_t.push(com_i_vk);
                comms_t.push(com_t);
            } else {
                // Even level
                let attr_count = comm.comms_t[i - 1].len();
                let unrevealed_attr_count = attr_count - revealed[i - 1].len();
                if attr_count > setup_params_2.y.len() {
                    return Err(DelgCredCDDErrorKind::MoreAttributesThanExpected {
                        expected: setup_params_2.y.len() + 1,
                        given: attr_count,
                    }
                    .into());
                }
                // Skipping 1 for verkey
                if (unrevealed_attr_count - 1) > resp.even_level_resp_a[(i / 2) - 1].len() {
                    return Err(DelgCredCDDErrorKind::MoreUnrevealedAttributesThanExpected {
                        expected: resp.even_level_resp_a[(i / 2) - 1].len(),
                        given: unrevealed_attr_count,
                    }
                    .into());
                }

                let e_1 = GT::ate_2_pairing(
                    &comm.even_level_blinded_r[(i / 2) - 1],
                    &resp.even_level_resp_s[(i / 2) - 1],
                    &resp.odd_level_resp_vk[(i / 2) - 1],
                    &groth2_neg_g2,
                );
                let com_i_s = &e_1 * &g1_y0_c;
                comms_s.push(com_i_s);

                let mut com_t = Vec::<GT>::with_capacity(comm.comms_t[i - 1].len());
                let mut k = 0;

                // Last attribute is the verkey so skip for now
                for j in 0..(attr_count - 1) {
                    if !revealed[i - 1].contains(&j) {
                        com_t.push(GT::ate_multi_pairing(vec![
                            // XXX: -y[j] can be pre-computed
                            (
                                &resp.odd_level_resp_vk[(i / 2) - 1],
                                &(-&setup_params_2.y[j]),
                            ),
                            (
                                &comm.even_level_blinded_r[(i / 2) - 1],
                                &resp.even_level_resp_t[(i / 2) - 1][j],
                            ),
                            (&groth2_neg_g1, &resp.even_level_resp_a[(i / 2) - 1][k]),
                        ]));
                        k += 1;
                    } else {
                        com_t.push({
                            // XXX: -y[j] can be pre-computed
                            GT::ate_multi_pairing(vec![
                                (
                                    &resp.odd_level_resp_vk[(i / 2) - 1],
                                    &(-&setup_params_2.y[j]),
                                ),
                                (
                                    &comm.even_level_blinded_r[(i / 2) - 1],
                                    &resp.even_level_resp_t[(i / 2) - 1][j],
                                ),
                                (
                                    &groth2_g1_c,
                                    &comm.even_level_revealed_attributes[(i / 2) - 1][&j],
                                ),
                            ])
                        });
                    }
                }

                // For verkey
                let com_i_vk = if i != L {
                    GT::ate_multi_pairing(vec![
                        (
                            &comm.even_level_blinded_r[(i / 2) - 1],
                            &resp.even_level_resp_t[(i / 2) - 1][attr_count - 1],
                        ),
                        (
                            &resp.odd_level_resp_vk[(i / 2) - 1],
                            &(-&setup_params_2.y[attr_count - 1]),
                        ),
                        (&groth2_neg_g1, &resp.even_level_resp_vk[(i / 2) - 1]),
                    ])
                } else {
                    GT::ate_multi_pairing(vec![
                        (
                            &comm.even_level_blinded_r[(i / 2) - 1],
                            &resp.even_level_resp_t[(i / 2) - 1][attr_count - 1],
                        ),
                        (
                            &resp.odd_level_resp_vk[(i / 2) - 1],
                            &(-&setup_params_2.y[attr_count - 1]),
                        ),
                        (&(&groth2_neg_g1 * &resp.resp_csk), &setup_params_2.g2),
                    ])
                };
                com_t.push(com_i_vk);
                comms_t.push(com_t);
            }
        }

        let mut reconstructed_comm = comm.clone();
        reconstructed_comm.comms_s = comms_s;
        reconstructed_comm.comms_t = comms_t;
        Ok(reconstructed_comm)
    }

    pub fn commitment_with_precomputation_on_setup_params(
        &mut self,
        revealed: Vec<HashSet<usize>>,
        precomputed: &PrecompOnSetupParams,
    ) -> DelgCredCDDResult<AttributeTokenComm> {
        let precomputed_sig_vals =
            PrecompOnCredChain::new(&self.cred_chain, &self.setup_params_1, &self.setup_params_2)?;
        self.commitment_with_precomputation(revealed, precomputed, &precomputed_sig_vals)
    }

    pub fn commitment_with_precomputation(
        &mut self,
        revealed: Vec<HashSet<usize>>,
        precomp_setup: &PrecompOnSetupParams,
        precomp_chain: &PrecompOnCredChain,
    ) -> DelgCredCDDResult<AttributeTokenComm> {
        if revealed.len() != self.L {
            return Err(
                DelgCredCDDErrorKind::IncorrectNumberOfRevealedAttributeSets {
                    expected: self.L,
                    given: revealed.len(),
                }
                .into(),
            );
        }

        let mut odd_level_revealed_attributes =
            Vec::<HashMap<usize, OddLevelAttribute>>::with_capacity(self.L);
        let mut even_level_revealed_attributes =
            Vec::<HashMap<usize, EvenLevelAttribute>>::with_capacity(self.L);
        let mut comms_s = Vec::<GT>::with_capacity(self.L);
        let mut comms_t = Vec::<Vec<GT>>::with_capacity(self.L);

        for i in 1..=self.L {
            let rho_sig = FieldElement::random();
            let rho_s = FieldElement::random();
            let rho_vk = FieldElement::random();

            let (rho_t, rho_a, com_s, com_t) = if i % 2 == 1 {
                // Odd levels
                let link = self.cred_chain.get_odd_link(i / 2)?;
                self.odd_level_blinded_sigs
                    .push(link.signature.randomize(&rho_sig));

                let mut rev_attrs = HashMap::<usize, OddLevelAttribute>::new();

                // e(g1, r_i)
                let pairing_g1_r_i = &precomp_chain.pairing_g_r[i - 1];

                let com_i_s = if i == 1 {
                    // e(g1, ri)^{rho_sig*rho_s}
                    pairing_g1_r_i.pow(&(&rho_sig * &rho_s))
                } else {
                    // e(g1, ri)^{rho_sig*rho_s} * e(-g1, g2)^{blindings_vk[i-2]}
                    let e_1 = pairing_g1_r_i.pow(&(&rho_sig * &rho_s));
                    let e_2 = precomp_setup
                        .pairing_inv_groth1_g1_g2
                        .pow(&self.blindings_vk[i - 2]);
                    &e_1 * &e_2
                };

                if revealed[i - 1].len() > self.setup_params_1.y.len() {
                    return Err(DelgCredCDDErrorKind::MoreAttributesThanExpected {
                        expected: self.setup_params_1.y.len(),
                        given: revealed[i - 1].len(),
                    }
                    .into());
                }

                let unrevealed_attr_count = link.attribute_count() - revealed[i - 1].len();
                let mut r_t = FieldElementVector::with_capacity(link.attribute_count());
                let mut r_a = FieldElementVector::with_capacity(unrevealed_attr_count);
                let mut com_t = Vec::<GT>::with_capacity(link.attribute_count());

                // Last attribute is the verkey so skip for now
                for j in 0..(link.attribute_count() - 1) {
                    // blinding for t_{i, j}
                    let rr_t = FieldElement::random();

                    let mut com_i_t = if i == 1 {
                        // e(g1, ri)^{rho_sig*rr_t}
                        pairing_g1_r_i.pow(&(&rho_sig * &rr_t))
                    } else {
                        // e(g1, ri)^{rho_sig*rr_t} * e(-y1_j, g2)^{blindings_vk[i-2]}
                        // e(-y1_j, g2) equals e(y1_j, -g2)
                        let e_1 = pairing_g1_r_i.pow(&(&rho_sig * &rr_t));
                        // Different from paper here, paper uses e(y1_j, .. but y1_j should be inverted.
                        let e_2 = precomp_setup.groth1_neg_y_g2[j].pow(&self.blindings_vk[i - 2]);
                        &e_1 * &e_2
                    };

                    if !revealed[i - 1].contains(&j) {
                        // Unrevealed attribute
                        // e(-g1, g2)^rr_a
                        let rr_a = FieldElement::random();
                        let e = precomp_setup.pairing_inv_groth1_g1_g2.pow(&rr_a);
                        // e(g1, ri)^{rho_sig*rr_t} * e(y1_j, g2)^{blindings_vk[i-2]} * e(-g1, g2)^rr_a
                        com_i_t = &com_i_t * &e;
                        r_a.push(rr_a);
                    } else {
                        rev_attrs.insert(j, link.attributes[j].clone());
                    }
                    com_t.push(com_i_t);
                    r_t.push(rr_t);
                }

                odd_level_revealed_attributes.push(rev_attrs);

                // For verkey
                let rr_t = FieldElement::random();
                let mut com_i_vk = {
                    // e(g1, ri)^{rho_sig*rr_t} * e(-g1, g2)^rr_a
                    let e_1 = pairing_g1_r_i.pow(&(&rho_sig * &rr_t));
                    let e_2 = precomp_setup.pairing_inv_groth1_g1_g2.pow(&rho_vk);
                    &e_1 * &e_2
                };
                if i != 1 {
                    // Different from paper here, paper uses e(y1_j, g2) but e(-y1_j, g2) should be used and e(-y1_j, g2) equals e(y1_j, -g2)
                    // e(y1_j, -g2)^{blindings_vk[i-2]}
                    let e = precomp_setup.groth1_neg_y_g2[link.attribute_count() - 1]
                        .pow(&self.blindings_vk[i - 2]);
                    // e(g1, ri)^{rho_sig*rr_t} * e(-g1, g2)^rr_a * e(y1_j, g2)^{blindings_vk[i-2]}
                    com_i_vk = &com_i_vk * &e;
                }
                com_t.push(com_i_vk);
                r_t.push(rr_t);

                (r_t, r_a, com_i_s, com_t)
            } else {
                // Even levels
                let link = self.cred_chain.get_even_link((i / 2) - 1)?;
                self.even_level_blinded_sigs
                    .push(link.signature.randomize(&rho_sig));

                let mut rev_attrs = HashMap::<usize, EvenLevelAttribute>::new();

                // e(r_i, g2)
                let pairing_r_i_g2 = &precomp_chain.pairing_g_r[i - 1];

                // e(ri, g2)^{rho_sig*rho_s} * e(-g1, g2)^{blindings_vk[i-2]}
                let e_1 = pairing_r_i_g2.pow(&(&rho_sig * &rho_s));
                let e_2 = precomp_setup
                    .pairing_inv_groth2_g1_g2
                    .pow(&self.blindings_vk[i - 2]);
                let com_i_s = &e_1 * &e_2;

                if revealed[i - 1].len() > self.setup_params_2.y.len() {
                    return Err(DelgCredCDDErrorKind::MoreAttributesThanExpected {
                        expected: self.setup_params_2.y.len(),
                        given: revealed[i - 1].len(),
                    }
                    .into());
                }

                let unrevealed_attr_count = link.attribute_count() - revealed[i - 1].len();
                let mut r_t = FieldElementVector::with_capacity(link.attribute_count());
                let mut r_a = FieldElementVector::with_capacity(unrevealed_attr_count);
                let mut com_t = Vec::<GT>::with_capacity(link.attribute_count());

                // Last attribute is the verkey so skip for now
                for j in 0..(link.attribute_count() - 1) {
                    // blinding for t_{i, j}
                    let rr_t = FieldElement::random();

                    // e(ri, g2)^{rho_sig*rr_t} * e(g1, -y2_j)^{blindings_vk[i-2]}.
                    // e(g1, -y2_j) equals e(-g1, y2_j)
                    let e_1 = pairing_r_i_g2.pow(&(&rho_sig * &rr_t));
                    let e_2 = precomp_setup.groth2_neg_g1_y[j].pow(&self.blindings_vk[i - 2]);
                    let mut com_i_t = &e_1 * &e_2;

                    if !revealed[i - 1].contains(&j) {
                        // Unrevealed attribute
                        // e(ri, g2)^{rho_sig*rr_t} * e(g1, -y2_j)^{blindings_vk[i-2]} * e(-g1, g2)^rr_a
                        // In above, replace e(g1, -y2_j)^{blindings_vk[i-2]} with e(-g1, y2_j)^{blindings_vk[i-2]}
                        let rr_a = FieldElement::random();
                        let e = GT::pow(&precomp_setup.pairing_inv_groth2_g1_g2, &rr_a);
                        com_i_t = &com_i_t * &e;
                        r_a.push(rr_a);
                    } else {
                        rev_attrs.insert(j, link.attributes[j].clone());
                    }
                    com_t.push(com_i_t);
                    r_t.push(rr_t);
                }

                even_level_revealed_attributes.push(rev_attrs);

                // For verkey
                let rr_t = FieldElement::random();
                // e(ri, g2)^{rho_sig*rr_t} * e(-g1, g2)^rr_a * e(g1, -y2_j)^{blindings_vk[i-2]}
                // In above, replace e(g1, -y2_j)^{blindings_vk[i-2]} with e(-g1, y2_j)^{blindings_vk[i-2]}
                let e_1 = GT::pow(pairing_r_i_g2, &(&rho_sig * &rr_t));
                let e_2 = GT::pow(&precomp_setup.pairing_inv_groth2_g1_g2, &rho_vk);
                let e_3 = precomp_setup.groth2_neg_g1_y[link.attribute_count() - 1]
                    .pow(&self.blindings_vk[i - 2]);
                let com_i_vk = &(&e_1 * &e_2) * &e_3;

                com_t.push(com_i_vk);
                r_t.push(rr_t);

                (r_t, r_a, com_i_s, com_t)
            };

            self.blindings_sigs.push(rho_sig);
            self.blindings_s.push(rho_s);
            self.blindings_vk.push(rho_vk);
            self.blindings_t.push(rho_t);
            self.blindings_a.push(rho_a);
            comms_s.push(com_s);
            comms_t.push(com_t);
        }
        let odd_level_blinded_r: G2Vector = self
            .odd_level_blinded_sigs
            .iter()
            .map(|sig| sig.R.clone())
            .collect::<Vec<G2>>()
            .into();
        let even_level_blinded_r: G1Vector = self
            .even_level_blinded_sigs
            .iter()
            .map(|sig| sig.R.clone())
            .collect::<Vec<G1>>()
            .into();

        Ok(AttributeTokenComm {
            odd_level_blinded_r,
            even_level_blinded_r,
            comms_s,
            comms_t,
            odd_level_revealed_attributes,
            even_level_revealed_attributes,
        })
    }

    pub fn reconstruct_commitment_with_precomputed_vals(
        L: usize,
        comm: &AttributeTokenComm,
        resp: &AttributeTokenResp,
        challenge: &FieldElement,
        revealed: Vec<HashSet<usize>>,
        setup_params_1: &Groth1SetupParams,
        setup_params_2: &Groth2SetupParams,
        precomputed: &PrecompForCommitmentReconstitution,
    ) -> DelgCredCDDResult<AttributeTokenComm> {
        comm.validate(L)?;
        resp.validate(L)?;

        let mut comms_s = Vec::<GT>::with_capacity(L);
        let mut comms_t = Vec::<Vec<GT>>::with_capacity(L);

        // In practice, g1 and g2 in both Groth1 and Groth2 can be same
        // The following can be precomputed if performance is critical
        let groth1_neg_g1 = -&setup_params_1.g1;
        let groth1_neg_g2 = -&setup_params_1.g2;
        let groth2_neg_g1 = -&setup_params_2.g1;
        let groth2_neg_g2 = -&setup_params_2.g2;

        let challenge_neg = -challenge;
        // g1^-c
        let groth2_g1_c = &setup_params_2.g1 * &challenge_neg;
        // g2^-c
        let groth1_g2_c = &setup_params_1.g2 * &challenge_neg;
        // e(y0, g2)^{-c}
        let y0_g2_c = precomputed.groth1_y0_g2.pow(&challenge_neg);
        // e(g1, y0)^{-c}
        let g1_y0_c = &precomputed.groth2_g1_y0.pow(&challenge_neg);

        for i in 1..=L {
            if i % 2 == 1 {
                // Odd level
                let attr_count = comm.comms_t[i - 1].len();
                let unrevealed_attr_count = attr_count - revealed[i - 1].len();
                if attr_count > setup_params_1.y.len() {
                    return Err(DelgCredCDDErrorKind::MoreAttributesThanExpected {
                        expected: setup_params_1.y.len() + 1,
                        given: attr_count,
                    }
                    .into());
                }
                // Skipping 1 for verkey
                if (unrevealed_attr_count - 1) > resp.odd_level_resp_a[i / 2].len() {
                    return Err(DelgCredCDDErrorKind::MoreUnrevealedAttributesThanExpected {
                        expected: resp.odd_level_resp_a[i / 2].len(),
                        given: unrevealed_attr_count,
                    }
                    .into());
                }

                // Use precomputed e(y[j], ipk) for all j
                let com_i_s = if i == 1 {
                    // e(resp_s_i, r'_i)
                    let e_1 = GT::ate_pairing(
                        &resp.odd_level_resp_s[i / 2],
                        &comm.odd_level_blinded_r[i / 2],
                    );
                    // e(g1, ipk)^-c * e(y0, g2)^-c = ( e(g1, ipk) * e(y0, g2) )^-c
                    // e(g1, ipk) * e(y0, g2)
                    let e_2 = &precomputed.groth1_g1_ipk * &precomputed.groth1_y0_g2;
                    // ( e(g1, ipk) * e(y0, g2) )^-c
                    let e_3 = GT::pow(&e_2, &challenge_neg);
                    // e(resp_s_i, r'_i) * ( e(g1, ipk) * e(y0, g2) )^-c
                    &e_1 * &e_3
                } else {
                    let e_1 = GT::ate_2_pairing(
                        &resp.odd_level_resp_s[i / 2],
                        &comm.odd_level_blinded_r[i / 2],
                        &groth1_neg_g1,
                        &resp.even_level_resp_vk[(i / 2) - 1],
                    );
                    &e_1 * &y0_g2_c
                };
                comms_s.push(com_i_s);

                let mut com_t = Vec::<GT>::with_capacity(comm.comms_t[i - 1].len());
                let mut k = 0;

                // Last attribute is the verkey so skip for now
                for j in 0..(attr_count - 1) {
                    if !revealed[i - 1].contains(&j) {
                        if i == 1 {
                            let e_1 = GT::ate_2_pairing(
                                &resp.odd_level_resp_t[i / 2][j],
                                &comm.odd_level_blinded_r[i / 2],
                                &resp.odd_level_resp_a[i / 2][k],
                                &groth1_neg_g2,
                            );
                            let e_2 = GT::pow(&precomputed.groth1_y_ipk[j], &challenge_neg);
                            com_t.push(&e_1 * &e_2);
                        } else {
                            com_t.push(GT::ate_multi_pairing(vec![
                                (
                                    &resp.odd_level_resp_t[i / 2][j],
                                    &comm.odd_level_blinded_r[i / 2],
                                ),
                                (&resp.odd_level_resp_a[i / 2][k], &groth1_neg_g2),
                                (
                                    &(-&setup_params_1.y[j]),
                                    &resp.even_level_resp_vk[(i / 2) - 1],
                                ),
                            ]));
                        }
                        k += 1;
                    } else {
                        if i == 1 {
                            let e_1 = GT::ate_2_pairing(
                                &resp.odd_level_resp_t[i / 2][j],
                                &comm.odd_level_blinded_r[i / 2],
                                &comm.odd_level_revealed_attributes[i / 2][&j],
                                &groth1_g2_c,
                            );
                            let e_2 = GT::pow(&precomputed.groth1_y_ipk[j], &challenge_neg);
                            com_t.push(&e_1 * &e_2);
                        } else {
                            com_t.push(GT::ate_multi_pairing(vec![
                                (
                                    &resp.odd_level_resp_t[i / 2][j],
                                    &comm.odd_level_blinded_r[i / 2],
                                ),
                                (
                                    &(-&setup_params_1.y[j]),
                                    &resp.even_level_resp_vk[(i / 2) - 1],
                                ),
                                (&comm.odd_level_revealed_attributes[i / 2][&j], &groth1_g2_c),
                            ]));
                        }
                    }
                }

                // For verkey
                let com_i_vk = if i == 1 {
                    if i != L {
                        let e_1 = GT::ate_2_pairing(
                            &resp.odd_level_resp_t[i / 2][attr_count - 1],
                            &comm.odd_level_blinded_r[i / 2],
                            &resp.odd_level_resp_vk[i / 2],
                            &groth1_neg_g2,
                        );
                        let e_2 =
                            GT::pow(&precomputed.groth1_y_ipk[attr_count - 1], &challenge_neg);
                        &e_1 * &e_2
                    } else {
                        let e_1 = GT::ate_pairing(
                            &resp.odd_level_resp_t[i / 2][attr_count - 1],
                            &comm.odd_level_blinded_r[i / 2],
                        );
                        let e_3 = GT::pow(&precomputed.pairing_inv_groth1_g1_g2, &resp.resp_csk);
                        let e_4 = &e_1 * &e_3;
                        let e_5 =
                            GT::pow(&precomputed.groth1_y_ipk[attr_count - 1], &challenge_neg);
                        &e_4 * &e_5
                    }
                } else {
                    if i != L {
                        GT::ate_multi_pairing(vec![
                            (
                                &resp.odd_level_resp_t[i / 2][attr_count - 1],
                                &comm.odd_level_blinded_r[i / 2],
                            ),
                            (
                                &(-&setup_params_1.y[attr_count - 1]),
                                &resp.even_level_resp_vk[(i / 2) - 1],
                            ),
                            (&resp.odd_level_resp_vk[i / 2], &groth1_neg_g2),
                        ])
                    } else {
                        let e_1 = GT::ate_2_pairing(
                            &resp.odd_level_resp_t[i / 2][attr_count - 1],
                            &comm.odd_level_blinded_r[i / 2],
                            &(-&setup_params_1.y[attr_count - 1]),
                            &resp.even_level_resp_vk[(i / 2) - 1],
                        );
                        let e_3 = GT::pow(&precomputed.pairing_inv_groth1_g1_g2, &resp.resp_csk);
                        &e_1 * &e_3
                    }
                };
                com_t.push(com_i_vk);
                comms_t.push(com_t);
            } else {
                // Even level
                let attr_count = comm.comms_t[i - 1].len();
                let unrevealed_attr_count = attr_count - revealed[i - 1].len();
                if attr_count > setup_params_2.y.len() {
                    return Err(DelgCredCDDErrorKind::MoreAttributesThanExpected {
                        expected: setup_params_2.y.len() + 1,
                        given: attr_count,
                    }
                    .into());
                }
                // Skipping 1 for verkey
                if (unrevealed_attr_count - 1) > resp.even_level_resp_a[(i / 2) - 1].len() {
                    return Err(DelgCredCDDErrorKind::MoreUnrevealedAttributesThanExpected {
                        expected: resp.even_level_resp_a[(i / 2) - 1].len(),
                        given: unrevealed_attr_count,
                    }
                    .into());
                }

                let e_1 = GT::ate_2_pairing(
                    &comm.even_level_blinded_r[(i / 2) - 1],
                    &resp.even_level_resp_s[(i / 2) - 1],
                    &resp.odd_level_resp_vk[(i / 2) - 1],
                    &groth2_neg_g2,
                );
                let com_i_s = &e_1 * g1_y0_c;
                comms_s.push(com_i_s);

                let mut com_t = Vec::<GT>::with_capacity(comm.comms_t[i - 1].len());
                let mut k = 0;

                // Last attribute is the verkey so skip for now
                for j in 0..(attr_count - 1) {
                    if !revealed[i - 1].contains(&j) {
                        com_t.push(GT::ate_multi_pairing(vec![
                            // XXX: -y[j] can be pre-computed
                            (
                                &resp.odd_level_resp_vk[(i / 2) - 1],
                                &(-&setup_params_2.y[j]),
                            ),
                            (
                                &comm.even_level_blinded_r[(i / 2) - 1],
                                &resp.even_level_resp_t[(i / 2) - 1][j],
                            ),
                            (&groth2_neg_g1, &resp.even_level_resp_a[(i / 2) - 1][k]),
                        ]));
                        k += 1;
                    } else {
                        com_t.push({
                            // XXX: -y[j] can be pre-computed
                            GT::ate_multi_pairing(vec![
                                (
                                    &resp.odd_level_resp_vk[(i / 2) - 1],
                                    &(-&setup_params_2.y[j]),
                                ),
                                (
                                    &comm.even_level_blinded_r[(i / 2) - 1],
                                    &resp.even_level_resp_t[(i / 2) - 1][j],
                                ),
                                (
                                    &groth2_g1_c,
                                    &comm.even_level_revealed_attributes[(i / 2) - 1][&j],
                                ),
                            ])
                        });
                    }
                }

                // For verkey
                let com_i_vk = if i != L {
                    GT::ate_multi_pairing(vec![
                        (
                            &comm.even_level_blinded_r[(i / 2) - 1],
                            &resp.even_level_resp_t[(i / 2) - 1][attr_count - 1],
                        ),
                        (
                            &resp.odd_level_resp_vk[(i / 2) - 1],
                            &(-&setup_params_2.y[attr_count - 1]),
                        ),
                        (&groth2_neg_g1, &resp.even_level_resp_vk[(i / 2) - 1]),
                    ])
                } else {
                    let e_1 = GT::ate_2_pairing(
                        &comm.even_level_blinded_r[(i / 2) - 1],
                        &resp.even_level_resp_t[(i / 2) - 1][attr_count - 1],
                        &resp.odd_level_resp_vk[(i / 2) - 1],
                        &(-&setup_params_2.y[attr_count - 1]),
                    );
                    let e_3 = GT::pow(&precomputed.pairing_inv_groth2_g1_g2, &resp.resp_csk);
                    &e_1 * &e_3
                };
                com_t.push(com_i_vk);
                comms_t.push(com_t);
            }
        }

        let mut reconstructed_comm = comm.clone();
        reconstructed_comm.comms_s = comms_s;
        reconstructed_comm.comms_t = comms_t;
        Ok(reconstructed_comm)
    }
}

macro_rules! check_odd_collection_length {
    ( $collection:expr, $L: ident, $entity_type:expr ) => {{
        if $L % 2 == 1 {
            if $collection.len() != (($L / 2) + 1) {
                Err(DelgCredCDDError::from_kind(
                    DelgCredCDDErrorKind::IncorrectNumberOfOddValues {
                        expected: ($L / 2) + 1,
                        given: $collection.len(),
                        entity_type: $entity_type,
                    },
                ))
            } else {
                Ok(())
            }
        } else {
            if $collection.len() != ($L / 2) {
                return Err(DelgCredCDDError::from_kind(
                    DelgCredCDDErrorKind::IncorrectNumberOfOddValues {
                        expected: $L / 2,
                        given: $collection.len(),
                        entity_type: $entity_type,
                    },
                ));
            } else {
                Ok(())
            }
        }
    }};
}

macro_rules! check_even_collection_length {
    ( $collection:expr, $L: ident, $entity_type:expr ) => {{
        if $collection.len() != ($L / 2) {
            Err(DelgCredCDDError::from_kind(
                DelgCredCDDErrorKind::IncorrectNumberOfEvenValues {
                    expected: $L / 2,
                    given: $collection.len(),
                    entity_type: $entity_type,
                },
            ))
        } else {
            Ok(())
        }
    }};
}

impl AttributeTokenComm {
    pub fn validate(&self, L: usize) -> DelgCredCDDResult<()> {
        if self.comms_t.len() != L {
            return Err(DelgCredCDDErrorKind::IncorrectNumberOfTCommitments {
                expected: L,
                given: self.comms_t.len(),
            }
            .into());
        }
        if self.comms_s.len() != L {
            return Err(DelgCredCDDErrorKind::IncorrectNumberOfSCommitments {
                expected: L,
                given: self.comms_s.len(),
            }
            .into());
        }
        if (self.odd_level_revealed_attributes.len() + self.even_level_revealed_attributes.len())
            != L
        {
            return Err(
                DelgCredCDDErrorKind::IncorrectNumberOfRevealedAttributeSets {
                    expected: L,
                    given: self.odd_level_revealed_attributes.len()
                        + self.even_level_revealed_attributes.len(),
                }
                .into(),
            );
        }
        if (self.odd_level_blinded_r.len() + self.even_level_blinded_r.len()) != L {
            return Err(DelgCredCDDErrorKind::IncorrectNumberOfBlindedR {
                expected: L,
                given: self.odd_level_blinded_r.len() + self.even_level_blinded_r.len(),
            }
            .into());
        }

        check_odd_collection_length!(
            self.odd_level_revealed_attributes,
            L,
            "revealed attributes".to_string()
        )?;
        check_odd_collection_length!(self.odd_level_blinded_r, L, "blinded r".to_string())?;
        check_even_collection_length!(
            self.even_level_revealed_attributes,
            L,
            "revealed attributes".to_string()
        )?;
        check_even_collection_length!(self.even_level_blinded_r, L, "blinded r".to_string())?;
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        for c in self.comms_s.iter() {
            bytes.extend_from_slice(&c.to_bytes())
        }
        for r in self.odd_level_blinded_r.iter() {
            bytes.extend_from_slice(&r.to_bytes())
        }
        for r in self.even_level_blinded_r.iter() {
            bytes.extend_from_slice(&r.to_bytes())
        }
        for v in self.comms_t.iter() {
            for c in v {
                bytes.extend_from_slice(&c.to_bytes())
            }
        }
        for r_map in &self.odd_level_revealed_attributes {
            for e in r_map.iter() {
                bytes.extend_from_slice(e.0.to_string().as_bytes());
                bytes.extend_from_slice(&e.1.to_bytes());
            }
        }
        for r_map in &self.even_level_revealed_attributes {
            for e in r_map.iter() {
                bytes.extend_from_slice(e.0.to_string().as_bytes());
                bytes.extend_from_slice(&e.1.to_bytes());
            }
        }
        bytes
    }
}

impl AttributeTokenResp {
    pub fn validate(&self, L: usize) -> DelgCredCDDResult<()> {
        if (self.odd_level_resp_s.len() + self.even_level_resp_s.len()) != L {
            return Err(DelgCredCDDErrorKind::UnequalNoOfCommitmentAndResponses {
                count_commitments: L,
                count_responses: self.odd_level_resp_s.len() + self.even_level_resp_s.len(),
                entity_type: "s from signature".to_string(),
            }
            .into());
        }

        if (self.odd_level_resp_t.len() + self.even_level_resp_t.len()) != L {
            return Err(DelgCredCDDErrorKind::UnequalNoOfCommitmentAndResponses {
                count_commitments: L,
                count_responses: self.odd_level_resp_t.len() + self.even_level_resp_t.len(),
                entity_type: "t from signature".to_string(),
            }
            .into());
        }
        Ok(())
    }
}

// XXX: Temporary until binary_scalar_mul is added to G2
fn binary_scalar_mul_g2(g2: &G2, h2: &G2, r1: &FieldElement, r2: &FieldElement) -> G2 {
    let mut g2_vec = G2Vector::with_capacity(2);
    g2_vec.push(g2.clone());
    g2_vec.push(h2.clone());
    let mut f_vec = FieldElementVector::with_capacity(2);
    f_vec.push(r1.clone());
    f_vec.push(r2.clone());
    g2_vec
        .multi_scalar_mul_const_time(f_vec.as_slice())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::super::groth_sig::{GrothS1, GrothS2};
    use super::super::issuer::{EvenLevelIssuer, OddLevelIssuer};
    use super::*;
    use amcl_wrapper::group_elem_g1::G1Vector;
    use amcl_wrapper::group_elem_g2::G2Vector;
    // For benchmarking
    use std::time::Instant;

    #[test]
    fn test_attribute_token() {
        let max_attributes = 6;
        let label = "test".as_bytes();

        println!(
            "Each credential will have {} attributes",
            max_attributes - 1
        );

        let params1 = GrothS1::setup(max_attributes, label);
        let params2 = GrothS2::setup(max_attributes, label);

        let l_0_issuer = EvenLevelIssuer::new(0).unwrap();
        let l_1_issuer = OddLevelIssuer::new(1).unwrap();
        let l_2_issuer = EvenLevelIssuer::new(2).unwrap();
        let l_3_issuer = OddLevelIssuer::new(3).unwrap();
        let l_4_issuer = EvenLevelIssuer::new(4).unwrap();
        let l_5_issuer = OddLevelIssuer::new(5).unwrap();

        let (l_0_issuer_sk, l_0_issuer_vk) = EvenLevelIssuer::keygen(&params1);
        let (l_1_issuer_sk, l_1_issuer_vk) = OddLevelIssuer::keygen(&params2);
        let (l_2_issuer_sk, l_2_issuer_vk) = EvenLevelIssuer::keygen(&params1);
        let (l_3_issuer_sk, l_3_issuer_vk) = OddLevelIssuer::keygen(&params2);
        let (l_4_issuer_sk, l_4_issuer_vk) = EvenLevelIssuer::keygen(&params1);
        let (l_5_issuer_sk, l_5_issuer_vk) = OddLevelIssuer::keygen(&params2);
        let (l_6_issuer_sk, l_6_issuer_vk) = EvenLevelIssuer::keygen(&params1);

        let attributes_1: G1Vector = (0..max_attributes - 1)
            .map(|_| G1::random())
            .collect::<Vec<G1>>()
            .into();
        let cred_link_1 = l_0_issuer
            .delegate(
                attributes_1.clone(),
                l_1_issuer_vk.clone(),
                &l_0_issuer_sk,
                &params1,
            )
            .unwrap();
        let mut chain_1 = CredChain::new();
        chain_1.extend_with_odd(cred_link_1).unwrap();

        let mut at_1 = AttributeToken::new(&chain_1, &params1, &params2);

        let start_com = Instant::now();
        let com_1 = at_1.commitment(vec![HashSet::<usize>::new(); 1]).unwrap();
        let com_duration = start_com.elapsed();

        assert!(com_1.odd_level_revealed_attributes[0].is_empty());

        let c_1 = AttributeToken::gen_challenge(&com_1, &l_0_issuer_vk, vec![]);

        let start_resp = Instant::now();
        let resp_1 = at_1
            .response(&com_1, &l_1_issuer_sk, &c_1, vec![], vec![&l_1_issuer_vk])
            .unwrap();
        let resp_duration = start_resp.elapsed();

        let L = com_1.comms_s.len();
        let start_recon = Instant::now();
        let recon_com_1 = AttributeToken::reconstruct_commitment(
            L,
            &com_1,
            &resp_1,
            &c_1,
            vec![HashSet::<usize>::new(); 1],
            &l_0_issuer_vk,
            &params1,
            &params2,
        )
        .unwrap();
        let recon_duration = start_recon.elapsed();

        let recon_c_1 = AttributeToken::gen_challenge(&recon_com_1, &l_0_issuer_vk, vec![]);
        assert_eq!(c_1, recon_c_1);
        println!("For delegation chain of length {}, commitment takes {:?}, response takes {:?}, commitment reconstitution takes {:?}. Total time taken by commitment and response is {:?}", L,
                 com_duration, resp_duration, recon_duration, com_duration + resp_duration);

        let attributes_2: G2Vector = (0..max_attributes - 1)
            .map(|_| G2::random())
            .collect::<Vec<G2>>()
            .into();
        let cred_link_2 = l_1_issuer
            .delegate(
                attributes_2.clone(),
                l_2_issuer_vk.clone(),
                &l_1_issuer_sk,
                &params2,
            )
            .unwrap();
        let mut chain_2 = chain_1.clone();
        chain_2.extend_with_even(cred_link_2).unwrap();

        let mut at_2 = AttributeToken::new(&chain_2, &params1, &params2);
        let start_com = Instant::now();
        let com_2 = at_2.commitment(vec![HashSet::<usize>::new(); 2]).unwrap();
        let com_duration = start_com.elapsed();

        assert!(com_2.odd_level_revealed_attributes[0].is_empty());
        assert!(com_2.even_level_revealed_attributes[0].is_empty());

        let c_2 = AttributeToken::gen_challenge(&com_2, &l_0_issuer_vk, vec![]);

        let start_resp = Instant::now();
        let resp_2 = at_2
            .response(
                &com_2,
                &l_2_issuer_sk,
                &c_2,
                vec![&l_2_issuer_vk],
                vec![&l_1_issuer_vk],
            )
            .unwrap();
        let resp_duration = start_resp.elapsed();

        let L = com_2.comms_s.len();
        let start_recon = Instant::now();
        let recon_com_2 = AttributeToken::reconstruct_commitment(
            L,
            &com_2,
            &resp_2,
            &c_2,
            vec![HashSet::<usize>::new(); 2],
            &l_0_issuer_vk,
            &params1,
            &params2,
        )
        .unwrap();
        let recon_duration = start_recon.elapsed();

        let recon_c_2 = AttributeToken::gen_challenge(&recon_com_2, &l_0_issuer_vk, vec![]);
        assert_eq!(c_2, recon_c_2);
        println!("For delegation chain of length {}, commitment takes {:?}, response takes {:?}, commitment reconstitution takes {:?}. Total time taken by commitment and response is {:?}", L,
                 com_duration, resp_duration, recon_duration, com_duration + resp_duration);

        let attributes_3: G1Vector = (0..max_attributes - 1)
            .map(|_| G1::random())
            .collect::<Vec<G1>>()
            .into();
        let cred_link_3 = l_2_issuer
            .delegate(
                attributes_3.clone(),
                l_3_issuer_vk.clone(),
                &l_2_issuer_sk,
                &params1,
            )
            .unwrap();
        let mut chain_3 = chain_2.clone();
        chain_3.extend_with_odd(cred_link_3).unwrap();

        let mut at_3 = AttributeToken::new(&chain_3, &params1, &params2);

        let start_com = Instant::now();
        let com_3 = at_3.commitment(vec![HashSet::<usize>::new(); 3]).unwrap();
        let com_duration = start_com.elapsed();

        assert!(com_3.odd_level_revealed_attributes[0].is_empty());
        assert!(com_3.odd_level_revealed_attributes[1].is_empty());
        assert!(com_3.even_level_revealed_attributes[0].is_empty());

        let c_3 = AttributeToken::gen_challenge(&com_3, &l_0_issuer_vk, vec![]);

        let start_resp = Instant::now();
        let resp_3 = at_3
            .response(
                &com_3,
                &l_3_issuer_sk,
                &c_3,
                vec![&l_2_issuer_vk],
                vec![&l_1_issuer_vk, &l_3_issuer_vk],
            )
            .unwrap();
        let resp_duration = start_resp.elapsed();

        let L = com_3.comms_s.len();
        let start_recon = Instant::now();
        let recon_com_3 = AttributeToken::reconstruct_commitment(
            L,
            &com_3,
            &resp_3,
            &c_3,
            vec![HashSet::<usize>::new(); 3],
            &l_0_issuer_vk,
            &params1,
            &params2,
        )
        .unwrap();
        let recon_duration = start_recon.elapsed();
        let recon_c_3 = AttributeToken::gen_challenge(&recon_com_3, &l_0_issuer_vk, vec![]);
        assert_eq!(c_3, recon_c_3);

        println!("For delegation chain of length {}, commitment takes {:?}, response takes {:?}, commitment reconstitution takes {:?}. Total time taken by commitment and response is {:?}", L,
                 com_duration, resp_duration, recon_duration, com_duration + resp_duration);

        let attributes_4: G2Vector = (0..max_attributes - 1)
            .map(|_| G2::random())
            .collect::<Vec<G2>>()
            .into();
        let cred_link_4 = l_3_issuer
            .delegate(
                attributes_4.clone(),
                l_4_issuer_vk.clone(),
                &l_3_issuer_sk,
                &params2,
            )
            .unwrap();
        let mut chain_4 = chain_3.clone();
        chain_4.extend_with_even(cred_link_4).unwrap();

        let mut at_4 = AttributeToken::new(&chain_4, &params1, &params2);

        let start_com = Instant::now();
        let com_4 = at_4.commitment(vec![HashSet::<usize>::new(); 4]).unwrap();
        let com_duration = start_com.elapsed();

        assert!(com_4.odd_level_revealed_attributes[0].is_empty());
        assert!(com_4.odd_level_revealed_attributes[1].is_empty());
        assert!(com_4.even_level_revealed_attributes[0].is_empty());
        assert!(com_4.even_level_revealed_attributes[1].is_empty());

        let c_4 = AttributeToken::gen_challenge(&com_4, &l_0_issuer_vk, vec![]);

        let start_resp = Instant::now();
        let resp_4 = at_4
            .response(
                &com_4,
                &l_4_issuer_sk,
                &c_4,
                vec![&l_2_issuer_vk, &l_4_issuer_vk],
                vec![&l_1_issuer_vk, &l_3_issuer_vk],
            )
            .unwrap();
        let resp_duration = start_resp.elapsed();

        let L = com_4.comms_s.len();
        let start_recon = Instant::now();
        let recon_com_4 = AttributeToken::reconstruct_commitment(
            L,
            &com_4,
            &resp_4,
            &c_4,
            vec![HashSet::<usize>::new(); 4],
            &l_0_issuer_vk,
            &params1,
            &params2,
        )
        .unwrap();
        let recon_duration = start_recon.elapsed();

        let recon_c_4 = AttributeToken::gen_challenge(&recon_com_4, &l_0_issuer_vk, vec![]);
        assert_eq!(c_4, recon_c_4);
        println!("For delegation chain of length {}, commitment takes {:?}, response takes {:?}, commitment reconstitution takes {:?}. Total time taken by commitment and response is {:?}", L,
                 com_duration, resp_duration, recon_duration, com_duration + resp_duration);

        let attributes_5: G1Vector = (0..max_attributes - 1)
            .map(|_| G1::random())
            .collect::<Vec<G1>>()
            .into();
        let cred_link_5 = l_4_issuer
            .delegate(
                attributes_5.clone(),
                l_5_issuer_vk.clone(),
                &l_4_issuer_sk,
                &params1,
            )
            .unwrap();
        let mut chain_5 = chain_4.clone();
        chain_5.extend_with_odd(cred_link_5).unwrap();

        let mut at_5 = AttributeToken::new(&chain_5, &params1, &params2);

        let start_com = Instant::now();
        let com_5 = at_5.commitment(vec![HashSet::<usize>::new(); 5]).unwrap();
        let com_duration = start_com.elapsed();

        assert!(com_5.odd_level_revealed_attributes[0].is_empty());
        assert!(com_5.odd_level_revealed_attributes[1].is_empty());
        assert!(com_5.odd_level_revealed_attributes[2].is_empty());
        assert!(com_5.even_level_revealed_attributes[0].is_empty());
        assert!(com_5.even_level_revealed_attributes[1].is_empty());

        let c_5 = AttributeToken::gen_challenge(&com_5, &l_0_issuer_vk, vec![]);

        let start_resp = Instant::now();
        let resp_5 = at_5
            .response(
                &com_5,
                &l_5_issuer_sk,
                &c_5,
                vec![&l_2_issuer_vk, &l_4_issuer_vk],
                vec![&l_1_issuer_vk, &l_3_issuer_vk, &l_5_issuer_vk],
            )
            .unwrap();
        let resp_duration = start_resp.elapsed();

        let L = com_5.comms_s.len();
        let start_recon = Instant::now();
        let recon_com_5 = AttributeToken::reconstruct_commitment(
            L,
            &com_5,
            &resp_5,
            &c_5,
            vec![HashSet::<usize>::new(); 5],
            &l_0_issuer_vk,
            &params1,
            &params2,
        )
        .unwrap();
        let recon_duration = start_recon.elapsed();

        let recon_c_5 = AttributeToken::gen_challenge(&recon_com_5, &l_0_issuer_vk, vec![]);
        assert_eq!(c_5, recon_c_5);
        println!("For delegation chain of length {}, commitment takes {:?}, response takes {:?}, commitment reconstitution takes {:?}. Total time taken by commitment and response is {:?}", L,
                 com_duration, resp_duration, recon_duration, com_duration + resp_duration);

        let attributes_6: G2Vector = (0..max_attributes - 1)
            .map(|_| G2::random())
            .collect::<Vec<G2>>()
            .into();
        let cred_link_6 = l_5_issuer
            .delegate(
                attributes_6.clone(),
                l_6_issuer_vk.clone(),
                &l_5_issuer_sk,
                &params2,
            )
            .unwrap();
        let mut chain_6 = chain_5.clone();
        chain_6.extend_with_even(cred_link_6).unwrap();

        let mut at_6 = AttributeToken::new(&chain_6, &params1, &params2);

        let start_com = Instant::now();
        let com_6 = at_6.commitment(vec![HashSet::<usize>::new(); 6]).unwrap();
        let com_duration = start_com.elapsed();

        assert!(com_6.odd_level_revealed_attributes[0].is_empty());
        assert!(com_6.odd_level_revealed_attributes[1].is_empty());
        assert!(com_6.odd_level_revealed_attributes[2].is_empty());
        assert!(com_6.even_level_revealed_attributes[0].is_empty());
        assert!(com_6.even_level_revealed_attributes[1].is_empty());
        assert!(com_6.even_level_revealed_attributes[2].is_empty());

        let c_6 = AttributeToken::gen_challenge(&com_6, &l_0_issuer_vk, vec![]);

        let start_resp = Instant::now();
        let resp_6 = at_6
            .response(
                &com_6,
                &l_6_issuer_sk,
                &c_6,
                vec![&l_2_issuer_vk, &l_4_issuer_vk, &l_6_issuer_vk],
                vec![&l_1_issuer_vk, &l_3_issuer_vk, &l_5_issuer_vk],
            )
            .unwrap();
        let resp_duration = start_resp.elapsed();

        let L = com_6.comms_s.len();
        let start_recon = Instant::now();
        let recon_com_6 = AttributeToken::reconstruct_commitment(
            L,
            &com_6,
            &resp_6,
            &c_6,
            vec![HashSet::<usize>::new(); 6],
            &l_0_issuer_vk,
            &params1,
            &params2,
        )
        .unwrap();
        let recon_duration = start_recon.elapsed();

        let recon_c_6 = AttributeToken::gen_challenge(&recon_com_6, &l_0_issuer_vk, vec![]);
        assert_eq!(c_6, recon_c_6);
        println!("For delegation chain of length {}, commitment takes {:?}, response takes {:?}, commitment reconstitution takes {:?}. Total time taken by commitment and response is {:?}", L,
                 com_duration, resp_duration, recon_duration, com_duration + resp_duration);
    }

    #[test]
    fn test_attribute_token_with_revealed_attributes() {
        let max_attributes = 6;
        let label = "test".as_bytes();

        println!(
            "Each credential will have {} attributes",
            max_attributes - 1
        );

        let params1 = GrothS1::setup(max_attributes, label);
        let params2 = GrothS2::setup(max_attributes, label);

        let l_0_issuer = EvenLevelIssuer::new(0).unwrap();
        let l_1_issuer = OddLevelIssuer::new(1).unwrap();
        let l_2_issuer = EvenLevelIssuer::new(2).unwrap();
        let l_3_issuer = OddLevelIssuer::new(3).unwrap();

        let (l_0_issuer_sk, l_0_issuer_vk) = EvenLevelIssuer::keygen(&params1);
        let (l_1_issuer_sk, l_1_issuer_vk) = OddLevelIssuer::keygen(&params2);
        let (l_2_issuer_sk, l_2_issuer_vk) = EvenLevelIssuer::keygen(&params1);
        let (l_3_issuer_sk, l_3_issuer_vk) = OddLevelIssuer::keygen(&params2);
        let (l_4_issuer_sk, l_4_issuer_vk) = EvenLevelIssuer::keygen(&params1);

        let attributes_1: G1Vector = (0..max_attributes - 1)
            .map(|_| G1::random())
            .collect::<Vec<G1>>()
            .into();
        let cred_link_1 = l_0_issuer
            .delegate(
                attributes_1.clone(),
                l_1_issuer_vk.clone(),
                &l_0_issuer_sk,
                &params1,
            )
            .unwrap();
        let mut chain_1 = CredChain::new();
        chain_1.extend_with_odd(cred_link_1).unwrap();

        let mut at_1 = AttributeToken::new(&chain_1, &params1, &params2);

        let mut revealed_attr_indices = HashSet::<usize>::new();
        revealed_attr_indices.insert(1);
        revealed_attr_indices.insert(3);

        let start_com = Instant::now();
        let com_1 = at_1
            .commitment(vec![revealed_attr_indices.clone()])
            .unwrap();
        let com_duration = start_com.elapsed();

        assert_eq!(com_1.odd_level_revealed_attributes[0][&1], attributes_1[1]);
        assert_eq!(com_1.odd_level_revealed_attributes[0][&3], attributes_1[3]);

        let c_1 = AttributeToken::gen_challenge(&com_1, &l_0_issuer_vk, vec![]);

        let start_resp = Instant::now();
        let resp_1 = at_1
            .response(&com_1, &l_1_issuer_sk, &c_1, vec![], vec![&l_1_issuer_vk])
            .unwrap();
        let resp_duration = start_resp.elapsed();

        let L = com_1.comms_s.len();
        let start_recon = Instant::now();
        let recon_com_1 = AttributeToken::reconstruct_commitment(
            L,
            &com_1,
            &resp_1,
            &c_1,
            vec![revealed_attr_indices.clone()],
            &l_0_issuer_vk,
            &params1,
            &params2,
        )
        .unwrap();
        let recon_duration = start_recon.elapsed();

        let recon_c_1 = AttributeToken::gen_challenge(&recon_com_1, &l_0_issuer_vk, vec![]);
        assert_eq!(c_1, recon_c_1);
        println!("For delegation chain of length {}, commitment takes {:?}, response takes {:?}, commitment reconstitution takes {:?}. Total time taken by commitment and response is {:?}", L,
                 com_duration, resp_duration, recon_duration, com_duration + resp_duration);

        let attributes_2: G2Vector = (0..max_attributes - 1)
            .map(|_| G2::random())
            .collect::<Vec<G2>>()
            .into();
        let cred_link_2 = l_1_issuer
            .delegate(
                attributes_2.clone(),
                l_2_issuer_vk.clone(),
                &l_1_issuer_sk,
                &params2,
            )
            .unwrap();
        let mut chain_2 = chain_1.clone();
        chain_2.extend_with_even(cred_link_2).unwrap();

        let mut at_2 = AttributeToken::new(&chain_2, &params1, &params2);

        let mut revealed_attr_indices_1 = HashSet::<usize>::new();
        revealed_attr_indices_1.insert(1);
        revealed_attr_indices_1.insert(3);

        let mut revealed_attr_indices_2 = HashSet::<usize>::new();
        revealed_attr_indices_2.insert(2);
        revealed_attr_indices_2.insert(3);
        revealed_attr_indices_2.insert(4);

        let start_com = Instant::now();
        let com_2 = at_2
            .commitment(vec![
                revealed_attr_indices_1.clone(),
                revealed_attr_indices_2.clone(),
            ])
            .unwrap();
        let com_duration = start_com.elapsed();

        assert_eq!(com_2.odd_level_revealed_attributes[0][&1], attributes_1[1]);
        assert_eq!(com_2.odd_level_revealed_attributes[0][&3], attributes_1[3]);
        assert_eq!(com_2.even_level_revealed_attributes[0][&2], attributes_2[2]);
        assert_eq!(com_2.even_level_revealed_attributes[0][&3], attributes_2[3]);
        assert_eq!(com_2.even_level_revealed_attributes[0][&4], attributes_2[4]);

        let c_2 = AttributeToken::gen_challenge(&com_2, &l_0_issuer_vk, vec![]);

        let start_resp = Instant::now();
        let resp_2 = at_2
            .response(
                &com_2,
                &l_2_issuer_sk,
                &c_2,
                vec![&l_2_issuer_vk],
                vec![&l_1_issuer_vk],
            )
            .unwrap();
        let resp_duration = start_resp.elapsed();

        let L = com_2.comms_s.len();
        let start_recon = Instant::now();
        let recon_com_2 = AttributeToken::reconstruct_commitment(
            L,
            &com_2,
            &resp_2,
            &c_2,
            vec![
                revealed_attr_indices_1.clone(),
                revealed_attr_indices_2.clone(),
            ],
            &l_0_issuer_vk,
            &params1,
            &params2,
        )
        .unwrap();
        let recon_duration = start_recon.elapsed();

        let recon_c_2 = AttributeToken::gen_challenge(&recon_com_2, &l_0_issuer_vk, vec![]);
        assert_eq!(c_2, recon_c_2);
        println!("For delegation chain of length {}, commitment takes {:?}, response takes {:?}, commitment reconstitution takes {:?}. Total time taken by commitment and response is {:?}", L,
                 com_duration, resp_duration, recon_duration, com_duration + resp_duration);

        let attributes_3: G1Vector = (0..max_attributes - 1)
            .map(|_| G1::random())
            .collect::<Vec<G1>>()
            .into();
        let cred_link_3 = l_2_issuer
            .delegate(
                attributes_3.clone(),
                l_3_issuer_vk.clone(),
                &l_2_issuer_sk,
                &params1,
            )
            .unwrap();
        let mut chain_3 = chain_2.clone();
        chain_3.extend_with_odd(cred_link_3).unwrap();

        let mut at_3 = AttributeToken::new(&chain_3, &params1, &params2);

        let mut revealed_attr_indices_1 = HashSet::<usize>::new();
        revealed_attr_indices_1.insert(1);
        revealed_attr_indices_1.insert(3);

        let mut revealed_attr_indices_2 = HashSet::<usize>::new();
        revealed_attr_indices_2.insert(3);
        revealed_attr_indices_2.insert(4);

        let mut revealed_attr_indices_3 = HashSet::<usize>::new();
        revealed_attr_indices_3.insert(1);

        let start_com = Instant::now();
        let com_3 = at_3
            .commitment(vec![
                revealed_attr_indices_1.clone(),
                revealed_attr_indices_2.clone(),
                revealed_attr_indices_3.clone(),
            ])
            .unwrap();
        let com_duration = start_com.elapsed();

        assert_eq!(com_3.odd_level_revealed_attributes[0][&1], attributes_1[1]);
        assert_eq!(com_3.odd_level_revealed_attributes[0][&3], attributes_1[3]);
        assert_eq!(com_3.even_level_revealed_attributes[0][&3], attributes_2[3]);
        assert_eq!(com_3.even_level_revealed_attributes[0][&4], attributes_2[4]);
        assert_eq!(com_3.odd_level_revealed_attributes[1][&1], attributes_3[1]);

        let c_3 = AttributeToken::gen_challenge(&com_3, &l_0_issuer_vk, vec![]);

        let start_resp = Instant::now();
        let resp_3 = at_3
            .response(
                &com_3,
                &l_3_issuer_sk,
                &c_3,
                vec![&l_2_issuer_vk],
                vec![&l_1_issuer_vk, &l_3_issuer_vk],
            )
            .unwrap();
        let resp_duration = start_resp.elapsed();

        let L = com_3.comms_s.len();
        let start_recon = Instant::now();
        let recon_com_3 = AttributeToken::reconstruct_commitment(
            L,
            &com_3,
            &resp_3,
            &c_3,
            vec![
                revealed_attr_indices_1.clone(),
                revealed_attr_indices_2.clone(),
                revealed_attr_indices_3.clone(),
            ],
            &l_0_issuer_vk,
            &params1,
            &params2,
        )
        .unwrap();
        let recon_duration = start_recon.elapsed();
        let recon_c_3 = AttributeToken::gen_challenge(&recon_com_3, &l_0_issuer_vk, vec![]);
        assert_eq!(c_3, recon_c_3);

        println!("For delegation chain of length {}, commitment takes {:?}, response takes {:?}, commitment reconstitution takes {:?}. Total time taken by commitment and response is {:?}", L,
                 com_duration, resp_duration, recon_duration, com_duration + resp_duration);

        let attributes_4: G2Vector = (0..max_attributes - 1)
            .map(|_| G2::random())
            .collect::<Vec<G2>>()
            .into();
        let cred_link_4 = l_3_issuer
            .delegate(
                attributes_4.clone(),
                l_4_issuer_vk.clone(),
                &l_3_issuer_sk,
                &params2,
            )
            .unwrap();
        let mut chain_4 = chain_3.clone();
        chain_4.extend_with_even(cred_link_4).unwrap();

        let mut at_4 = AttributeToken::new(&chain_4, &params1, &params2);

        let mut revealed_attr_indices_1 = HashSet::<usize>::new();
        revealed_attr_indices_1.insert(3);
        revealed_attr_indices_1.insert(4);

        let mut revealed_attr_indices_2 = HashSet::<usize>::new();
        revealed_attr_indices_2.insert(1);
        revealed_attr_indices_2.insert(3);

        let mut revealed_attr_indices_3 = HashSet::<usize>::new();
        revealed_attr_indices_3.insert(2);

        let mut revealed_attr_indices_4 = HashSet::<usize>::new();
        revealed_attr_indices_4.insert(1);
        revealed_attr_indices_4.insert(4);

        let start_com = Instant::now();
        let com_4 = at_4
            .commitment(vec![
                revealed_attr_indices_1.clone(),
                revealed_attr_indices_2.clone(),
                revealed_attr_indices_3.clone(),
                revealed_attr_indices_4.clone(),
            ])
            .unwrap();
        let com_duration = start_com.elapsed();

        assert_eq!(com_4.odd_level_revealed_attributes[0][&3], attributes_1[3]);
        assert_eq!(com_4.odd_level_revealed_attributes[0][&4], attributes_1[4]);
        assert_eq!(com_4.even_level_revealed_attributes[0][&1], attributes_2[1]);
        assert_eq!(com_4.even_level_revealed_attributes[0][&3], attributes_2[3]);
        assert_eq!(com_4.odd_level_revealed_attributes[1][&2], attributes_3[2]);
        assert_eq!(com_4.even_level_revealed_attributes[1][&1], attributes_4[1]);
        assert_eq!(com_4.even_level_revealed_attributes[1][&4], attributes_4[4]);

        let c_4 = AttributeToken::gen_challenge(&com_4, &l_0_issuer_vk, vec![]);

        let start_resp = Instant::now();
        let resp_4 = at_4
            .response(
                &com_4,
                &l_4_issuer_sk,
                &c_4,
                vec![&l_2_issuer_vk, &l_4_issuer_vk],
                vec![&l_1_issuer_vk, &l_3_issuer_vk],
            )
            .unwrap();
        let resp_duration = start_resp.elapsed();

        let L = com_4.comms_s.len();
        let start_recon = Instant::now();
        let recon_com_4 = AttributeToken::reconstruct_commitment(
            L,
            &com_4,
            &resp_4,
            &c_4,
            vec![
                revealed_attr_indices_1.clone(),
                revealed_attr_indices_2.clone(),
                revealed_attr_indices_3.clone(),
                revealed_attr_indices_4.clone(),
            ],
            &l_0_issuer_vk,
            &params1,
            &params2,
        )
        .unwrap();
        let recon_duration = start_recon.elapsed();

        let recon_c_4 = AttributeToken::gen_challenge(&recon_com_4, &l_0_issuer_vk, vec![]);
        assert_eq!(c_4, recon_c_4);
        println!("For delegation chain of length {}, commitment takes {:?}, response takes {:?}, commitment reconstitution takes {:?}. Total time taken by commitment and response is {:?}", L,
                 com_duration, resp_duration, recon_duration, com_duration + resp_duration);
    }

    #[test]
    fn test_attribute_token_with_precomputation() {
        let max_attributes = 6;
        let chain_size = 10;
        let label = "test".as_bytes();

        println!(
            "Each credential will have {} attributes",
            max_attributes - 1
        );

        let params1 = GrothS1::setup(max_attributes, label);
        let params2 = GrothS2::setup(max_attributes, label);

        let precomputed_setup_params = PrecompOnSetupParams::new(&params1, &params2);

        let l_0_issuer = EvenLevelIssuer::new(0).unwrap();
        let mut odd_level_issuers = vec![];
        let mut even_level_issuers = vec![];
        for i in 1..=chain_size {
            if i % 2 == 1 {
                odd_level_issuers.push(OddLevelIssuer::new(i).unwrap());
            } else {
                even_level_issuers.push(EvenLevelIssuer::new(i).unwrap());
            }
        }

        let (l_0_issuer_sk, l_0_issuer_vk) = EvenLevelIssuer::keygen(&params1);
        let mut odd_level_issuer_keys = vec![];
        let mut even_level_issuer_keys = vec![];
        for i in 1..=chain_size {
            if i % 2 == 1 {
                odd_level_issuer_keys.push(OddLevelIssuer::keygen(&params2));
            } else {
                even_level_issuer_keys.push(EvenLevelIssuer::keygen(&params1));
            }
        }

        let precomp_for_commit_recons =
            PrecompForCommitmentReconstitution::new(&l_0_issuer_vk, &params1, &params2);

        let mut even_level_vks = vec![];
        let mut odd_level_vks = vec![];
        let mut odd_level_attributes = vec![];
        let mut even_level_attributes = vec![];
        let mut chains = Vec::<CredChain>::new();
        for i in 1..=chain_size {
            let chain = if i % 2 == 1 {
                odd_level_vks.push(&odd_level_issuer_keys[i / 2].1);
                let attributes: G1Vector = (0..max_attributes - 1)
                    .map(|_| G1::random())
                    .collect::<Vec<G1>>()
                    .into();
                let chain = if i == 1 {
                    let cred_link = l_0_issuer
                        .delegate(
                            attributes.clone(),
                            odd_level_issuer_keys[0].1.clone(),
                            &l_0_issuer_sk,
                            &params1,
                        )
                        .unwrap();
                    let mut chain = CredChain::new();
                    chain.extend_with_odd(cred_link).unwrap();
                    chain
                } else {
                    let cred_link = even_level_issuers[(i / 2) - 1]
                        .delegate(
                            attributes.clone(),
                            odd_level_issuer_keys[i / 2].1.clone(),
                            &even_level_issuer_keys[(i / 2) - 1].0,
                            &params1,
                        )
                        .unwrap();
                    let mut chain = chains[i - 2].clone();
                    chain.extend_with_odd(cred_link).unwrap();
                    chain
                };
                odd_level_attributes.push(attributes);
                chain
            } else {
                even_level_vks.push(&even_level_issuer_keys[(i / 2) - 1].1);
                let attributes: G2Vector = (0..max_attributes - 1)
                    .map(|_| G2::random())
                    .collect::<Vec<G2>>()
                    .into();
                let cred_link = odd_level_issuers[(i / 2) - 1]
                    .delegate(
                        attributes.clone(),
                        even_level_issuer_keys[(i / 2) - 1].1.clone(),
                        &odd_level_issuer_keys[(i / 2) - 1].0,
                        &params2,
                    )
                    .unwrap();
                let mut chain = chains[i - 2].clone();
                chain.extend_with_even(cred_link).unwrap();
                even_level_attributes.push(attributes);
                chain
            };

            let precomp_sig_vals = PrecompOnCredChain::new(&chain, &params1, &params2).unwrap();
            chains.push(chain);

            let mut at = AttributeToken::new(&chains[i - 1], &params1, &params2);

            // To be used with precompute checks
            let mut at_1 = at.clone();
            let mut at_2 = at.clone();

            let start = Instant::now();
            let com = at.commitment(vec![HashSet::<usize>::new(); i]).unwrap();
            let com_duration = start.elapsed();

            let start = Instant::now();
            let com_precomp_setup = at_1
                .commitment_with_precomputation_on_setup_params(
                    vec![HashSet::<usize>::new(); i],
                    &precomputed_setup_params,
                )
                .unwrap();
            let com_precomp_setup_duration = start.elapsed();

            let start = Instant::now();
            let com_precomp = at_2
                .commitment_with_precomputation(
                    vec![HashSet::<usize>::new(); i],
                    &precomputed_setup_params,
                    &precomp_sig_vals,
                )
                .unwrap();
            let com_precomp_duration = start.elapsed();

            let c = AttributeToken::gen_challenge(&com, &l_0_issuer_vk, vec![]);
            let c_precomp_setup =
                AttributeToken::gen_challenge(&com_precomp_setup, &l_0_issuer_vk, vec![]);
            let c_precomp = AttributeToken::gen_challenge(&com_precomp, &l_0_issuer_vk, vec![]);

            let sk = if i % 2 == 1 {
                &odd_level_issuer_keys[i / 2].0
            } else {
                &even_level_issuer_keys[(i / 2) - 1].0
            };
            let start = Instant::now();
            let resp = at
                .response(&com, sk, &c, even_level_vks.clone(), odd_level_vks.clone())
                .unwrap();
            let resp_duration = start.elapsed();

            let resp_precomp_setup = at_1
                .response(
                    &com_precomp_setup,
                    sk,
                    &c_precomp_setup,
                    even_level_vks.clone(),
                    odd_level_vks.clone(),
                )
                .unwrap();
            let resp_precomp = at_2
                .response(
                    &com_precomp,
                    sk,
                    &c_precomp,
                    even_level_vks.clone(),
                    odd_level_vks.clone(),
                )
                .unwrap();

            let L = com.comms_s.len();

            let start = Instant::now();
            let recon_com = AttributeToken::reconstruct_commitment(
                L,
                &com,
                &resp,
                &c,
                vec![HashSet::<usize>::new(); i],
                &l_0_issuer_vk,
                &params1,
                &params2,
            )
            .unwrap();
            let recon_duration = start.elapsed();

            let recon_c = AttributeToken::gen_challenge(&recon_com, &l_0_issuer_vk, vec![]);
            assert_eq!(c, recon_c);

            let start = Instant::now();
            let recon_precomp_setup_com =
                AttributeToken::reconstruct_commitment_with_precomputed_vals(
                    L,
                    &com_precomp_setup,
                    &resp_precomp_setup,
                    &c_precomp_setup,
                    vec![HashSet::<usize>::new(); i],
                    &params1,
                    &params2,
                    &precomp_for_commit_recons,
                )
                .unwrap();
            let recon_precomp_duration = start.elapsed();

            let recon_c_precomp_setup_com =
                AttributeToken::gen_challenge(&recon_precomp_setup_com, &l_0_issuer_vk, vec![]);
            assert_eq!(c_precomp_setup, recon_c_precomp_setup_com);

            let recon_precomp_com = AttributeToken::reconstruct_commitment_with_precomputed_vals(
                L,
                &com_precomp,
                &resp_precomp,
                &c_precomp,
                vec![HashSet::<usize>::new(); i],
                &params1,
                &params2,
                &precomp_for_commit_recons,
            )
            .unwrap();

            let recon_c_precomp_com =
                AttributeToken::gen_challenge(&recon_precomp_com, &l_0_issuer_vk, vec![]);
            assert_eq!(c_precomp, recon_c_precomp_com);

            println!("For delegation chain of length {}", L);
            println!("Commitment takes {:?}, response takes {:?}, commitment reconstitution takes {:?}. Total time taken by commitment and response is {:?}",
                     com_duration, resp_duration, recon_duration, com_duration + resp_duration);
            println!(
                "Commitment with precomputation on setup params takes {:?}",
                com_precomp_setup_duration
            );
            println!(
                "Commitment with precomputation on setup params and signature takes {:?}",
                com_precomp_duration
            );
            println!("Commitment reconstitution with precomputation on setup params and root issuer key takes {:?}", recon_precomp_duration);
        }
    }

    #[test]
    fn test_attribute_token_validations() {
        let max_attributes = 3;
        let label = "test".as_bytes();

        println!(
            "Each credential will have {} attributes",
            max_attributes - 1
        );

        let params1 = GrothS1::setup(max_attributes, label);
        let params2 = GrothS2::setup(max_attributes, label);

        let l_0_issuer = EvenLevelIssuer::new(0).unwrap();
        let l_1_issuer = OddLevelIssuer::new(1).unwrap();

        let (l_0_issuer_sk, l_0_issuer_vk) = EvenLevelIssuer::keygen(&params1);
        let (l_1_issuer_sk, l_1_issuer_vk) = OddLevelIssuer::keygen(&params2);
        let (_, l_2_issuer_vk) = EvenLevelIssuer::keygen(&params1);

        let attributes_1: G1Vector = (0..max_attributes - 1)
            .map(|_| G1::random())
            .collect::<Vec<G1>>()
            .into();
        let cred_link_1 = l_0_issuer
            .delegate(
                attributes_1.clone(),
                l_1_issuer_vk.clone(),
                &l_0_issuer_sk,
                &params1,
            )
            .unwrap();

        assert!(cred_link_1
            .verify(&l_1_issuer_vk, &l_0_issuer_vk, &params1)
            .unwrap());

        let mut chain_1 = CredChain::new();
        chain_1.extend_with_odd(cred_link_1).unwrap();

        let mut at_1 = AttributeToken::new(&chain_1, &params1, &params2);

        // Supplying more or less collections of revealed attributes.
        assert!(at_1.commitment(vec![]).is_err());
        assert!(at_1.commitment(vec![HashSet::<usize>::new(); 2]).is_err());

        // Supplying same number of collections of revealed attributes as the chain size
        let com_1 = at_1.commitment(vec![HashSet::<usize>::new(); 1]).unwrap();

        let c_1 = AttributeToken::gen_challenge(&com_1, &l_0_issuer_vk, vec![]);

        let mut morphed_commitment = com_1.clone();
        // Adding an element of comms_s to increase its size
        morphed_commitment
            .comms_s
            .push(morphed_commitment.comms_s[0].clone());
        assert!(at_1
            .response(
                &morphed_commitment,
                &l_1_issuer_sk,
                &c_1,
                vec![],
                vec![&l_1_issuer_vk]
            )
            .is_err());
        // Remove the added element
        morphed_commitment.comms_s.pop().unwrap();

        // Adding an element of comms_t to increase its size
        morphed_commitment.comms_t.push(vec![]);
        assert!(at_1
            .response(
                &morphed_commitment,
                &l_1_issuer_sk,
                &c_1,
                vec![],
                vec![&l_1_issuer_vk]
            )
            .is_err());
        // Remove the added element
        morphed_commitment.comms_t.pop().unwrap();

        // Decrease size of comms_s
        morphed_commitment.comms_s.pop().unwrap();
        assert!(at_1
            .response(
                &morphed_commitment,
                &l_1_issuer_sk,
                &c_1,
                vec![],
                vec![&l_1_issuer_vk]
            )
            .is_err());

        // Decrease size of comms_t
        morphed_commitment.comms_t.pop().unwrap();
        assert!(at_1
            .response(
                &morphed_commitment,
                &l_1_issuer_sk,
                &c_1,
                vec![],
                vec![&l_1_issuer_vk]
            )
            .is_err());

        let _resp_1 = at_1
            .response(&com_1, &l_1_issuer_sk, &c_1, vec![], vec![&l_1_issuer_vk])
            .unwrap();

        let attributes_2: G2Vector = (0..max_attributes - 1)
            .map(|_| G2::random())
            .collect::<Vec<G2>>()
            .into();
        let cred_link_2 = l_1_issuer
            .delegate(
                attributes_2.clone(),
                l_2_issuer_vk.clone(),
                &l_1_issuer_sk,
                &params2,
            )
            .unwrap();
        assert!(cred_link_2
            .verify(&l_2_issuer_vk, &l_1_issuer_vk, &params2)
            .unwrap());

        let mut chain_2 = chain_1.clone();
        chain_2.extend_with_even(cred_link_2).unwrap();
    }
}
