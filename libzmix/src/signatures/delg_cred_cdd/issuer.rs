use super::errors::{DelgCredCDDErrorKind, DelgCredCDDResult};
use super::groth_sig::{
    Groth1SetupParams, Groth1Sig, Groth1Verkey, Groth2SetupParams, Groth2Sig, Groth2Verkey,
    GrothS1, GrothS2, GrothSigkey,
};
use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::GroupElementVector;
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use amcl_wrapper::group_elem_g2::{G2Vector, G2};

pub type Sigkey = GrothSigkey;
pub type EvenLevelVerkey = Groth1Verkey;
pub type OddLevelVerkey = Groth2Verkey;

macro_rules! impl_CredLink {
    ( $CredLink:ident, $GrothSetupParams:ident, $GrothSig:ident, $delegatee_vk:ident, $delegator_vk:ident, $GVector:ident ) => {
        // (attributes, signature). The signature is over the attributes and the public key combined
        // by appending public key to the attribute vector.
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct $CredLink {
            pub level: usize,
            pub attributes: $GVector,
            pub signature: $GrothSig,
        }

        impl $CredLink {
            pub fn attribute_count(&self) -> usize {
                self.attributes.len()
            }

            pub fn has_verkey(&self, vk: &$delegatee_vk) -> bool {
                self.attributes[self.attributes.len() - 1] == vk.0
            }

            /// Check that link correct number of attributes, has the delegatee's verkey and has
            /// valid signature from delegator
            pub fn verify(
                &self,
                delegatee_vk: &$delegatee_vk,
                delegator_vk: &$delegator_vk,
                setup_params: &$GrothSetupParams,
            ) -> DelgCredCDDResult<bool> {
                self.validate(delegatee_vk, setup_params)?;
                self.signature
                    .verify_batch(self.attributes.as_slice(), delegator_vk, setup_params)
            }

            /// Check that link correct number of attributes and has the delegatee's verkey
            pub fn validate(
                &self,
                delegatee_vk: &$delegatee_vk,
                setup_params: &$GrothSetupParams,
            ) -> DelgCredCDDResult<()> {
                if self.attributes.len() > setup_params.y.len() {
                    return Err(DelgCredCDDErrorKind::MoreAttributesThanExpected {
                        expected: setup_params.y.len(),
                        given: self.attributes.len(),
                    }
                    .into());
                }
                if !self.has_verkey(delegatee_vk) {
                    return Err(DelgCredCDDErrorKind::VerkeyNotFoundInDelegationLink {}.into());
                }
                Ok(())
            }
        }
    };
}

macro_rules! impl_Issuer {
    ( $Issuer:ident, $GrothSetupParams:ident, $GrothS:ident, $GrothSig:ident, $CredLink:ident, $delegatee_vk:ident, $delegator_vk:ident, $GVector:ident, $opr:tt, $ExpectedLevelError:ident ) => {
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct $Issuer {
            pub level: usize,
        }

        impl $Issuer {
            pub fn new(level: usize) -> DelgCredCDDResult<Self> {
                if level % 2 $opr 0 {
                    return Err(DelgCredCDDErrorKind::$ExpectedLevelError { given: level }.into());
                }
                Ok(Self { level })
            }

            pub fn keygen(setup_params: &$GrothSetupParams) -> (Sigkey, $delegator_vk) {
                $GrothS::keygen(setup_params)
            }

            /// Issuer creates a Groth signature.
            pub fn delegate(
                &self,
                mut delegatee_attributes: $GVector,
                delegatee_vk: $delegatee_vk,
                sk: &Sigkey,
                setup_params: &$GrothSetupParams,
            ) -> DelgCredCDDResult<$CredLink> {
                if delegatee_attributes.len() >= setup_params.y.len() {
                    return Err(DelgCredCDDErrorKind::MoreAttributesThanExpected {
                        expected: setup_params.y.len(),
                        given: delegatee_attributes.len(),
                    }
                    .into());
                }
                delegatee_attributes.push(delegatee_vk.0);
                let signature = $GrothSig::new(delegatee_attributes.as_slice(), sk, setup_params)?;
                Ok($CredLink {
                    level: &self.level + 1,
                    attributes: delegatee_attributes,
                    signature,
                })
            }
        }
    }
}

impl_CredLink!(
    CredLinkOdd,
    Groth1SetupParams,
    Groth1Sig,
    OddLevelVerkey,
    EvenLevelVerkey,
    G1Vector
);

impl_CredLink!(
    CredLinkEven,
    Groth2SetupParams,
    Groth2Sig,
    EvenLevelVerkey,
    OddLevelVerkey,
    G2Vector
);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredChain {
    pub odd_links: Vec<CredLinkOdd>,
    pub even_links: Vec<CredLinkEven>,
}

impl_Issuer!(EvenLevelIssuer, Groth1SetupParams, GrothS1, Groth1Sig, CredLinkOdd, OddLevelVerkey, EvenLevelVerkey, G1Vector, !=, ExpectedEvenLevel);

impl_Issuer!(OddLevelIssuer, Groth2SetupParams, GrothS2, Groth2Sig, CredLinkEven, EvenLevelVerkey, OddLevelVerkey, G2Vector, ==, ExpectedOddLevel);

pub struct RootIssuer {}

pub type RootIssuerVerkey = EvenLevelVerkey;

impl CredChain {
    pub fn new() -> Self {
        Self {
            odd_links: vec![],
            even_links: vec![],
        }
    }

    pub fn odd_size(&self) -> usize {
        self.odd_links.len()
    }

    pub fn even_size(&self) -> usize {
        self.even_links.len()
    }

    pub fn size(&self) -> usize {
        self.odd_size() + self.even_size()
    }

    pub fn get_odd_link(&self, idx: usize) -> DelgCredCDDResult<&CredLinkOdd> {
        if self.odd_size() <= idx {
            return Err(DelgCredCDDErrorKind::NoOddLinkInChainAtGivenIndex {
                given_index: idx,
                size: self.odd_size(),
            }
            .into());
        }
        Ok(&self.odd_links[idx])
    }

    pub fn get_even_link(&self, idx: usize) -> DelgCredCDDResult<&CredLinkEven> {
        if self.even_size() <= idx {
            return Err(DelgCredCDDErrorKind::NoEvenLinkInChainAtGivenIndex {
                given_index: idx,
                size: self.even_size(),
            }
            .into());
        }
        Ok(&self.even_links[idx])
    }

    pub fn extend_with_odd(&mut self, link: CredLinkOdd) -> DelgCredCDDResult<()> {
        if link.level % 2 == 0 {
            return Err(DelgCredCDDErrorKind::ExpectedOddLevel { given: link.level }.into());
        }
        if self.odd_size() == 0 && link.level != 1 {
            return Err(DelgCredCDDErrorKind::UnexpectedLevel {
                expected: 1,
                given: link.level,
            }
            .into());
        } else if self.odd_size() != 0
            && ((link.level - self.odd_links[self.odd_size() - 1].level) != 2)
        {
            return Err(DelgCredCDDErrorKind::UnexpectedLevel {
                expected: self.odd_links[self.odd_size() - 1].level + 2,
                given: link.level,
            }
            .into());
        }
        self.odd_links.push(link);
        Ok(())
    }

    pub fn extend_with_even(&mut self, link: CredLinkEven) -> DelgCredCDDResult<()> {
        if link.level % 2 != 0 {
            return Err(DelgCredCDDErrorKind::ExpectedEvenLevel { given: link.level }.into());
        }
        if self.even_size() == 0 && link.level != 2 {
            return Err(DelgCredCDDErrorKind::UnexpectedLevel {
                expected: 2,
                given: link.level,
            }
            .into());
        } else if self.even_size() != 0
            && ((link.level - self.even_links[self.even_size() - 1].level) != 2)
        {
            return Err(DelgCredCDDErrorKind::UnexpectedLevel {
                expected: self.even_links[self.even_size() - 1].level + 2,
                given: link.level,
            }
            .into());
        }
        self.even_links.push(link);
        Ok(())
    }

    pub fn verify_last_odd_delegation(
        &self,
        delegatee_vk: &OddLevelVerkey,
        delegator_vk: &EvenLevelVerkey,
        setup_params: &Groth1SetupParams,
    ) -> DelgCredCDDResult<bool> {
        if self.odd_size() == 0 {
            return Err(DelgCredCDDErrorKind::NoOddLinksInChain {}.into());
        }
        let link = &self.odd_links[self.odd_size() - 1];
        link.verify(delegatee_vk, delegator_vk, setup_params)
    }

    pub fn verify_last_even_delegation(
        &self,
        delegatee_vk: &EvenLevelVerkey,
        delegator_vk: &OddLevelVerkey,
        setup_params: &Groth2SetupParams,
    ) -> DelgCredCDDResult<bool> {
        if self.even_size() == 0 {
            return Err(DelgCredCDDErrorKind::NoEvenLinksInChain {}.into());
        }
        let link = &self.even_links[self.even_size() - 1];
        link.verify(delegatee_vk, delegator_vk, setup_params)
    }

    /// Verifies several Groth signatures, one for each link in the chain.
    /// First verkey of even_level_vks is the root issuer's key. Each link is verified independently
    /// resulting in a multi-pairing check per link.
    pub fn verify_delegations(
        &self,
        even_level_vks: Vec<&EvenLevelVerkey>,
        odd_level_vks: Vec<&OddLevelVerkey>,
        setup_params_1: &Groth1SetupParams,
        setup_params_2: &Groth2SetupParams,
    ) -> DelgCredCDDResult<bool> {
        self.validate(&even_level_vks, &odd_level_vks)?;

        for i in 1..=self.size() {
            let r = if i % 2 == 1 {
                let idx = i / 2;
                let link = &self.odd_links[idx];
                if link.level != i {
                    return Err(DelgCredCDDErrorKind::UnexpectedLevel {
                        expected: i,
                        given: link.level,
                    }
                    .into());
                }
                link.verify(odd_level_vks[idx], even_level_vks[idx], setup_params_1)?
            } else {
                let link = &self.even_links[(i / 2) - 1];
                if link.level != i {
                    return Err(DelgCredCDDErrorKind::UnexpectedLevel {
                        expected: i,
                        given: link.level,
                    }
                    .into());
                }
                link.verify(
                    even_level_vks[i / 2],
                    odd_level_vks[(i / 2) - 1],
                    setup_params_2,
                )?
            };
            if !r {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Used for the same task as `verify_delegations`. As an optimization, the several `link.verify`s
    /// called (once for verifying each link) in verify_delegations are batched together such that
    /// there is only 1 big multi-pairing rather than chain.size(). The technique used is same as used in
    /// `verify_batch`
    pub fn verify_delegations_batched(
        &self,
        even_level_vks: Vec<&EvenLevelVerkey>,
        odd_level_vks: Vec<&OddLevelVerkey>,
        setup_params_1: &Groth1SetupParams,
        setup_params_2: &Groth2SetupParams,
    ) -> DelgCredCDDResult<bool> {
        self.validate(&even_level_vks, &odd_level_vks)?;

        // Accumulates elements for multi-pairings.
        let mut pairing_elems: Vec<(G1, G2)> = vec![];

        // The random values whose powers are created for doing the batched pairing verification
        let r = FieldElement::random();

        // Calculate total number of attributes (including verkeys) for all links in the chain.
        let mut total_attrib_count = 0;
        for i in 1..=self.size() {
            if i % 2 == 1 {
                total_attrib_count += self.odd_links[i / 2].attribute_count() + 1;
            } else {
                total_attrib_count += self.even_links[(i / 2) - 1].attribute_count() + 1;
            }
        }
        // Vector that holds powers of the random value created above
        let r_vec = FieldElementVector::new_vandermonde_vector(&r, total_attrib_count);

        // Offset in the above vector so group elements are multiplied by the correct power of random value.
        let mut r_vec_offset = 0;
        for i in 1..=self.size() {
            if i % 2 == 1 {
                let idx = i / 2;
                let link = &self.odd_links[idx];
                if link.level != i {
                    return Err(DelgCredCDDErrorKind::UnexpectedLevel {
                        expected: i,
                        given: link.level,
                    }
                    .into());
                }
                // Validate the link
                link.validate(odd_level_vks[idx], setup_params_1)?;
                // Accumulate values for the multi-pairing
                Groth1Sig::prepare_for_pairing_checks(
                    &mut pairing_elems,
                    &r_vec,
                    r_vec_offset,
                    &link.signature,
                    link.attributes.as_slice(),
                    even_level_vks[idx],
                    setup_params_1,
                );
                r_vec_offset += link.attributes.len() + 1;
            } else {
                let link = &self.even_links[(i / 2) - 1];
                if link.level != i {
                    return Err(DelgCredCDDErrorKind::UnexpectedLevel {
                        expected: i,
                        given: link.level,
                    }
                    .into());
                }
                // Validate the link
                link.validate(even_level_vks[i / 2], setup_params_2)?;
                // Accumulate values for the multi-pairing
                Groth2Sig::prepare_for_pairing_checks(
                    &mut pairing_elems,
                    &r_vec,
                    r_vec_offset,
                    &link.signature,
                    link.attributes.as_slice(),
                    odd_level_vks[(i / 2) - 1],
                    setup_params_2,
                );
                r_vec_offset += link.attributes.len() + 1;
            }
        }
        let e = GT::ate_multi_pairing(
            pairing_elems
                .iter()
                .map(|p| (&p.0, &p.1))
                .collect::<Vec<_>>(),
        );
        Ok(e.is_one())
    }

    /// Returns a truncated version of the current chain. Does not modify the current chain but clones the links.
    pub fn get_truncated(&self, size: usize) -> DelgCredCDDResult<Self> {
        if size > self.size() {
            return Err(DelgCredCDDErrorKind::ChainIsShorterThanExpected {
                actual_size: self.size(),
                expected_size: size,
            }
            .into());
        }
        let mut new_chain = CredChain::new();
        for i in 1..=size {
            if (i % 2) == 1 {
                new_chain.odd_links.push(self.odd_links[i / 2].clone());
            } else {
                new_chain
                    .even_links
                    .push(self.even_links[(i / 2) - 1].clone());
            }
        }
        Ok(new_chain)
    }

    /// Check that the chain is non-empty and there are correct number of odd and even level verkeys.
    fn validate(
        &self,
        even_level_vks: &Vec<&EvenLevelVerkey>,
        odd_level_vks: &Vec<&OddLevelVerkey>,
    ) -> DelgCredCDDResult<()> {
        let size = self.size();
        if size == 0 {
            return Err(DelgCredCDDErrorKind::ChainEmpty {}.into());
        }
        if (even_level_vks.len() + odd_level_vks.len()) != (size + 1) {
            return Err(DelgCredCDDErrorKind::IncorrectNumberOfVerkeys {
                expected: size + 1,
                given: even_level_vks.len() + odd_level_vks.len(),
            }
            .into());
        }
        if even_level_vks.len() != ((size / 2) + 1) {
            return Err(DelgCredCDDErrorKind::IncorrectNumberOfEvenLevelVerkeys {
                expected: (size / 2) + 1,
                given: even_level_vks.len(),
            }
            .into());
        }
        if size % 2 == 1 {
            if odd_level_vks.len() != ((size / 2) + 1) {
                return Err(DelgCredCDDErrorKind::IncorrectNumberOfOddLevelVerkeys {
                    expected: (size / 2) + 1,
                    given: odd_level_vks.len(),
                }
                .into());
            }
        } else {
            if odd_level_vks.len() != (size / 2) {
                return Err(DelgCredCDDErrorKind::IncorrectNumberOfOddLevelVerkeys {
                    expected: size / 2,
                    given: odd_level_vks.len(),
                }
                .into());
            }
        }

        Ok(())
    }
}

impl RootIssuer {
    pub fn keygen(setup_params: &Groth1SetupParams) -> (Sigkey, RootIssuerVerkey) {
        GrothS1::keygen(setup_params)
    }

    pub fn delegate(
        delegatee_attributes: G1Vector,
        delegatee_vk: OddLevelVerkey,
        sk: &Sigkey,
        setup_params: &Groth1SetupParams,
    ) -> DelgCredCDDResult<CredLinkOdd> {
        let issuer = EvenLevelIssuer::new(0)?;
        issuer.delegate(delegatee_attributes, delegatee_vk, sk, setup_params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // For benchmarking
    use amcl_wrapper::group_elem::GroupElement;
    use amcl_wrapper::group_elem_g1::G1;
    use amcl_wrapper::group_elem_g2::G2;
    use std::time::Instant;

    /// XXX: Need test fixtures

    #[test]
    fn test_delegation_level_0_to_level_2() {
        let max_attributes = 5;
        let label = "test".as_bytes();
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
        assert_eq!(chain_1.odd_size(), 1);
        assert_eq!(chain_1.even_size(), 0);
        assert_eq!(chain_1.size(), 1);
        assert!(chain_1
            .verify_last_odd_delegation(&l_1_issuer_vk, &l_0_issuer_vk, &params1)
            .unwrap());

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
        assert_eq!(chain_2.even_size(), 1);
        assert_eq!(chain_2.odd_size(), 1);
        assert_eq!(chain_2.size(), 2);

        assert!(chain_2
            .verify_last_even_delegation(&l_2_issuer_vk, &l_1_issuer_vk, &params2)
            .unwrap());
    }

    #[test]
    fn test_root_issuer() {
        let max_attributes = 5;
        let label = "test".as_bytes();
        let params1 = GrothS1::setup(max_attributes, label);
        let params2 = GrothS2::setup(max_attributes, label);

        let l_1_issuer = OddLevelIssuer::new(1).unwrap();

        let (root_issuer_sk, root_issuer_vk) = RootIssuer::keygen(&params1);
        let (l_1_issuer_sk, l_1_issuer_vk) = OddLevelIssuer::keygen(&params2);
        let (_, l_2_issuer_vk) = EvenLevelIssuer::keygen(&params1);

        let attributes_1: G1Vector = (0..max_attributes - 1)
            .map(|_| G1::random())
            .collect::<Vec<G1>>()
            .into();
        let cred_link_1 = RootIssuer::delegate(
            attributes_1.clone(),
            l_1_issuer_vk.clone(),
            &root_issuer_sk,
            &params1,
        )
        .unwrap();

        assert!(cred_link_1
            .verify(&l_1_issuer_vk, &root_issuer_vk, &params1)
            .unwrap());

        let mut chain_1 = CredChain::new();
        chain_1.extend_with_odd(cred_link_1).unwrap();

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
    }

    #[test]
    fn test_delegation_chain_verification() {
        let max_attributes = 3;
        let label = "test".as_bytes();
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
        let (_, l_4_issuer_vk) = EvenLevelIssuer::keygen(&params1);

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

        let start = Instant::now();
        assert!(chain_1
            .verify_delegations(
                vec![&l_0_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        println!(
            "Verifying delegation chain of length {} takes {:?}",
            chain_1.size(),
            start.elapsed()
        );

        let start = Instant::now();
        assert!(chain_1
            .verify_delegations_batched(
                vec![&l_0_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        println!(
            "Verifying delegation chain of length {} using batched verification takes {:?}",
            chain_1.size(),
            start.elapsed()
        );

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

        let start = Instant::now();
        assert!(chain_2
            .verify_delegations(
                vec![&l_0_issuer_vk, &l_2_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        println!(
            "Verifying delegation chain of length {} takes {:?}",
            chain_2.size(),
            start.elapsed()
        );

        let start = Instant::now();
        assert!(chain_2
            .verify_delegations_batched(
                vec![&l_0_issuer_vk, &l_2_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        println!(
            "Verifying delegation chain of length {} using batched verification takes {:?}",
            chain_2.size(),
            start.elapsed()
        );

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
        assert!(cred_link_3
            .verify(&l_3_issuer_vk, &l_2_issuer_vk, &params1)
            .unwrap());
        let mut chain_3 = chain_2.clone();
        chain_3.extend_with_odd(cred_link_3).unwrap();

        let start = Instant::now();
        assert!(chain_3
            .verify_delegations(
                vec![&l_0_issuer_vk, &l_2_issuer_vk],
                vec![&l_1_issuer_vk, &l_3_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        println!(
            "Verifying delegation chain of length {} takes {:?}",
            chain_3.size(),
            start.elapsed()
        );

        let start = Instant::now();
        assert!(chain_3
            .verify_delegations_batched(
                vec![&l_0_issuer_vk, &l_2_issuer_vk],
                vec![&l_1_issuer_vk, &l_3_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        println!(
            "Verifying delegation chain of length {} using batched verification takes {:?}",
            chain_3.size(),
            start.elapsed()
        );

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
        assert!(cred_link_4
            .verify(&l_4_issuer_vk, &l_3_issuer_vk, &params2)
            .unwrap());
        let mut chain_4 = chain_3.clone();
        chain_4.extend_with_even(cred_link_4).unwrap();

        let start = Instant::now();
        assert!(chain_4
            .verify_delegations(
                vec![&l_0_issuer_vk, &l_2_issuer_vk, &l_4_issuer_vk],
                vec![&l_1_issuer_vk, &l_3_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        println!(
            "Verifying delegation chain of length {} takes {:?}",
            chain_4.size(),
            start.elapsed()
        );

        let start = Instant::now();
        assert!(chain_4
            .verify_delegations_batched(
                vec![&l_0_issuer_vk, &l_2_issuer_vk, &l_4_issuer_vk],
                vec![&l_1_issuer_vk, &l_3_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        println!(
            "Verifying delegation chain of length {} using batched verification takes {:?}",
            chain_4.size(),
            start.elapsed()
        );
    }

    #[test]
    fn test_truncated_delegation_chain() {
        let max_attributes = 3;
        let label = "test".as_bytes();
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
        let (_, l_4_issuer_vk) = EvenLevelIssuer::keygen(&params1);

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

        assert!(chain_1
            .verify_delegations(vec![&l_0_issuer_vk], vec![], &params1, &params2)
            .is_err());

        chain_1.extend_with_odd(cred_link_1).unwrap();

        assert!(chain_1
            .verify_delegations(
                vec![&l_0_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());

        assert!(chain_1
            .verify_delegations_batched(
                vec![&l_0_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());

        assert!(chain_1.get_truncated(2).is_err());

        let chain_1_1 = chain_1.get_truncated(1).unwrap();
        assert_eq!(chain_1_1.size(), 1);
        assert!(chain_1_1
            .verify_delegations(
                vec![&l_0_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        assert!(chain_1_1
            .verify_delegations_batched(
                vec![&l_0_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());

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

        assert!(chain_2
            .verify_delegations(
                vec![&l_0_issuer_vk, &l_2_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        assert!(chain_2
            .verify_delegations_batched(
                vec![&l_0_issuer_vk, &l_2_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());

        assert!(chain_2.get_truncated(3).is_err());

        let chain_2_1 = chain_2.get_truncated(1).unwrap();
        assert_eq!(chain_2_1.size(), 1);
        assert!(chain_2_1
            .verify_delegations(
                vec![&l_0_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        assert!(chain_2_1
            .verify_delegations_batched(
                vec![&l_0_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());

        let chain_2_2 = chain_2.get_truncated(2).unwrap();
        assert_eq!(chain_2_2.size(), 2);
        assert!(chain_2_2
            .verify_delegations(
                vec![&l_0_issuer_vk, &l_2_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        assert!(chain_2_2
            .verify_delegations_batched(
                vec![&l_0_issuer_vk, &l_2_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());

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

        assert!(chain_3
            .verify_delegations(
                vec![&l_0_issuer_vk, &l_2_issuer_vk],
                vec![&l_1_issuer_vk, &l_3_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        assert!(chain_3
            .verify_delegations_batched(
                vec![&l_0_issuer_vk, &l_2_issuer_vk],
                vec![&l_1_issuer_vk, &l_3_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());

        assert!(chain_3.get_truncated(4).is_err());

        let chain_3_1 = chain_3.get_truncated(1).unwrap();
        assert_eq!(chain_3_1.size(), 1);
        assert!(chain_3_1
            .verify_delegations(
                vec![&l_0_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        assert!(chain_3_1
            .verify_delegations_batched(
                vec![&l_0_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());

        let chain_3_2 = chain_3.get_truncated(2).unwrap();
        assert_eq!(chain_3_2.size(), 2);
        assert!(chain_3_2
            .verify_delegations(
                vec![&l_0_issuer_vk, &l_2_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        assert!(chain_3_2
            .verify_delegations_batched(
                vec![&l_0_issuer_vk, &l_2_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());

        let chain_3_3 = chain_3.get_truncated(3).unwrap();
        assert_eq!(chain_3_3.size(), 3);
        assert!(chain_3
            .verify_delegations(
                vec![&l_0_issuer_vk, &l_2_issuer_vk],
                vec![&l_1_issuer_vk, &l_3_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        assert!(chain_3
            .verify_delegations_batched(
                vec![&l_0_issuer_vk, &l_2_issuer_vk],
                vec![&l_1_issuer_vk, &l_3_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());

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

        assert!(chain_4
            .verify_delegations(
                vec![&l_0_issuer_vk, &l_2_issuer_vk, &l_4_issuer_vk],
                vec![&l_1_issuer_vk, &l_3_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        assert!(chain_4
            .verify_delegations_batched(
                vec![&l_0_issuer_vk, &l_2_issuer_vk, &l_4_issuer_vk],
                vec![&l_1_issuer_vk, &l_3_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());

        assert!(chain_4.get_truncated(5).is_err());

        let chain_4_1 = chain_4.get_truncated(1).unwrap();
        assert_eq!(chain_4_1.size(), 1);
        assert!(chain_4_1
            .verify_delegations(
                vec![&l_0_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        assert!(chain_4_1
            .verify_delegations_batched(
                vec![&l_0_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());

        let chain_4_2 = chain_4.get_truncated(2).unwrap();
        assert_eq!(chain_4_2.size(), 2);
        assert!(chain_4_2
            .verify_delegations(
                vec![&l_0_issuer_vk, &l_2_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        assert!(chain_4_2
            .verify_delegations_batched(
                vec![&l_0_issuer_vk, &l_2_issuer_vk],
                vec![&l_1_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());

        let chain_4_3 = chain_4.get_truncated(3).unwrap();
        assert_eq!(chain_4_3.size(), 3);
        assert!(chain_4_3
            .verify_delegations(
                vec![&l_0_issuer_vk, &l_2_issuer_vk],
                vec![&l_1_issuer_vk, &l_3_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        assert!(chain_4_3
            .verify_delegations_batched(
                vec![&l_0_issuer_vk, &l_2_issuer_vk],
                vec![&l_1_issuer_vk, &l_3_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());

        let chain_4_4 = chain_4.get_truncated(4).unwrap();
        assert_eq!(chain_4_4.size(), 4);
        assert!(chain_4_4
            .verify_delegations(
                vec![&l_0_issuer_vk, &l_2_issuer_vk, &l_4_issuer_vk],
                vec![&l_1_issuer_vk, &l_3_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
        assert!(chain_4_4
            .verify_delegations_batched(
                vec![&l_0_issuer_vk, &l_2_issuer_vk, &l_4_issuer_vk],
                vec![&l_1_issuer_vk, &l_3_issuer_vk],
                &params1,
                &params2
            )
            .unwrap());
    }

    #[test]
    fn test_delegation_chain_extension() {
        let max_attributes = 3;
        let label = "test".as_bytes();
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
        let (_, l_6_issuer_vk) = EvenLevelIssuer::keygen(&params1);

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
        assert!(cred_link_3
            .verify(&l_3_issuer_vk, &l_2_issuer_vk, &params1)
            .unwrap());

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
        assert!(cred_link_4
            .verify(&l_4_issuer_vk, &l_3_issuer_vk, &params2)
            .unwrap());

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

        let mut chain_1 = CredChain::new();

        // Make level of odd link even
        let mut morphed_link = cred_link_3.clone();
        morphed_link.level = 2;
        assert!(chain_1.extend_with_odd(morphed_link).is_err());

        // Try to extend chain of length 0 with odd link of level 3
        assert!(chain_1.extend_with_odd(cred_link_3.clone()).is_err());

        chain_1.extend_with_odd(cred_link_1).unwrap();

        let mut chain_2 = chain_1.clone();

        // Make level of even link odd
        let mut morphed_link = cred_link_2.clone();
        morphed_link.level = 1;
        assert!(chain_2.extend_with_even(morphed_link).is_err());

        // Try to extend chain with no even links with even link of level 4
        assert!(chain_2.extend_with_even(cred_link_4.clone()).is_err());

        chain_2.extend_with_even(cred_link_2).unwrap();

        let mut chain_3 = chain_2.clone();

        // Try to extend chain last odd link of level 1 with odd link of level 5
        assert!(chain_3.extend_with_odd(cred_link_5).is_err());

        chain_3.extend_with_odd(cred_link_3).unwrap();

        let mut chain_4 = chain_3.clone();

        // Try to extend chain last even link of level 2 with odd link of level 6
        assert!(chain_4.extend_with_even(cred_link_6).is_err());

        chain_4.extend_with_even(cred_link_4).unwrap();
    }
}
