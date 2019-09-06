use crate::errors::{DelgError, DelgResult};
use crate::groth_sig::{
    Groth1SetupParams, Groth1Sig, Groth1Sigkey, Groth1Verkey, Groth2SetupParams, Groth2Sig,
    Groth2Sigkey, Groth2Verkey, GrothS1, GrothS2,
};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::{G1LookupTable, G1Vector, G1};
use amcl_wrapper::group_elem_g2::{G2Vector, G2};

pub type EvenLevelSigkey = Groth1Sigkey;
pub type EvenLevelVerkey = Groth1Verkey;
pub type OddLevelSigkey = Groth2Sigkey;
pub type OddLevelVerkey = Groth2Verkey;

// (attributes, signature). The signature is over the attributes and the public key combined by appending public key to the attribute vector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredLinkOdd {
    pub level: usize,
    pub attributes: G1Vector,
    pub signature: Groth1Sig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredLinkEven {
    pub level: usize,
    pub attributes: G2Vector,
    pub signature: Groth2Sig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredChain {
    pub odd_links: Vec<CredLinkOdd>,
    pub even_links: Vec<CredLinkEven>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvenLevelIssuer {
    pub level: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OddLevelIssuer {
    pub level: usize,
}

impl CredLinkOdd {
    pub fn attribute_count(&self) -> usize {
        self.attributes.len()
    }

    pub fn has_verkey(&self, vk: &OddLevelVerkey) -> bool {
        self.attributes[self.attributes.len() - 1] == vk.0
    }

    pub fn verify(
        &self,
        delegatee_vk: &OddLevelVerkey,
        delegator_vk: &EvenLevelVerkey,
        setup_params: &Groth1SetupParams,
    ) -> DelgResult<bool> {
        if self.attributes.len() > setup_params.y.len() {
            return Err(DelgError::MoreAttributesThanExpected {
                expected: setup_params.y.len(),
                given: self.attributes.len(),
            });
        }
        if !self.has_verkey(delegatee_vk) {
            return Err(DelgError::VerkeyNotFoundInDelegationLink {});
        }
        /*link.signature
        .verify(link.messages.as_slice(), delegator_vk, setup_params)*/
        self.signature
            .verify_fast(self.attributes.as_slice(), delegator_vk, setup_params)
    }
}

impl CredLinkEven {
    pub fn attribute_count(&self) -> usize {
        self.attributes.len()
    }

    pub fn has_verkey(&self, vk: &EvenLevelVerkey) -> bool {
        self.attributes[self.attributes.len() - 1] == vk.0
    }

    pub fn verify(
        &self,
        delegatee_vk: &EvenLevelVerkey,
        delegator_vk: &OddLevelVerkey,
        setup_params: &Groth2SetupParams,
    ) -> DelgResult<bool> {
        if self.attributes.len() > setup_params.y.len() {
            return Err(DelgError::MoreAttributesThanExpected {
                expected: setup_params.y.len(),
                given: self.attributes.len(),
            });
        }
        if !self.has_verkey(delegatee_vk) {
            return Err(DelgError::VerkeyNotFoundInDelegationLink {});
        }
        /*link.signature
        .verify(link.messages.as_slice(), delegator_vk, setup_params)*/
        self.signature
            .verify_fast(self.attributes.as_slice(), delegator_vk, setup_params)
    }
}

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

    pub fn get_odd_link(&self, idx: usize) -> DelgResult<&CredLinkOdd> {
        if self.odd_size() <= idx {
            return Err(DelgError::NoOddLinkInChainAtGivenIndex {
                given_index: idx,
                size: self.odd_size(),
            });
        }
        Ok(&self.odd_links[idx])
    }

    pub fn get_even_link(&self, idx: usize) -> DelgResult<&CredLinkEven> {
        if self.even_size() <= idx {
            return Err(DelgError::NoEvenLinkInChainAtGivenIndex {
                given_index: idx,
                size: self.even_size(),
            });
        }
        Ok(&self.even_links[idx])
    }

    pub fn extend_with_odd(&mut self, link: CredLinkOdd) -> DelgResult<()> {
        if link.level % 2 == 0 {
            return Err(DelgError::ExpectedOddLevel { given: link.level });
        }
        if self.odd_size() == 0 && link.level != 1 {
            return Err(DelgError::UnexpectedLevel {
                expected: 1,
                given: link.level,
            });
        } else if self.odd_size() != 0
            && ((link.level - self.odd_links[self.odd_size() - 1].level) != 2)
        {
            return Err(DelgError::UnexpectedLevel {
                expected: self.odd_links[self.odd_size() - 1].level + 2,
                given: link.level,
            });
        }
        self.odd_links.push(link);
        Ok(())
    }

    pub fn extend_with_even(&mut self, link: CredLinkEven) -> DelgResult<()> {
        if link.level % 2 != 0 {
            return Err(DelgError::ExpectedEvenLevel { given: link.level });
        }
        if self.even_size() == 0 && link.level != 2 {
            return Err(DelgError::UnexpectedLevel {
                expected: 2,
                given: link.level,
            });
        } else if self.even_size() != 0
            && ((link.level - self.even_links[self.even_size() - 1].level) != 2)
        {
            return Err(DelgError::UnexpectedLevel {
                expected: self.even_links[self.even_size() - 1].level + 2,
                given: link.level,
            });
        }
        self.even_links.push(link);
        Ok(())
    }

    pub fn verify_last_odd_delegation(
        &self,
        delegatee_vk: &OddLevelVerkey,
        delegator_vk: &EvenLevelVerkey,
        setup_params: &Groth1SetupParams,
    ) -> DelgResult<bool> {
        if self.odd_size() == 0 {
            return Err(DelgError::NoOddLinksInChain {});
        }
        let link = &self.odd_links[self.odd_size() - 1];
        link.verify(delegatee_vk, delegator_vk, setup_params)
    }

    pub fn verify_last_even_delegation(
        &self,
        delegatee_vk: &EvenLevelVerkey,
        delegator_vk: &OddLevelVerkey,
        setup_params: &Groth2SetupParams,
    ) -> DelgResult<bool> {
        if self.even_size() == 0 {
            return Err(DelgError::NoEvenLinksInChain {});
        }
        let link = &self.even_links[self.even_size() - 1];
        link.verify(delegatee_vk, delegator_vk, setup_params)
    }

    // First verkey of even_level_vks is the root issuer's key
    pub fn verify_delegations(
        &self,
        even_level_vks: Vec<&EvenLevelVerkey>,
        odd_level_vks: Vec<&OddLevelVerkey>,
        setup_params_1: &Groth1SetupParams,
        setup_params_2: &Groth2SetupParams,
    ) -> DelgResult<bool> {
        if self.size() == 0 {
            return Err(DelgError::ChainEmpty {});
        }
        if (even_level_vks.len() + odd_level_vks.len()) != (self.size() + 1) {
            return Err(DelgError::IncorrectNumberOfVerkeys {
                expected: self.size() + 1,
                given: even_level_vks.len() + odd_level_vks.len(),
            });
        }
        if even_level_vks.len() != ((self.size() / 2) + 1) {
            return Err(DelgError::IncorrectNumberOfEvenLevelVerkeys {
                expected: (self.size() / 2) + 1,
                given: even_level_vks.len(),
            });
        }
        if self.size() % 2 == 1 {
            if odd_level_vks.len() != ((self.size() / 2) + 1) {
                return Err(DelgError::IncorrectNumberOfOddLevelVerkeys {
                    expected: (self.size() / 2) + 1,
                    given: odd_level_vks.len(),
                });
            }
        } else {
            if odd_level_vks.len() != (self.size() / 2) {
                return Err(DelgError::IncorrectNumberOfOddLevelVerkeys {
                    expected: self.size() / 2,
                    given: odd_level_vks.len(),
                });
            }
        }

        for i in 1..=self.size() {
            let r = if i % 2 == 1 {
                let idx = i / 2;
                let link = &self.odd_links[idx];
                if link.level != i {
                    return return Err(DelgError::UnexpectedLevel {
                        expected: i,
                        given: link.level,
                    });
                }
                link.verify(odd_level_vks[idx], even_level_vks[idx], setup_params_1)?
            } else {
                let link = &self.even_links[(i / 2) - 1];
                if link.level != i {
                    return return Err(DelgError::UnexpectedLevel {
                        expected: i,
                        given: link.level,
                    });
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

    /// Returns a truncated version of the current chain. Does not modify the current chain but clones the links.
    pub fn get_truncated(&self, size: usize) -> DelgResult<Self> {
        if size > self.size() {
            return Err(DelgError::ChainIsShorterThanExpected {
                actual_size: self.size(),
                expected_size: size,
            });
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
}

impl EvenLevelIssuer {
    pub fn new(level: usize) -> DelgResult<Self> {
        if level % 2 != 0 {
            return Err(DelgError::ExpectedEvenLevel { given: level });
        }
        Ok(Self { level })
    }

    pub fn keygen(setup_params: &Groth1SetupParams) -> (EvenLevelSigkey, EvenLevelVerkey) {
        GrothS1::keygen(setup_params)
    }

    pub fn delegate(
        &self,
        mut delegatee_attributes: G1Vector,
        delegatee_vk: OddLevelVerkey,
        sk: &EvenLevelSigkey,
        setup_params: &Groth1SetupParams,
    ) -> DelgResult<CredLinkOdd> {
        if delegatee_attributes.len() >= setup_params.y.len() {
            return Err(DelgError::MoreAttributesThanExpected {
                expected: setup_params.y.len(),
                given: delegatee_attributes.len(),
            });
        }
        delegatee_attributes.push(delegatee_vk.0);
        let signature = Groth1Sig::new(delegatee_attributes.as_slice(), sk, setup_params)?;
        Ok(CredLinkOdd {
            level: &self.level + 1,
            attributes: delegatee_attributes,
            signature,
        })
    }
}

impl OddLevelIssuer {
    pub fn new(level: usize) -> DelgResult<Self> {
        if level % 2 == 0 {
            return Err(DelgError::ExpectedOddLevel { given: level });
        }
        Ok(Self { level })
    }

    pub fn keygen(setup_params: &Groth2SetupParams) -> (OddLevelSigkey, OddLevelVerkey) {
        GrothS2::keygen(setup_params)
    }

    pub fn delegate(
        &self,
        mut delegatee_attributes: G2Vector,
        delegatee_vk: EvenLevelVerkey,
        sk: &OddLevelSigkey,
        setup_params: &Groth2SetupParams,
    ) -> DelgResult<CredLinkEven> {
        if delegatee_attributes.len() >= setup_params.y.len() {
            return Err(DelgError::MoreAttributesThanExpected {
                expected: setup_params.y.len(),
                given: delegatee_attributes.len(),
            });
        }
        delegatee_attributes.push(delegatee_vk.0);
        let signature = Groth2Sig::new(delegatee_attributes.as_slice(), sk, setup_params)?;
        Ok(CredLinkEven {
            level: &self.level + 1,
            attributes: delegatee_attributes,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // For benchmarking
    use std::time::{Duration, Instant};

    /// XXX: Need test fixtures

    #[test]
    fn test_delegation_level_0_to_level_2() {
        let max_attributes = 5;
        let label = "test".as_bytes();
        let params1 = GrothS1::setup(max_attributes, label);
        let params2 = GrothS2::setup(max_attributes, label);

        let l_0_issuer = EvenLevelIssuer::new(0).unwrap();
        let l_1_issuer = OddLevelIssuer::new(1).unwrap();
        let l_2_issuer = EvenLevelIssuer::new(2).unwrap();

        let (l_0_issuer_sk, l_0_issuer_vk) = EvenLevelIssuer::keygen(&params1);
        let (l_1_issuer_sk, l_1_issuer_vk) = OddLevelIssuer::keygen(&params2);
        let (l_2_issuer_sk, l_2_issuer_vk) = EvenLevelIssuer::keygen(&params1);

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
