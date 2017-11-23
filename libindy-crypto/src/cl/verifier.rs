use cl::types::*;
use cl::constants::{LARGE_E_START, ITERATION, LARGE_NONCE};
use cl::helpers::{AppendByteArray, bignum_to_group_element, calc_teq, calc_tge, get_hash_as_int, bn_rand};
use bn::BigNumber;
use std::collections::{HashMap, HashSet};
use errors::IndyCryptoError;
use cl::prover::ProofBuilder;

pub struct Verifier {}

impl Verifier {
    pub fn new_nonce() -> Result<Nonce, IndyCryptoError> {
        Ok(Nonce {
            value: bn_rand(LARGE_NONCE)?
        })
    }

    pub fn new_proof_verifier() -> Result<ProofVerifier, IndyCryptoError> {
        Ok(ProofVerifier {
            claims: HashMap::new(),
        })
    }
}


#[derive(Debug)]
pub struct ProofVerifier {
    claims: HashMap<String, VerifyClaim>,
}

impl ProofVerifier {
    pub fn add_sub_proof_request(&mut self,
                                 issuer_key_id: &str,
                                 pub_key: IssuerPublicKey,
                                 r_reg: Option<RevocationRegistryPublic>,
                                 sub_proof_request: SubProofRequest,
                                 claim_schema: ClaimSchema) -> Result<(), IndyCryptoError> {
        self.claims.insert(issuer_key_id.to_string(), VerifyClaim {
            pub_key,
            r_reg,
            sub_proof_request,
            claim_schema,
        });
        Ok(())
    }

    pub fn verify(&mut self,
                  proof: &Proof,
                  nonce: &Nonce) -> Result<bool, IndyCryptoError> {
        info!(target: "anoncreds_service", "Verifier verify proof -> start");

        //TODO check self.claims.sub_proof_request against proof.proofs.primary proof

        let mut tau_list: Vec<Vec<u8>> = Vec::new();

        for (issuer_key_id, proof_item) in &proof.proofs {
            let claim: &VerifyClaim = self.claims.get(issuer_key_id)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Schema is not found")))?;

            if let (Some(non_revocation_proof), Some(pkr), Some(revoc_reg)) = (proof_item.non_revoc_proof.as_ref(),
                                                                               claim.pub_key.r_key.as_ref(),
                                                                               claim.r_reg.as_ref()) {
                tau_list.extend_from_slice(
                    &ProofVerifier::_verify_non_revocation_proof(
                        &pkr,
                        &revoc_reg.acc,
                        &revoc_reg.key,
                        &proof.aggregated_proof.c_hash,
                        &non_revocation_proof)?.as_slice()?
                );
            };

            tau_list.append_vec(
                &ProofVerifier::_verify_primary_proof(&claim.pub_key.p_key,
                                                      &proof.aggregated_proof.c_hash,
                                                      &proof_item.primary_proof,
                                                      &claim.claim_schema,
                                                      &claim.sub_proof_request)?
            )?;
        }

        let mut values: Vec<Vec<u8>> = Vec::new();

        values.extend_from_slice(&tau_list);
        values.extend_from_slice(&proof.aggregated_proof.c_list);
        values.push(nonce.value.to_bytes()?);

        let c_hver = get_hash_as_int(&mut values)?;

        info!(target: "anoncreds_service", "Verifier verify proof -> done");

        Ok(c_hver == proof.aggregated_proof.c_hash)
    }

    fn _verify_primary_proof(pk: &IssuerPrimaryPublicKey, c_hash: &BigNumber,
                             primary_proof: &PrimaryProof, claim_schema: &ClaimSchema, sub_proof_request: &SubProofRequest) -> Result<Vec<BigNumber>, IndyCryptoError> {
        info!(target: "anoncreds_service", "Verifier verify primary proof -> start");

        let mut t_hat: Vec<BigNumber> = ProofVerifier::_verify_equality(pk, &primary_proof.eq_proof, c_hash, claim_schema, sub_proof_request)?;

        for ge_proof in primary_proof.ge_proofs.iter() {
            t_hat.append(&mut ProofVerifier::_verify_ge_predicate(pk, ge_proof, c_hash)?)
        }

        info!(target: "anoncreds_service", "Verifier verify primary proof -> done");
        Ok(t_hat)
    }

    fn _verify_equality(pk: &IssuerPrimaryPublicKey, proof: &PrimaryEqualProof, c_h: &BigNumber,
                        claim_schema: &ClaimSchema, sub_proof_request: &SubProofRequest) -> Result<Vec<BigNumber>, IndyCryptoError> {
        let unrevealed_attrs: HashSet<String> =
            claim_schema.attrs
                .difference(&sub_proof_request.revealed_attrs)
                .map(|attr| attr.clone())
                .collect::<HashSet<String>>();

        let t1: BigNumber = calc_teq(&pk, &proof.a_prime, &proof.e, &proof.v, &proof.m,
                                     &proof.m1, &proof.m2, &unrevealed_attrs)?;

        let mut ctx = BigNumber::new_context()?;
        let mut rar = BigNumber::from_dec("1")?;

        for (attr, encoded_value) in &proof.revealed_attrs {
            let cur_r = pk.r.get(attr)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in pk.r", attr)))?;

            rar = cur_r
                .mod_exp(encoded_value, &pk.n, Some(&mut ctx))?
                .mul(&rar, Some(&mut ctx))?;
        }

        let tmp: BigNumber =
            BigNumber::from_dec("2")?
                .exp(
                    &BigNumber::from_dec(&LARGE_E_START.to_string())?,
                    Some(&mut ctx)
                )?;

        rar = proof.a_prime
            .mod_exp(&tmp, &pk.n, Some(&mut ctx))?
            .mul(&rar, Some(&mut ctx))?;

        let t2: BigNumber = pk.z
            .mod_div(&rar, &pk.n)?
            .mod_exp(&c_h, &pk.n, Some(&mut ctx))?
            .inverse(&pk.n, Some(&mut ctx))?;

        let t: BigNumber = t1
            .mul(&t2, Some(&mut ctx))?
            .modulus(&pk.n, Some(&mut ctx))?;

        Ok(vec![t])
    }

    fn _verify_ge_predicate(pk: &IssuerPrimaryPublicKey, proof: &PrimaryPredicateGEProof, c_h: &BigNumber) -> Result<Vec<BigNumber>, IndyCryptoError> {
        let mut ctx = BigNumber::new_context()?;
        let mut tau_list = calc_tge(&pk, &proof.u, &proof.r, &proof.mj,
                                    &proof.alpha, &proof.t)?;

        for i in 0..ITERATION {
            let cur_t = proof.t.get(&i.to_string())
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in proof.t", i)))?;

            tau_list[i] = cur_t
                .mod_exp(&c_h, &pk.n, Some(&mut ctx))?
                .inverse(&pk.n, Some(&mut ctx))?
                .mul(&tau_list[i], Some(&mut ctx))?
                .modulus(&pk.n, Some(&mut ctx))?;
        }

        let delta = proof.t.get("DELTA")
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in proof.t", "DELTA")))?;

        tau_list[ITERATION] = pk.z
            .mod_exp(
                &BigNumber::from_dec(&proof.predicate.value.to_string())?,
                &pk.n, Some(&mut ctx))?
            .mul(&delta, Some(&mut ctx))?
            .mod_exp(&c_h, &pk.n, Some(&mut ctx))?
            .inverse(&pk.n, Some(&mut ctx))?
            .mul(&tau_list[ITERATION], Some(&mut ctx))?
            .modulus(&pk.n, Some(&mut ctx))?;

        tau_list[ITERATION + 1] = delta
            .mod_exp(&c_h, &pk.n, Some(&mut ctx))?
            .inverse(&pk.n, Some(&mut ctx))?
            .mul(&tau_list[ITERATION + 1], Some(&mut ctx))?
            .modulus(&pk.n, Some(&mut ctx))?;

        Ok(tau_list)
    }

    pub fn _verify_non_revocation_proof(pkr: &IssuerRevocationPublicKey,
                                        accum: &RevocationAccumulator,
                                        accum_pk: &RevocationAccumulatorPublicKey,
                                        c_hash: &BigNumber, proof: &NonRevocProof)
                                        -> Result<NonRevocProofTauList, IndyCryptoError> {
        info!(target: "anoncreds_service", "Verifier verify non revocation proof -> start");

        let ch_num_z = bignum_to_group_element(&c_hash)?;

        let t_hat_expected_values = ProofBuilder::create_tau_list_expected_values(pkr, accum, accum_pk, &proof.c_list)?;
        let t_hat_calc_values = ProofBuilder::create_tau_list_values(&pkr, &accum, &proof.x_list, &proof.c_list)?;


        let res = Ok(NonRevocProofTauList {
            t1: t_hat_expected_values.t1.mul(&ch_num_z)?.add(&t_hat_calc_values.t1)?,
            t2: t_hat_expected_values.t2.mul(&ch_num_z)?.add(&t_hat_calc_values.t2)?,
            t3: t_hat_expected_values.t3.pow(&ch_num_z)?.mul(&t_hat_calc_values.t3)?,
            t4: t_hat_expected_values.t4.pow(&ch_num_z)?.mul(&t_hat_calc_values.t4)?,
            t5: t_hat_expected_values.t5.mul(&ch_num_z)?.add(&t_hat_calc_values.t5)?,
            t6: t_hat_expected_values.t6.mul(&ch_num_z)?.add(&t_hat_calc_values.t6)?,
            t7: t_hat_expected_values.t7.pow(&ch_num_z)?.mul(&t_hat_calc_values.t7)?,
            t8: t_hat_expected_values.t8.pow(&ch_num_z)?.mul(&t_hat_calc_values.t8)?
        });
        info!(target: "anoncreds_service", "Verifier verify non revocation proof -> start");
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cl::prover;
    use cl::issuer;

    #[test]
    fn verify_equlity_works() {
        let proof = prover::mocks::eq_proof();
        let pk = issuer::mocks::issuer_primary_public_key();
        let c_h = prover::mocks::aggregated_proof().c_hash;
        let claim_schema = issuer::mocks::claim_schema();

        let sub_proof_request = SubProofRequestBuilder::new().unwrap()
            .add_revealed_attr("name").unwrap()
            .finalize().unwrap();

        let res: Vec<BigNumber> = ProofVerifier::_verify_equality(&pk,
                                                                  &proof,
                                                                  &c_h,
                                                                  &claim_schema,
                                                                  &sub_proof_request).unwrap();

        assert_eq!("5726715933634154184237442341903521921929637766411345954184987907936686738874379427010785278205728337008490886334546986256977911094895352684252668401039\
        0734822547748045548230392972760963518121157019709701625242723461454152432542778593173172718989724831707206802011046039600739512848642063504936248491468813901985203\
        54967877305697946935843517325405833146048432820340694038565990837598448770700308385128291666088326619995322552956263732406309387145993589509288204758190568289210681\
        7949064772180224991836096702787507175722462532114363947522106747408210077795425134317713696705518683739608360318815557420637666058347763955", res[0].to_dec().unwrap());
    }

    #[test]
    fn _verify_ge_predicate_works() {
        let proof = prover::mocks::ge_proof();
        let c_h = prover::mocks::aggregated_proof().c_hash;
        let pk = issuer::mocks::issuer_primary_public_key();

        let res = ProofVerifier::_verify_ge_predicate(&pk, &proof, &c_h);

        assert!(res.is_ok());
        let res_data = res.unwrap();

        assert_eq!("376910366785000888640907068892773445290856982028553183426096623244555347257778101747799882436148347403830024840429617795354387295127009257238001847697728551\
        176536093973115809374401318141110098900739722767845936624708107236876761676800627172399726564255634308382367493256717024633900449205720018609556512423317410372608366135\
        066533236820567062263706984223659166559990463804265095415860347492428279789699722395246760391390256022639741018088870083311929296796590769109958556654779529301996928547\
        78469439162325030246066895851569630345729938981633504514117558420480144828304421708923356898912192737390539479512879411139535", res_data[0].to_dec().unwrap());

        assert_eq!("376910366785000888640907068892773445290856982028553183426096623244555347257778101747799882436148347403830024840429617795354387295127009257238001847697728551\
        176536093973115809374401318141110098900739722767845936624708107236876761676800627172399726564255634308382367493256717024633900449205720018609556512423317410372608366135\
        066533236820567062263706984223659166559990463804265095415860347492428279789699722395246760391390256022639741018088870083311929296796590769109958556654779529301996928547\
        78469439162325030246066895851569630345729938981633504514117558420480144828304421708923356898912192737390539479512879411139535", res_data[4].to_dec().unwrap());

        assert_eq!("4706530486660795807594696126453392843593312253601667969008027865938669831613255990876876168574341472858634191430502533997053787371484591516484310077682156120\
        0343390749927996265246866447155790487554483555192805709960222015718787293872197230832464704800887153568636866026153126587657548580608446574507279965440247754859129693686\
        1864273991033137371106324132550175224820164581900030456410773386740196083471393997554706544523739752281900419801521207994038554809091738654313973079882387597672518908535\
        80982844825639097363091181044515877489450972963624109587697097258041963985607958610791800500711857115582406526050626576194", res_data[5].to_dec().unwrap());
    }
}
