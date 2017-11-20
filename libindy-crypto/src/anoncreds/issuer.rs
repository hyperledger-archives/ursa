use bn::BigNumber;
use errors::IndyCryptoError;

use pair::{
    GroupOrderElement,
    PointG1,
    PointG2,
    Pair
};

use super::constants::{
    LARGE_E_END_RANGE,
    LARGE_E_START,
    LARGE_MASTER_SECRET,
    LARGE_PRIME
};

use super::helpers::{
    ByteOrder,
    bitwise_or_big_int,
    encode_attribute,
    generate_safe_prime,
    generate_v_prime_prime,
    gen_x,
    get_hash_as_int,
    random_qr,
    transform_u32_to_array_of_u8
};

use super::prover::{
    BlindedPrimaryMasterSecret,
    BlindedRevocationMasterSecret
};

use std::collections::{HashMap, HashSet};
use time;

pub struct Attributes {
    attributes: HashSet<String>
}

impl Attributes {
    pub fn new() -> Result<Attributes, IndyCryptoError> {
        Ok(Attributes {
            attributes: HashSet::new()
        })
    }

    pub fn add(&mut self, attribute: String) {
        self.attributes.insert(attribute);
    }
}

pub struct AttributesValues {
    attributes_values: HashMap<String, BigNumber>
}

impl AttributesValues {
    pub fn new() -> Result<AttributesValues, IndyCryptoError> {
        Ok(AttributesValues {
            attributes_values: HashMap::new()
        })
    }

    pub fn add(&mut self, attribute: String, value: BigNumber) {
        self.attributes_values.insert(attribute, value);
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PrimaryPrivateKey {
    p: BigNumber,
    q: BigNumber
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PrimaryPublicKey {
    pub n: BigNumber,
    pub s: BigNumber,
    pub rms: BigNumber,
    pub r: HashMap<String, BigNumber>,
    pub rctxt: BigNumber,
    pub z: BigNumber
}

pub struct RevocationPrivateKey {
    pub x: GroupOrderElement,
    pub sk: GroupOrderElement
}

pub struct RevocationPublicKey {
    pub g: PointG1,
    pub g_dash: PointG2,
    pub h: PointG1,
    pub h0: PointG1,
    pub h1: PointG1,
    pub h2: PointG1,
    pub htilde: PointG1,
    pub h_cap: PointG2,
    pub u: PointG2,
    pub pk: PointG1,
    pub y: PointG2
}

pub struct RevocationAccumulator {
    pub acc: PointG2,
    pub v: HashSet<u32>,
    pub max_claim_num: u32,
    pub current_i: u32
}

impl RevocationAccumulator {
    pub fn is_full(&self) -> bool {
        self.current_i > self.max_claim_num
    }
}

pub struct RevocationAccumulatorPrivateKey {
    pub gamma: GroupOrderElement
}

pub struct RevocationAccumulatorPublicKey {
    pub z: Pair
}

pub struct RevocationAccumulatorTails {
    pub tails: HashMap<u32, PointG1>,
    pub tails_dash: HashMap<u32, PointG2>
}

pub struct RevocationContext {
    pub m_2: BigNumber,
    pub acc_idx: u32
}

impl RevocationContext {
    pub fn new(acc_idx: u32, prover_id: &str) -> Result<RevocationContext, IndyCryptoError> {
        let accumulator_index_bn = encode_attribute(&acc_idx.to_string(), ByteOrder::Little)?;
        let prover_id_bn = encode_attribute(prover_id, ByteOrder::Little)?;

        let mut s = vec![
            bitwise_or_big_int(&accumulator_index_bn, &prover_id_bn)?.to_bytes()?
        ];

        /* TODO: FIXME: use const!!! */
        let pow_2 = BigNumber::from_u32(2)?.exp(&BigNumber::from_u32(LARGE_MASTER_SECRET)?, None)?;
        let m_2 = get_hash_as_int(&mut s)?.modulus(&pow_2, None)?;

        Ok(RevocationContext { m_2, acc_idx })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PrimaryClaim {
    pub m_2: BigNumber,
    pub a: BigNumber,
    pub e: BigNumber,
    pub v: BigNumber
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Witness {
    pub sigma_i: PointG2,
    pub u_i: PointG2,
    pub g_i: PointG1,
    pub omega: PointG2,
    pub v: HashSet<u32>
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NonRevocationClaim {
    pub sigma: PointG1,
    pub c: GroupOrderElement,
    pub vr_prime_prime: GroupOrderElement,
    pub witness: Witness,
    pub g_i: PointG1,
    pub i: u32,
    pub m2: GroupOrderElement
}

pub struct Issuer {}

impl Issuer {
    pub fn generate_primary_keys(attrs: &Attributes) -> Result<(PrimaryPublicKey,
                                                                PrimaryPrivateKey), IndyCryptoError> {
        let mut ctx = BigNumber::new_context()?;

        if attrs.attributes.len() == 0 {
            return Err(IndyCryptoError::InvalidStructure(format!("List of attribute names is empty")));
        }

        let p_safe = generate_safe_prime(LARGE_PRIME)?;
        let q_safe = generate_safe_prime(LARGE_PRIME)?;

        let mut p = p_safe.sub(&BigNumber::from_u32(1)?)?;
        p.div_word(2)?;

        let mut q = q_safe.sub(&BigNumber::from_u32(1)?)?;
        q.div_word(2)?;

        let n = p_safe.mul(&q_safe, Some(&mut ctx))?;
        let s = random_qr(&n)?;
        let xz = gen_x(&p, &q)?;
        let mut r: HashMap<String, BigNumber> = HashMap::new();

        for attribute in &attrs.attributes {
            r.insert(attribute.to_owned(), s.mod_exp(&gen_x(&p, &q)?, &n, Some(&mut ctx))?);
        }

        let z = s.mod_exp(&xz, &n, Some(&mut ctx))?;

        let rms = s.mod_exp(&gen_x(&p, &q)?, &n, Some(&mut ctx))?;
        let rctxt = s.mod_exp(&gen_x(&p, &q)?, &n, Some(&mut ctx))?;

        Ok((
            PrimaryPublicKey { n, s, rms, r, rctxt, z },
            PrimaryPrivateKey { p, q }
        ))
    }

    pub fn generate_revocation_keys() -> Result<(RevocationPublicKey,
                                                 RevocationPrivateKey), IndyCryptoError> {
        let h = PointG1::new()?;
        let h0 = PointG1::new()?;
        let h1 = PointG1::new()?;
        let h2 = PointG1::new()?;
        let htilde = PointG1::new()?;
        let g = PointG1::new()?;

        let u = PointG2::new()?;
        let h_cap = PointG2::new()?;

        let x = GroupOrderElement::new()?;
        let sk = GroupOrderElement::new()?;
        let g_dash = PointG2::new()?;

        let pk = g.mul(&sk)?;
        let y = h_cap.mul(&x)?;

        Ok((
            RevocationPublicKey { g, g_dash, h, h0, h1, h2, htilde, h_cap, u, pk, y },
            RevocationPrivateKey { x, sk }
        ))
    }

    pub fn issue_revocation_accumulator(r_pub_key: &RevocationPublicKey,
                                        max_claim_num: u32) -> Result<(RevocationAccumulator,
                                                                       RevocationAccumulatorPublicKey,
                                                                       RevocationAccumulatorPrivateKey,
                                                                       RevocationAccumu
        let mut g: HashMap<u32, PointG1> = HashMap::new();latorTails), IndyCryptoError> {
            let gamma = GroupOrderElement::new()?;
        let mut g_dash: HashMap<u32, PointG2> = HashMap::new();

        for i in 0..(2 * max_claim_num) {
            if i != max_claim_num + 1 {
                let i_bytes = transform_u32_to_array_of_u8(i);
                let mut pow = GroupOrderElement::from_bytes(&i_bytes)?;
                pow = gamma.pow_mod(&pow)?;
                g.insert(i, r_pub_key.g.mul(&pow)?);
                g_dash.insert(i, r_pub_key.g_dash.mul(&pow)?);
            }
        }

        let mut z = Pair::pair(&r_pub_key.g, &r_pub_key.g_dash)?;
        let mut pow = GroupOrderElement::from_bytes(&transform_u32_to_array_of_u8(max_claim_num + 1))?;
        pow = gamma.pow_mod(&pow)?;
        z = z.pow(&pow)?;
        let acc = PointG2::new_inf()?;
        let v: HashSet<u32> = HashSet::new();

        Ok((
            RevocationAccumulator { acc, v, max_claim_num, current_i: 1 },
            RevocationAccumulatorPublicKey { z },
            RevocationAccumulatorPrivateKey { gamma },
            RevocationAccumulatorTails { tails: g, tails_dash: g_dash }
        ))
    }

    fn issue_primary_claim(p_pub_key: &PrimaryPublicKey,
                           p_priv_key: &PrimaryPrivateKey,
                           blnd_p_ms: &BlindedPrimaryMasterSecret,
                           r_cnxt: &RevocationContext,
                           attrs_values: &AttributesValues) -> Result<PrimaryClaim, IndyCryptoError> {
        /* TODO: FIXME: Use const!!! */
        let e_start = BigNumber::from_u32(2)?.exp(&BigNumber::from_u32(LARGE_E_START)?, None)?;

        /* TODO: FIXME: Use const!!! */
        let e_end = BigNumber::from_u32(2)?
            .exp(&BigNumber::from_u32(LARGE_E_END_RANGE)?, None)?
            .add(&e_start)?;

        let m_2 = r_cnxt.m_2.clone()?;
        let v = generate_v_prime_prime()?;
        let e = BigNumber::generate_prime_in_range(&e_start, &e_end)?;
        let a = Issuer::_sign_primary_claim(p_pub_key, p_priv_key, r_cnxt, &attrs_values, &v, blnd_p_ms, &e)?;

        Ok(PrimaryClaim { m_2, a, e, v })
    }

    fn issue_non_revocation_claim(r_cnxt: &RevocationContext,
                                  blnd_r_ms: &BlindedRevocationMasterSecret,
                                  r_pub_key: &RevocationPublicKey,
                                  r_priv_key: &RevocationPrivateKey,
                                  r_acc: &mut RevocationAccumulator,
                                  r_acc_priv_key: &RevocationAccumulatorPrivateKey,
                                  r_acc_tails: &mut RevocationAccumulatorTails) -> Result<(NonRevocationClaim,
                                                                                           i64), IndyCryptoError> {
        if r_acc.is_full() {
            return Err(IndyCryptoError::AnoncredsRevocationAccumulatorIsFull(format!("Revocation accumulator is full")));
        }

        let i = r_cnxt.acc_idx;
        r_acc.current_i += 1;

        let vr_prime_prime = GroupOrderElement::new()?;
        let c = GroupOrderElement::new()?;
        let m2 = GroupOrderElement::from_bytes(&r_cnxt.m_2.to_bytes()?)?;

        let g_i = r_acc_tails.tails
            .get(&i)
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in tails.g", i)))?;

        let sigma =
            r_pub_key.h0.add(&r_pub_key.h1.mul(&m2)?)?
                .add(&blnd_r_ms.ur)?
                .add(g_i)?
                .add(&r_pub_key.h2.mul(&vr_prime_prime)?)?
                .mul(&r_priv_key.x.add_mod(&c)?.inverse()?)?;

        let mut omega = PointG2::new_inf()?;

        for j in &r_acc.v {
            let index = r_acc.max_claim_num + 1 - j + i;
            omega = omega.add(r_acc_tails.tails_dash
                .get(&index)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in g", index)))?)?;
        }

        let sigma_i = r_pub_key.g_dash
            .mul(&r_priv_key.sk
                .add_mod(&r_acc_priv_key.gamma
                    .pow_mod(&GroupOrderElement::from_bytes(&transform_u32_to_array_of_u8(i as u32))?)?)?
                .inverse()?)?;
        let u_i = r_pub_key.u
            .mul(&r_acc_priv_key.gamma
                .pow_mod(&GroupOrderElement::from_bytes(&transform_u32_to_array_of_u8(i as u32))?)?)?;

        let index = r_acc.max_claim_num + 1 - i;

        r_acc.acc = r_acc.acc
            .add(r_acc_tails.tails_dash
                .get(&index)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in g", index)))?)?;

        r_acc.v.insert(i);

        let witness = Witness {
            sigma_i,
            u_i,
            g_i: g_i.clone(),
            omega,
            v: r_acc.v.clone()
        };

        let timestamp = time::now_utc().to_timespec().sec;

        Ok((
            NonRevocationClaim { sigma, c, vr_prime_prime, witness, g_i: g_i.clone(), i, m2 },
            timestamp
        ))
    }

    pub fn revoke(&self,
                  r_acc: &mut RevocationAccumulator,
                  r_acc_tails: &mut RevocationAccumulatorTails,
                  acc_idx: u32) -> Result<i64, IndyCryptoError> {
        if !r_acc.v.remove(&acc_idx) {
            return Err(IndyCryptoError::AnoncredsRevocationAccumulatorIndex(
                format!("User index:{} not found in Accumulator", acc_idx))
            );
        }

        let index: u32 = r_acc.max_claim_num + 1 - acc_idx;

        let element = r_acc_tails.tails_dash
            .get(&index)
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in g", index)))?;

        r_acc.acc = r_acc.acc.sub(element)?;
        let timestamp = time::now_utc().to_timespec().sec;

        Ok(timestamp)
    }

    fn _sign_primary_claim(p_pub_key: &PrimaryPublicKey,
                           p_priv_key: &PrimaryPrivateKey,
                           r_cnxt: &RevocationContext,
                           attrs_values: &AttributesValues,
                           v: &BigNumber,
                           blnd_p_ms: &BlindedPrimaryMasterSecret,
                           e: &BigNumber) -> Result<BigNumber, IndyCryptoError> {
        let mut context = BigNumber::new_context()?;
        let mut rx = BigNumber::from_u32(1)?;

        for (key, value) in &attrs_values.attributes_values {
            let pk_r = p_pub_key.r
                .get(key)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in pk.r", key)))?;

            rx = rx.mul(
                &pk_r.mod_exp(&value, &p_pub_key.n, Some(&mut context))?,
                Some(&mut context)
            )?;
        }

        rx = p_pub_key.rctxt
            .mod_exp(&r_cnxt.m_2, &p_pub_key.n, Some(&mut context))?
            .mul(&rx, Some(&mut context))?;

        if &blnd_p_ms.u != &BigNumber::from_u32(0)? {
            rx = blnd_p_ms.u
                .modulus(&p_pub_key.n, Some(&mut context))?
                .mul(&rx, Some(&mut context))?;
        }

        let n = p_priv_key.p.mul(&p_priv_key.q, Some(&mut context))?;
        let mut e_inverse = e.modulus(&n, Some(&mut context))?;

        let mut a = p_pub_key.s
            .mod_exp(&v, &p_pub_key.n, Some(&mut context))?
            .mul(&rx, Some(&mut context))?;

        a = p_pub_key.z.mod_div(&a, &p_pub_key.n)?;
        e_inverse = e_inverse.inverse(&n, Some(&mut context))?;
        a = a.mod_exp(&e_inverse, &p_pub_key.n, Some(&mut context))?;

        Ok(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_generate_primary_keys_works() {
        let (p_pub_key, p_priv_key) = Issuer::generate_primary_keys(&mocks::attributes()).unwrap();
        assert_eq!(p_pub_key, mocks::primary_public_key());
        assert_eq!(p_priv_key, mocks::primary_private_key());
    }

    pub mod mocks {
        use super::*;

        pub fn primary_public_key() -> PrimaryPublicKey {
            let n = BigNumber::from_dec("89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129").unwrap();
            let s = BigNumber::from_dec("64684820421150545443421261645532741305438158267230326415141505826951816460650437611148133267480407958360035501128469885271549378871140475869904030424615175830170939416512594291641188403335834762737251794282186335118831803135149622404791467775422384378569231649224208728902565541796896860352464500717052768431523703881746487372385032277847026560711719065512366600220045978358915680277126661923892187090579302197390903902744925313826817940566429968987709582805451008234648959429651259809188953915675063700676546393568304468609062443048457324721450190021552656280473128156273976008799243162970386898307404395608179975243").unwrap();
            let rms = BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap();

            let mut r: HashMap<String, BigNumber> = HashMap::new();
            r.insert("sex".to_string(), BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap());
            r.insert("name".to_string(), BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap());
            r.insert("age".to_string(), BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap());
            r.insert("height".to_string(), BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap());

            let rctxt = BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap();
            let z = BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap();

            PrimaryPublicKey { n, s, rms, r, rctxt, z }
        }

        pub fn primary_private_key() -> PrimaryPrivateKey {
            let p = BigNumber::from_dec("149212738775716179659508649034140914067267873385650452563221860367878267143635191771233591587868730221903476199105022913859057555905442876114559838735355652672950963033972314646471235775711934244481758977047119803475879470383993713606231800156950590334088086141997103196482505556481059579729337361392854778311").unwrap();
            let q = BigNumber::from_dec("149212738775716179659508649034140914067267873385650452563221860367878267143635191771233591587868730221903476199105022913859057555905442876114559838735355652672950963033972314646471235775711934244481758977047119803475879470383993713606231800156950590334088086141997103196482505556481059579729337361392854778311").unwrap();

            PrimaryPrivateKey { p, q }
        }

        pub fn attributes() -> Attributes {
            let mut attributes: HashSet<String> = HashSet::new();
            attributes.insert("name".to_string());
            attributes.insert("age".to_string());
            attributes.insert("height".to_string());
            attributes.insert("sex".to_string());

            Attributes { attributes }
        }
    }
}