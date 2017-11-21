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

use super::types::{
    Claim,
    ClaimAttributes,
    ClaimAttributesBuilder,
    ClaimAttributesValues,
    ClaimAttributesValuesBuilder,
    BlindedMasterSecret,
    IssuerPrimaryPublicKey,
    IssuerPrimaryPrivateKey,
    IssuerPublicKey,
    IssuerPrivateKey,
    IssuerRevocationPublicKey,
    IssuerRevocationPrivateKey,
    RevocationAccumulator,
    RevocationAccumulatorPublicKey,
    RevocationAccumulatorPrivateKey,
    RevocationAccumulatorTails,
    RevocationRegistryPublic,
    RevocationRegistryPrivate,
    PrimaryClaim,
    NonRevocationClaim,
    Witness,
};

use std::collections::{HashMap, HashSet};

pub struct Issuer {}

impl Issuer {
    pub fn new_claim_attrs_builder() -> Result<ClaimAttributesBuilder, IndyCryptoError> {
        let res = ClaimAttributesBuilder::new()?;
        Ok(res)
    }

    pub fn new_keys(attrs: &ClaimAttributes, non_revocation_part: bool) -> Result<(IssuerPublicKey, IssuerPrivateKey), IndyCryptoError> {
        let (p_pub_key, p_priv_key) = Issuer::_new_primary_keys(attrs)?;

        let (r_pub_key, r_priv_key) = if non_revocation_part {
            let (r_pub_key, r_priv_key) = Issuer::_new_revocation_keys()?;
            (Some(r_pub_key), Some(r_priv_key))
        } else {
            (None, None)
        };

        Ok((
            IssuerPublicKey { p_key: p_pub_key, r_key: r_pub_key },
            IssuerPrivateKey { p_key: p_priv_key, r_key: r_priv_key }
        ))
    }

    pub fn new_revocation_registry(issuer_pub_key: &IssuerPublicKey,
                                   max_claim_num: u32) -> Result<(RevocationRegistryPublic,
                                                                  RevocationRegistryPrivate), IndyCryptoError> {
        let r_pub_key = issuer_pub_key.r_key
            .as_ref()
            .ok_or(IndyCryptoError::InvalidStructure(format!("No revocation part present in issuer key.")))?;

        let mut g: HashMap<u32, PointG1> = HashMap::new();
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
            RevocationRegistryPublic {
                acc: RevocationAccumulator { acc, v, max_claim_num },
                key: RevocationAccumulatorPublicKey { z },
                tails: RevocationAccumulatorTails { tails: g, tails_dash: g_dash },

            },
            RevocationRegistryPrivate {
                key: RevocationAccumulatorPrivateKey { gamma },
            }
        ))
    }

    pub fn new_claim_attrs_values_builder() -> Result<ClaimAttributesValuesBuilder, IndyCryptoError> {
        let res = ClaimAttributesValuesBuilder::new()?;
        Ok(res)
    }

    pub fn new_claim(prover_id: &str,
                     blnd_ms: &BlindedMasterSecret,
                     attr_values: &ClaimAttributesValues,
                     issuer_pub_key: &IssuerPublicKey,
                     issuer_priv_key: &IssuerPrivateKey,
                     rev_idx: Option<u32>,
                     r_reg_pub: Option<&mut RevocationRegistryPublic>,
                     r_reg_priv: Option<&RevocationRegistryPrivate>) -> Result<Claim, IndyCryptoError> {
        let m_2 = Issuer::_calc_m2(prover_id, rev_idx)?;

        let p_claim = Issuer::_new_primary_claim(&m_2,
                                                 issuer_pub_key,
                                                 issuer_priv_key,
                                                 blnd_ms,
                                                 attr_values)?;

        let r_claim = if let (Some(rev_idx_2), Some(r_reg_pub), Some(r_reg_priv)) = (rev_idx, r_reg_pub, r_reg_priv) {
            Some(Issuer::_new_non_revocation_claim(rev_idx_2,
                                                   &m_2,
                                                   blnd_ms,
                                                   issuer_pub_key,
                                                   issuer_priv_key,
                                                   r_reg_pub,
                                                   r_reg_priv)?)
        } else {
            None
        };

        Ok(Claim { p_claim, r_claim })
    }

    pub fn revoke(&self,
                  r_acc: &mut RevocationAccumulator,
                  r_acc_tails: &mut RevocationAccumulatorTails,
                  acc_idx: u32) -> Result<(), IndyCryptoError> {
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

        Ok(())
    }

    fn _new_primary_keys(attrs: &ClaimAttributes) -> Result<(IssuerPrimaryPublicKey,
                                                             IssuerPrimaryPrivateKey), IndyCryptoError> {
        let mut ctx = BigNumber::new_context()?;

        if attrs.attrs.len() == 0 {
            return Err(IndyCryptoError::InvalidStructure(format!("List of attributes is empty")));
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

        for attribute in &attrs.attrs {
            r.insert(attribute.to_owned(), s.mod_exp(&gen_x(&p, &q)?, &n, Some(&mut ctx))?);
        }

        let z = s.mod_exp(&xz, &n, Some(&mut ctx))?;

        let rms = s.mod_exp(&gen_x(&p, &q)?, &n, Some(&mut ctx))?;
        let rctxt = s.mod_exp(&gen_x(&p, &q)?, &n, Some(&mut ctx))?;

        Ok((
            IssuerPrimaryPublicKey { n, s, rms, r, rctxt, z },
            IssuerPrimaryPrivateKey { p, q }
        ))
    }

    pub fn _new_revocation_keys() -> Result<(IssuerRevocationPublicKey,
                                             IssuerRevocationPrivateKey), IndyCryptoError> {
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
            IssuerRevocationPublicKey { g, g_dash, h, h0, h1, h2, htilde, h_cap, u, pk, y },
            IssuerRevocationPrivateKey { x, sk }
        ))
    }

    pub fn _calc_m2(prover_id: &str, rev_idx: Option<u32>) -> Result<BigNumber, IndyCryptoError> {
        let rev_idx = rev_idx.unwrap_or(0);

        let prover_id_bn = encode_attribute(prover_id, ByteOrder::Little)?;
        let rev_idx_bn = encode_attribute(&rev_idx.to_string(), ByteOrder::Little)?;

        let mut s = vec![
            bitwise_or_big_int(&rev_idx_bn, &prover_id_bn)?.to_bytes()?
        ];

        /* TODO: FIXME: use const!!! */
        let pow_2 = BigNumber::from_u32(2)?.exp(&BigNumber::from_u32(LARGE_MASTER_SECRET)?, None)?;
        let m_2 = get_hash_as_int(&mut s)?.modulus(&pow_2, None)?;

        Ok(m_2)
    }

    fn _new_primary_claim(m_2: &BigNumber,
                          issuer_pub_key: &IssuerPublicKey,
                          issuer_priv_key: &IssuerPrivateKey,
                          blnd_ms: &BlindedMasterSecret,
                          attrs_values: &ClaimAttributesValues) -> Result<PrimaryClaim, IndyCryptoError> {
        /* TODO: FIXME: Use const!!! */
        let e_start = BigNumber::from_u32(2)?.exp(&BigNumber::from_u32(LARGE_E_START)?, None)?;

        /* TODO: FIXME: Use const!!! */
        let e_end = BigNumber::from_u32(2)?
            .exp(&BigNumber::from_u32(LARGE_E_END_RANGE)?, None)?
            .add(&e_start)?;

        let m_2 = m_2.clone()?;
        let v = generate_v_prime_prime()?;
        let e = BigNumber::generate_prime_in_range(&e_start, &e_end)?;
        let a = Issuer::_sign_primary_claim(issuer_pub_key, issuer_priv_key, &m_2, &attrs_values, &v, blnd_ms, &e)?;

        Ok(PrimaryClaim { m_2, a, e, v })
    }

    fn _sign_primary_claim(p_pub_key: &IssuerPublicKey,
                           p_priv_key: &IssuerPrivateKey,
                           m_2: &BigNumber,
                           attrs_values: &ClaimAttributesValues,
                           v: &BigNumber,
                           blnd_ms: &BlindedMasterSecret,
                           e: &BigNumber) -> Result<BigNumber, IndyCryptoError> {
        let p_pub_key = &p_pub_key.p_key;
        let p_priv_key = &p_priv_key.p_key;

        let mut context = BigNumber::new_context()?;
        let mut rx = BigNumber::from_u32(1)?;

        for (key, value) in &attrs_values.attrs_values {
            let pk_r = p_pub_key.r
                .get(key)
                .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in pk.r", key)))?;

            rx = rx.mul(
                &pk_r.mod_exp(&value, &p_pub_key.n, Some(&mut context))?,
                Some(&mut context)
            )?;
        }

        rx = p_pub_key.rctxt
            .mod_exp(&m_2, &p_pub_key.n, Some(&mut context))?
            .mul(&rx, Some(&mut context))?;

        if &blnd_ms.u != &BigNumber::from_u32(0)? {
            rx = blnd_ms.u
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

    fn _new_non_revocation_claim(rev_idx: u32,
                                 m_2: &BigNumber,
                                 blnd_ms: &BlindedMasterSecret,
                                 issuer_pub_key: &IssuerPublicKey,
                                 issuer_priv_key: &IssuerPrivateKey,
                                 r_reg_pub: &mut RevocationRegistryPublic,
                                 r_reg_priv: &RevocationRegistryPrivate) -> Result<NonRevocationClaim, IndyCryptoError> {
        let ur = blnd_ms.ur
            .ok_or(IndyCryptoError::InvalidStructure(format!("No revocation part present in blinded master secred.")))?;

        let r_pub_key = issuer_pub_key.r_key
            .as_ref()
            .ok_or(IndyCryptoError::InvalidStructure(format!("No revocation part present in issuer public key.")))?;

        let r_priv_key = issuer_priv_key.r_key
            .as_ref()
            .ok_or(IndyCryptoError::InvalidStructure(format!("No revocation part present in issuer private key.")))?;

        let r_acc: &mut RevocationAccumulator = &mut r_reg_pub.acc;
        let r_acc_tails: &mut RevocationAccumulatorTails = &mut r_reg_pub.tails;
        let r_acc_priv_key: &RevocationAccumulatorPrivateKey = &r_reg_priv.key;

        if r_acc.is_full() {
            return Err(IndyCryptoError::AnoncredsRevocationAccumulatorIsFull(format!("Revocation accumulator is full.")));
        }

        if r_acc.is_idx_used(rev_idx) {
            return Err(IndyCryptoError::AnoncredsRevocationAccumulatorIsFull(format!("Revocation index is already used.")));
        }

        let i = rev_idx;

        let vr_prime_prime = GroupOrderElement::new()?;
        let c = GroupOrderElement::new()?;
        let m2 = GroupOrderElement::from_bytes(&m_2.to_bytes()?)?;

        let g_i = r_acc_tails.tails
            .get(&i)
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in tails.g", i)))?;

        let sigma =
            r_pub_key.h0.add(&r_pub_key.h1.mul(&m2)?)?
                .add(&ur)?
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

        Ok(
            NonRevocationClaim { sigma, c, vr_prime_prime, witness, g_i: g_i.clone(), i, m2 }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_generate_keys_works() {
        let (pub_key, priv_key) = Issuer::new_keys(&mocks::claim_attributes(), false).unwrap();
        assert_eq!(pub_key.p_key, mocks::issuer_primary_public_key());
        assert_eq!(priv_key.p_key, mocks::issuer_primary_private_key());
        assert!(pub_key.r_key.is_none());
        assert!(priv_key.r_key.is_none());
    }
}

pub mod mocks {
    use super::*;

    pub fn issuer_primary_public_key() -> IssuerPrimaryPublicKey {
        let n = BigNumber::from_dec("95230844261716231334966278654105782744493078250034916428724307571481648650972254096365233503303500776910009532385733941342231244809050180342216701303297309484964627111488667613567243812137828734726055835536190375874228378361894062875040911721595668269426387378524841651770329520854646198182993599992246846197622806018586940960824812499707703407200235006250330376435395757240807360245145895448238973940748414130249165698642798758094515234629492123379833360060582377815656998861873479266942101526163937107816424422201955494796734174781894506437514751553369884508767256335322189421050651814494097369702888544056010606733").unwrap();
        let s = BigNumber::from_dec("83608735581956052060766602122241456047092927591272898317077507857903324472083195301035502442829713523495655160192410742120440247481077060649728889735943333622709039987090137325037494001551239812739256925595650405403616377574225590614582056226657979932825031688262428848508620618206304014287232713708048427099425348438343473342088258502098208531627321778163620061043269821806176268690486341352405206188888371253713940995260309747672937693391957731544958179245054768704977202091642139481745073141174316305851938990898215928942632876267309335084279137046749673230694376359278715909536580114502953378593787412958122696491").unwrap();
        let rms = BigNumber::from_dec("12002410972675035848706631786298987049295298281772467607461994087192649160666347028767622091944497528304565759377490497287538655369597530498218287879384450121974605678051982553150980093839175365101087722528582689341030912237571526676430070213849160857477430406424356131111577547636360346507596843363617776545054084329725294982409132506989181200852351104199115448152798956456818387289142907618956667090125913885442746763678284193811934837479547315881192351556311788630337391374089308234091189363160599574268958752271955343795665269131980077642259235693653829664040302092446308732796745472579352704501330580826351662240").unwrap();

        let mut r = HashMap::new();
        r.insert("name".to_string(), BigNumber::from_dec("55636937636844819812189791288187243913404055721058334520072574568680438360936320682628189506248931475232504868784141809162526982794777886937554791279646171992316154768489491205932973020390955775825994246509354890417980543491344959419958264200222321573290332068573840656874584148318471805081070819330139498643368112616125508016850665039138240007045133711819182960399913468566074586611076818097815310939823561848962949647054263397457358507697316036204724311688330058092618087260011626918624130336633163118234963001890740389604366796070789463043007475519162863457847133916866147682877703700016314519649272629853810342756").unwrap());
        r.insert("height".to_string(), BigNumber::from_dec("32014206266070285395118493698246684536543402308857326229844369749153998025988120078148833919040926762489849787174726278317154939222455553684674979640533728771798727404529140716275948809394914126446467274094766630776034154814466245563241594664595503357965283703581353868787640425189228669159837529621065262578472511140258233443082035493432067002995028424708181638248338655901732889892559561796172833245307347288440850886016760883963087954594369665160758244185860669353304463245326602784567519981372129418674907732019485821481470791951576038671383506105840172336020165255666872489673679749492975692222529386986002548508").unwrap());
        r.insert("age".to_string(), BigNumber::from_dec("5573886601587513393941805393558438475134278869721908377896820376573868172897985632537697650826768061917733566546691785934393119648542993289296693181509209448802827620254572500988956963540401872482092959068516484681223765164669694589952326903719257213107559712016680752042520470482095682948519795635218252370953948099226141669796718651544648226881826585169101432801215379161624527044414118535373924688074790569833168081423701512430033511620744395776217769497965549575153091462845485986562792539143519413414753164756782101386489471333391388468474082175228293592033872018644198196278046021752128670441648674265160079365").unwrap());
        r.insert("sex".to_string(), BigNumber::from_dec("44319112097252841415305877008967513656231862316131581238409828513703699212059952418622049664178569730633939544882861264006945675755509881864438312327074402062963599178195087536260752294006450133601248863198870283839961116512248865885787100775903023034879852152846002669257161013317472827548494571935048240800817870893700771269978535707078640961353407573194897812343272563394036737677668293122931520603798620428922052839619195929427039933665104815440476791376703125056734891504425929510493567119107731184250744646520780647416583157402277832961026300695141515177928171182043898138863324570665593349095177082259229019129").unwrap());

        let rctxt = BigNumber::from_dec("77129119521935975385795386930301402827628026853991528755303486255023263353142617098662225360498227999564663438861313570702364984107826653399214544314002820732458443871729599318191904265844432709910182014204478532265518566229953111318413830009256162339443077098917698777223763712267731802804425167444165048596271025553618253855465562660530445682078873631967934956107222619891473818051441942768338388425312823594456990243766677728754477201176089151138798586336262283249409402074987943625960454785501038059209634637204497573094989557296328178873844804605590768348774565136642366470996059740224170274762372312531963184654").unwrap();
        let z = BigNumber::from_dec("55164544925922114758373643773121488212903100773688663772257168750760838562077540114734459902014369305346806516101767509487128278169584105585138623374643674838487232408713159693511105298301789373764578281065365292802332455328842835614608027129883137292324033168485729810074426971615144489078436563295402449746541981155232849178606822309310700682675942602404109375598809372735287212196379089816519481644996930522775604565458855945697714216633192192613598668941671920105596720544264146532180330974698466182799108850159851058132630467033919618658033816306014912309279430724013987717126519405488323062369100827358874261055").unwrap();

        IssuerPrimaryPublicKey { n, s, rms, r, rctxt, z }
    }

    pub fn issuer_primary_private_key() -> IssuerPrimaryPrivateKey {
        let p = BigNumber::from_dec("157329491389375793912190594961134932804032426403110797476730107804356484516061051345332763141806005838436304922612495876180233509449197495032194146432047460167589034147716097417880503952139805241591622353828629383332869425029086898452227895418829799945650973848983901459733426212735979668835984691928193677469").unwrap();
        let q = BigNumber::from_dec("151323892648373196579515752826519683836764873607632072057591837216698622729557534035138587276594156320800768525825023728398410073692081011811496168877166664537052088207068061172594879398773872352920912390983199416927388688319207946493810449203702100559271439586753256728900713990097168484829574000438573295723").unwrap();

        IssuerPrimaryPrivateKey { p, q }
    }

    pub fn claim_attributes() -> ClaimAttributes {
        let mut attributes: HashSet<String> = HashSet::new();
        attributes.insert("name".to_string());
        attributes.insert("age".to_string());
        attributes.insert("height".to_string());
        attributes.insert("sex".to_string());

        ClaimAttributes { attrs: attributes }
    }

    pub fn issuer_revocation_public_key() -> IssuerRevocationPublicKey {
        IssuerRevocationPublicKey {
            g: PointG1::new().unwrap(),
            g_dash: PointG2::new().unwrap(),
            h: PointG1::new().unwrap(),
            h0: PointG1::new().unwrap(),
            h1: PointG1::new().unwrap(),
            h2: PointG1::new().unwrap(),
            htilde: PointG1::new().unwrap(),
            h_cap: PointG2::new().unwrap(),
            u: PointG2::new().unwrap(),
            pk: PointG1::new().unwrap(),
            y: PointG2::new().unwrap(),
        }
    }

    pub fn issuer_revocation_private_key() -> IssuerRevocationPrivateKey {
        IssuerRevocationPrivateKey {
            x: GroupOrderElement::new().unwrap(),
            sk: GroupOrderElement::new().unwrap()
        }
    }
}