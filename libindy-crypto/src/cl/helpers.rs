use bn::BigNumber;
use errors::IndyCryptoError;
use pair::GroupOrderElement;

use super::constants::*;
use cl::*;

use std::cmp::max;
use std::collections::{HashMap, HashSet};

#[allow(dead_code)] //FIXME
pub enum ByteOrder {
    Big,
    Little
}

#[cfg(not(test))]
pub fn bn_rand(size: usize) -> Result<BigNumber, IndyCryptoError> {
    BigNumber::rand(size)
}

#[cfg(test)]
pub fn bn_rand(size: usize) -> Result<BigNumber, IndyCryptoError> {
    match size {
        LARGE_NONCE => Ok(BigNumber::from_dec("526193306511429638192053")?),
        LARGE_MASTER_SECRET => Ok(BigNumber::from_dec("21578029250517794450984707538122537192839006240802068037273983354680998203845")?),
        LARGE_ETILDE => Ok(BigNumber::from_dec("162083298053730499878539835193560156486733663622707027216327685550780519347628838870322946818623352681120371349972731968874009673965057322")?),
        LARGE_UTILDE => Ok(BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338")?),
        LARGE_RTILDE => Ok(BigNumber::from_dec("7575191721496255329790454166600075461811327744716122725414003704363002865687003988444075479817517968742651133011723131465916075452356777073568785406106174349810313776328792235352103470770562831584011847")?),
        LARGE_PRIME => Ok(BigNumber::from_dec("67940925789970108743024738273926421512152745397724199848594503731042154269417576665420030681245389493783225644817826683796657351721363490290016166310023506339911751676800452438014771736117676826911321621579680668201191205819012441197794443970687648330757835198888257781967404396196813475280544039772512800509")?),
        LARGE_VPRIME => Ok(BigNumber::from_dec("1921424195886158938744777125021406748763985122590553448255822306242766229793715475428833504725487921105078008192433858897449555181018215580757557939320974389877538474522876366787859030586130885280724299566241892352485632499791646228580480458657305087762181033556428779333220803819945703716249441372790689501824842594015722727389764537806761583087605402039968357991056253519683582539703803574767702877615632257021995763302779502949501243649740921598491994352181379637769188829653918416991301420900374928589100515793950374255826572066003334385555085983157359122061582085202490537551988700484875690854200826784921400257387622318582276996322436")?),
        LARGE_VPRIME_PRIME => Ok(BigNumber::from_dec("6620937836014079781509458870800001917950459774302786434315639456568768602266735503527631640833663968617512880802104566048179854406925811731340920442625764155409951969854303612644121780700879432308016935250101960876405664503219252820761501606507817390189252221968804450207070282033815280889897882643560437257171838117793768660731379360330750300543760457608638753190279419951706206819943151918535286779337023708838891906829360439545064730288538139152367417882097349210427894031568623898916625312124319876670702064561291393993815290033742478045530118808274555627855247830659187691067893683525651333064738899779446324124393932782261375663033826174482213348732912255948009062641783238846143256448824091556005023241191311617076266099622843011796402959351074671886795391490945230966123230485475995208322766090290573654498779155")?),
        LARGE_VTILDE => Ok(BigNumber::from_dec("241132863422049783305938184561371219250127488499746090592218003869595412171810997360214885239402274273939963489505434726467041932541499422544431299362364797699330176612923593931231233163363211565697860685967381420219969754969010598350387336530924879073366177641099382257720898488467175132844984811431059686249020737675861448309521855120928434488546976081485578773933300425198911646071284164884533755653094354378714645351464093907890440922615599556866061098147921890790915215227463991346847803620736586839786386846961213073783437136210912924729098636427160258710930323242639624389905049896225019051952864864612421360643655700799102439682797806477476049234033513929028472955119936073490401848509891547105031112859155855833089675654686301183778056755431562224990888545742379494795601542482680006851305864539769704029428620446639445284011289708313620219638324467338840766574612783533920114892847440641473989502440960354573501")?),
        LARGE_ALPHATILDE => Ok(BigNumber::from_dec("15019832071918025992746443764672619814038193111378331515587108416842661492145380306078894142589602719572721868876278167686578705125701790763532708415180504799241968357487349133908918935916667492626745934151420791943681376124817051308074507483664691464171654649868050938558535412658082031636255658721308264295197092495486870266555635348911182100181878388728256154149188718706253259396012667950509304959158288841789791483411208523521415447630365867367726300467842829858413745535144815825801952910447948288047749122728907853947789264574578039991615261320141035427325207080621563365816477359968627596441227854436137047681372373555472236147836722255880181214889123172703767379416198854131024048095499109158532300492176958443747616386425935907770015072924926418668194296922541290395990933578000312885508514814484100785527174742772860178035596639")?),
        _ => {
            debug!("Uncovered case: {}", size);
            Ok(BigNumber::new()?)
        }
    }
}

pub fn encode_attribute(attribute: &str, byte_order: ByteOrder) -> Result<BigNumber, IndyCryptoError> {
    let mut result = BigNumber::hash(attribute.as_bytes())?;
    let index = result.iter().position(|&value| value == 0);

    if let Some(position) = index {
        result.truncate(position); //FIXME logical error 0x00 may be in any position inside Vec<u8>
    }

    if let ByteOrder::Little = byte_order {
        result.reverse();
    }

    Ok(BigNumber::from_bytes(&result)?)
}

#[cfg(test)]
pub fn generate_v_prime_prime() -> Result<BigNumber, IndyCryptoError> {
    BigNumber::from_dec("6620937836014079781509458870800001917950459774302786434315639456568768602266735503527631640833663968617512880802104566048179854406925811731340920442625764155409951969854303612644125623549271204625894424804352003689903192473464433927658013251120302922648839652919662117216521257876025436906282750361355336367533874548955283776610021309110505377492806210342214471251451681722267655419075635703240258044336607001296052867746675049720589092355650996711033859489737240617860392914314205277920274997312351322125481593636904917159990500837822414761512231315313922792934655437808723096823124948039695324591344458785345326611693414625458359651738188933757751726392220092781991665483583988703321457480411992304516676385323318285847376271589157730040526123521479652961899368891914982347831632139045838008837541334927738208491424027")
}

#[cfg(not(test))]
pub fn generate_v_prime_prime() -> Result<BigNumber, IndyCryptoError> {
    let a = bn_rand(LARGE_VPRIME_PRIME)?;

    let b = BigNumber::from_u32(2)?
        .exp(&BigNumber::from_u32(LARGE_VPRIME_PRIME - 1)?, None)?;

    let v_prime_prime = bitwise_or_big_int(&a, &b)?;
    Ok(v_prime_prime)
}

#[cfg(test)]
pub fn generate_prime_in_range(start: &BigNumber, end: &BigNumber) -> Result<BigNumber, IndyCryptoError> {
    BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930201588264091397308910346117473868881")
}

#[cfg(not(test))]
pub fn generate_prime_in_range(start: &BigNumber, end: &BigNumber) -> Result<BigNumber, IndyCryptoError> {
    BigNumber::generate_prime_in_range(start, end)
}

#[cfg(not(test))]
pub fn generate_safe_prime(size: usize) -> Result<BigNumber, IndyCryptoError> {
    BigNumber::generate_safe_prime(size)
}

#[cfg(test)]
pub fn generate_safe_prime(size: usize) -> Result<BigNumber, IndyCryptoError> {
    match size {
        LARGE_PRIME => Ok(BigNumber::from_dec("298425477551432359319017298068281828134535746771300905126443720735756534287270383542467183175737460443806952398210045827718115111810885752229119677470711305345901926067944629292942471551423868488963517954094239606951758940767987427212463600313901180668176172283994206392965011112962119159458674722785709556623")?),
        _ => {
            debug!("Uncovered case: {}", size);
            Ok(BigNumber::new()?)
        }
    }
}

#[cfg(test)]
pub fn gen_x(_p: &BigNumber, _q: &BigNumber) -> Result<BigNumber, IndyCryptoError> {
    Ok(BigNumber::from_dec("21756443327382027172985704617047967597993694788495380290694324827806324727974811069286883097008098972826137846700650885182803802394920367284736320514617598740869006348763668941791139304299497512001555851506177534398138662287596439312757685115968057647052806345903116050638193978301573172649243964671896070438965753820826200974052042958554415386005813811429117062833340444950490735389201033755889815382997617514953672362380638953231325483081104074039069074312082459855104868061153181218462493120741835250281211598658590317583724763093211076383033803581749876979865965366178002285968278439178209181121479879436785731938")?)
}

#[cfg(not(test))]
pub fn gen_x(p: &BigNumber, q: &BigNumber) -> Result<BigNumber, IndyCryptoError> {
    let mut result = p
        .mul(&q, None)?
        .sub_word(3)?
        .rand_range()?;

    result.add_word(2)?;
    Ok(result)
}

#[cfg(not(test))]
pub fn random_qr(n: &BigNumber) -> Result<BigNumber, IndyCryptoError> {
    let random = n
        .rand_range()?
        .sqr(None)?
        .modulus(&n, None)?;
    Ok(random)
}

#[cfg(test)]
pub fn random_qr(_n: &BigNumber) -> Result<BigNumber, IndyCryptoError> {
    Ok(BigNumber::from_dec("64684820421150545443421261645532741305438158267230326415141505826951816460650437611148133267480407958360035501128469885271549378871140475869904030424615175830170939416512594291641188403335834762737251794282186335118831803135149622404791467775422384378569231649224208728902565541796896860352464500717052768431523703881746487372385032277847026560711719065512366600220045978358915680277126661923892187090579302197390903902744925313826817940566429968987709582805451008234648959429651259809188953915675063700676546393568304468609062443048457324721450190021552656280473128156273976008799243162970386898307404395608179975243")?)
}

pub fn bitwise_or_big_int(a: &BigNumber, b: &BigNumber) -> Result<BigNumber, IndyCryptoError> {
    let significant_bits = max(a.num_bits()?, b.num_bits()?);
    let mut result = BigNumber::new()?;
    for i in 0..significant_bits {
        if a.is_bit_set(i)? || b.is_bit_set(i)? {
            result.set_bit(i)?;
        }
    }
    Ok(result)
}

//Byte order: Little
pub fn transform_u32_to_array_of_u8(x: u32) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    for i in (0..4).rev() {
        result.push((x >> i * 8) as u8);
    }
    result
}

pub fn get_hash_as_int(nums: &mut Vec<Vec<u8>>) -> Result<BigNumber, IndyCryptoError> {
    nums.sort();

    let mut hashed_array: Vec<u8> = BigNumber::hash_array(&nums)?;
    hashed_array.reverse();

    BigNumber::from_bytes(&hashed_array[..])
}

pub fn get_mtilde(unrevealed_attrs: &HashSet<String>)
                  -> Result<HashMap<String, BigNumber>, IndyCryptoError> {
    let mut mtilde: HashMap<String, BigNumber> = HashMap::new();

    for attr in unrevealed_attrs.iter() {
        mtilde.insert(attr.clone(), bn_rand(LARGE_MVECT)?);
    }
    Ok(mtilde)
}

pub fn calc_teq(pk: &IssuerPrimaryPublicKey, a_prime: &BigNumber, e: &BigNumber, v: &BigNumber,
                mtilde: &HashMap<String, BigNumber>, m1tilde: &BigNumber, m2tilde: &BigNumber,
                unrevealed_attrs: &HashSet<String>) -> Result<BigNumber, IndyCryptoError> {
    let mut ctx = BigNumber::new_context()?;
    let mut result: BigNumber = BigNumber::from_dec("1")?;

    for k in unrevealed_attrs.iter() {
        let cur_r = pk.r.get(k)
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in pk.r", k)))?;
        let cur_m = mtilde.get(k)
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in mtilde", k)))?;

        result = cur_r
            .mod_exp(&cur_m, &pk.n, Some(&mut ctx))?
            .mul(&result, Some(&mut ctx))?;
    }

    result = pk.rms
        .mod_exp(&m1tilde, &pk.n, Some(&mut ctx))?
        .mul(&result, Some(&mut ctx))?;

    result = pk.rctxt
        .mod_exp(&m2tilde, &pk.n, Some(&mut ctx))?
        .mul(&result, Some(&mut ctx))?;

    result = a_prime
        .mod_exp(&e, &pk.n, Some(&mut ctx))?
        .mul(&result, Some(&mut ctx))?;

    result = pk.s
        .mod_exp(&v, &pk.n, Some(&mut ctx))?
        .mul(&result, Some(&mut ctx))?
        .modulus(&pk.n, Some(&mut ctx))?;

    Ok(result)
}

pub fn calc_tge(pk: &IssuerPrimaryPublicKey, u: &HashMap<String, BigNumber>, r: &HashMap<String, BigNumber>,
                mj: &BigNumber, alpha: &BigNumber, t: &HashMap<String, BigNumber>)
                -> Result<Vec<BigNumber>, IndyCryptoError> {
    let mut tau_list: Vec<BigNumber> = Vec::new();
    let mut ctx = BigNumber::new_context()?;

    for i in 0..ITERATION {
        let cur_u = u.get(&i.to_string())
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in u", i)))?;
        let cur_r = r.get(&i.to_string())
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in r", i)))?;

        let t_tau = pk.z
            .mod_exp(&cur_u, &pk.n, Some(&mut ctx))?
            .mul(
                &pk.s.mod_exp(&cur_r, &pk.n, Some(&mut ctx))?,
                Some(&mut ctx)
            )?
            .modulus(&pk.n, Some(&mut ctx))?;

        tau_list.push(t_tau);
    }

    let delta = r.get("DELTA")
        .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in r", "DELTA")))?;


    let t_tau = pk.z
        .mod_exp(&mj, &pk.n, Some(&mut ctx))?
        .mul(
            &pk.s.mod_exp(&delta, &pk.n, Some(&mut ctx))?,
            Some(&mut ctx)
        )?
        .modulus(&pk.n, Some(&mut ctx))?;

    tau_list.push(t_tau);

    let mut q: BigNumber = BigNumber::from_dec("1")?;

    for i in 0..ITERATION {
        let cur_t = t.get(&i.to_string())
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in t", i)))?;
        let cur_u = u.get(&i.to_string())
            .ok_or(IndyCryptoError::InvalidStructure(format!("Value by key '{}' not found in u", i)))?;

        q = cur_t
            .mod_exp(&cur_u, &pk.n, Some(&mut ctx))?
            .mul(&q, Some(&mut ctx))?;
    }

    q = pk.s
        .mod_exp(&alpha, &pk.n, Some(&mut ctx))?
        .mul(&q, Some(&mut ctx))?
        .modulus(&pk.n, Some(&mut ctx))?;

    tau_list.push(q);

    Ok(tau_list)
}

fn largest_square_less_than(delta: usize) -> usize {
    (delta as f64).sqrt().floor() as usize
}

pub fn four_squares(delta: i32) -> Result<HashMap<String, BigNumber>, IndyCryptoError> {
    if delta < 0 {
        return Err(IndyCryptoError::InvalidStructure(format!("Cannot get the four squares for delta {} ", delta)));
    }

    let d = delta as usize;
    let mut roots: [usize; 4] = [largest_square_less_than(d), 0, 0, 0];

    'outer: for i in (1..roots[0] + 1).rev() {
        roots[0] = i;
        if d == roots[0].pow(2) {
            roots[1] = 0;
            roots[2] = 0;
            roots[3] = 0;
            break 'outer;
        }
        roots[1] = largest_square_less_than(d - roots[0].pow(2));
        for j in (1..roots[1] + 1).rev() {
            roots[1] = j;
            if d == roots[0].pow(2) + roots[1].pow(2) {
                roots[2] = 0;
                roots[3] = 0;
                break 'outer;
            }
            roots[2] = largest_square_less_than(d - roots[0].pow(2) - roots[1].pow(2));
            for k in (1..roots[2] + 1).rev() {
                roots[2] = k;
                if d == roots[0].pow(2) + roots[1].pow(2) + roots[2].pow(2) {
                    roots[3] = 0;
                    break 'outer;
                }
                roots[3] = largest_square_less_than(d - roots[0].pow(2) - roots[1].pow(2) - roots[2].pow(2));
                if d == roots[0].pow(2) + roots[1].pow(2) + roots[2].pow(2) + roots[3].pow(2) {
                    break 'outer;
                }
            }
        }
    }

    let mut res: HashMap<String, BigNumber> = HashMap::new();
    res.insert("0".to_string(), BigNumber::from_dec(&roots[0].to_string()[..])?);
    res.insert("1".to_string(), BigNumber::from_dec(&roots[1].to_string()[..])?);
    res.insert("2".to_string(), BigNumber::from_dec(&roots[2].to_string()[..])?);
    res.insert("3".to_string(), BigNumber::from_dec(&roots[3].to_string()[..])?);

    Ok(res)
}

pub fn group_element_to_bignum(el: &GroupOrderElement) -> Result<BigNumber, IndyCryptoError> {
    Ok(BigNumber::from_bytes(&el.to_bytes()?)?)
}

pub fn bignum_to_group_element(num: &BigNumber) -> Result<GroupOrderElement, IndyCryptoError> {
    Ok(GroupOrderElement::from_bytes(&num.to_bytes()?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{issuer, prover};

    #[test]
    fn encode_attribute_works() {
        let test_str = "5435";
        let test_answer = "83761840706354868391674207739241454863743470852830526299004654280720761327142";
        assert_eq!(test_answer, encode_attribute(test_str, ByteOrder::Big).unwrap().to_dec().unwrap());
    }

    #[test]
    fn generate_v_prime_prime_works() {
        let result = BigNumber::from_dec("6620937836014079781509458870800001917950459774302786434315639456568768602266735503527631640833663968617512880802104566048179854406925811731340920442625764155409951969854303612644125623549271204625894424804352003689903192473464433927658013251120302922648839652919662117216521257876025436906282750361355336367533874548955283776610021309110505377492806210342214471251451681722267655419075635703240258044336607001296052867746675049720589092355650996711033859489737240617860392914314205277920274997312351322125481593636904917159990500837822414761512231315313922792934655437808723096823124948039695324591344458785345326611693414625458359651738188933757751726392220092781991665483583988703321457480411992304516676385323318285847376271589157730040526123521479652961899368891914982347831632139045838008837541334927738208491424027").unwrap();
        assert_eq!(generate_v_prime_prime().unwrap(), result);
    }

    #[test]
    fn bitwise_or_big_int_works() {
        let a = BigNumber::from_dec("778378032744961463933002553964902776831187587689736807008034459507677878432383414623740074");
        let b = BigNumber::from_dec("1018517988167243043134222844204689080525734196832968125318070224677190649881668353091698688");
        let result = BigNumber::from_dec("1796896020912204507067225398169591857356921784522704932326104684184868528314051767715438762");
        assert_eq!(result.unwrap(), bitwise_or_big_int(&a.unwrap(), &b.unwrap()).unwrap());
    }

    #[test]
    fn get_hash_as_int_works() {
        let mut nums = vec![
            BigNumber::from_hex("ff9d2eedfee9cffd9ef6dbffedff3fcbef4caecb9bffe79bfa94d3fdf6abfbff").unwrap().to_bytes().unwrap(),
            BigNumber::from_hex("ff9d2eedfee9cffd9ef6dbffedff3fcbef4caecb9bffe79bfa9168615ccbc546").unwrap().to_bytes().unwrap()
        ];
        let res = get_hash_as_int(&mut nums);

        assert!(res.is_ok());
        assert_eq!("9E2A0653691B96A9B55B3D1133F9FEE2F2C37B848DBADF2F70DFFFE9E47C5A5D", res.unwrap().to_hex().unwrap());
    }

    #[test]
    fn four_squares_works() {
        let res = four_squares(107 as i32);
        let res_data = res.unwrap();

        assert_eq!("9".to_string(), res_data.get("0").unwrap().to_dec().unwrap());
        assert_eq!("5".to_string(), res_data.get("1").unwrap().to_dec().unwrap());
        assert_eq!("1".to_string(), res_data.get("2").unwrap().to_dec().unwrap());
        assert_eq!("0".to_string(), res_data.get("3").unwrap().to_dec().unwrap());

        let res = four_squares(112 as i32);
        let res_data = res.unwrap();

        assert_eq!("10".to_string(), res_data.get("0").unwrap().to_dec().unwrap());
        assert_eq!("2".to_string(), res_data.get("1").unwrap().to_dec().unwrap());
        assert_eq!("2".to_string(), res_data.get("2").unwrap().to_dec().unwrap());
        assert_eq!("2".to_string(), res_data.get("3").unwrap().to_dec().unwrap());


        let res = four_squares(253 as i32);
        let res_data = res.unwrap();

        assert_eq!("14".to_string(), res_data.get("0").unwrap().to_dec().unwrap());
        assert_eq!("7".to_string(), res_data.get("1").unwrap().to_dec().unwrap());
        assert_eq!("2".to_string(), res_data.get("2").unwrap().to_dec().unwrap());
        assert_eq!("2".to_string(), res_data.get("3").unwrap().to_dec().unwrap());

        let res = four_squares(1506099439 as i32);
        let res_data = res.unwrap();

        assert_eq!("38807".to_string(), res_data.get("0").unwrap().to_dec().unwrap());
        assert_eq!("337".to_string(), res_data.get("1").unwrap().to_dec().unwrap());
        assert_eq!("50".to_string(), res_data.get("2").unwrap().to_dec().unwrap());
        assert_eq!("11".to_string(), res_data.get("3").unwrap().to_dec().unwrap());
    }

    #[test]
    fn transform_u32_to_array_of_u8_works() {
        let int = 0x74BA7445;
        let answer = vec![0x74, 0xBA, 0x74, 0x45];
        assert_eq!(transform_u32_to_array_of_u8(int), answer)
    }

    #[test]
    fn test_encode_attribute_fail_simple_collision_on_internal_truncate() {
//        let ea3079 = encode_attribute("3079", ByteOrder::Big).unwrap();
//        let ea6440 = encode_attribute("6440", ByteOrder::Big).unwrap();
//        println!("{:?}", ea3079);
//        println!("{:?}", ea6440);
//        assert_ne!(ea3079, ea6440);

        /* Collision generator
        let mut arr: [i32; 256] = [0; 256];
        let i: usize = 0;
        loop {
            let v = BigNumber::hash(i.to_string().as_bytes()).unwrap();
            if v[1] == 0 {
                let v0 = v[0] as usize;
                if v0 != 0 && arr[v0] != 0 {
                    println!("{} {}", arr[v0], i);
                    return;
                }
                arr[v0] = i;
            }
        }
        */
    }

    #[test]
    fn calc_tge_works() {
        let proof = prover::mocks::ge_proof();
        let pk = issuer::mocks::issuer_primary_public_key();

        let res = calc_tge(&pk, &proof.u, &proof.r, &proof.mj,
                           &proof.alpha, &proof.t);

        assert!(res.is_ok());

        let res_data = res.unwrap();

        assert_eq!("8322127546989896387275966956717489392954820699417338251786556649101493429318430531199001069911562901306259435656932382677128954011982805798558006591721833\
        5605431924740621290790822867526996426754498647749364551568573632825130411767933496263889341279557543916007550669691321376657209328075522462343797812161210811077590453\
        2120173633123501910313442097856448826420434464755676360215985046345722091638733825930359023698405153911155327052509255848703950056172211486532920054779856058690601785\
        53020437624967613113731545390424297704583135328648719191754311224160798780349254409651297547530341660850249766004830649980982560982", res_data[1].to_dec().unwrap());

        assert_eq!("482750782059660412101615177232611888550755766507419936401511863067591296049923125980377336564481051028377064316923299158582211115331245992257386978849974734\
        128707465753053942755569336068548526953297525768147337354454557362519747980499932799921159907032930547556911458927682401494687841514706231212097433415831739325516526560\
        075527230247420132195414890013155207914292568288968476400452361612498414907131296781811794942616488648114731129265573497484044597921079462222609784783074511383869086532\
        68952390850248707502986344513346138642945213485581168943420984097835878425842495014654784179029992889576447472900665689557557", res_data[4].to_dec().unwrap());

        assert_eq!("3613871845492340617127219520158714980977937944164917178523895686065055379712679234655322296868824037422063290363828203927993886987618536511052116881807519513\
        0313571087877672608805322827152915884789569921083851953757287437838504629826969185328421789445446058402932602038884346108127772134818624626778105440936581477856573966975\
        9956922128854394993124728622435188333767509375096357851424539937526069133692189910988941581668627867472306963240915206151560886585841801560896326133720075449399566243732\
        56982972478404916002854030409057179140658509128394260362346825950255589626617227440758523178850898009163909088360326059196", res_data[5].to_dec().unwrap());
    }

    #[test]
    fn calc_teq_works() {
        let proof = prover::mocks::eq_proof();
        let pk = issuer::mocks::issuer_primary_public_key();
        let unrevealed_attrs = prover::mocks::unrevealed_attrs();

        let res = calc_teq(&pk, &proof.a_prime, &proof.e, &proof.v,
                           &proof.m, &proof.m1, &proof.m2, &unrevealed_attrs
        );

        assert!(res.is_ok());
        assert_eq!("381926765932188241543638166295836414884226639539118718065769943239416177756577713506562746090966084931668714212852500894527124357552891493284799254325180\
        550618350619463078448090619550539984321896578172169128335147589428402324781718901869549112532798652601463746685045212133193174381490524514911738520011287083602890709\
        48079960772659047566794177011062557693924377595447897825427041909910147539820909799749276641294365433984505662572279688664855362124712265751122800305172874190132079584439370708309080764145976583745638279272393589372240070072863129023320369502403543275214865690334236255622586065544807114732455123529", res.unwrap().to_dec().unwrap());
    }
}