use super::constants::*;
use bn::{BigNumber, BIGNUMBER_1};
use cl::*;
use errors::prelude::*;
use pair::GroupOrderElement;

use std::cmp::max;
use std::collections::{HashMap, HashSet};

#[cfg(test)]
use std::cell::RefCell;

#[derive(Debug, Copy, Clone)]
#[allow(dead_code)] //FIXME
pub enum ByteOrder {
    Big,
    Little,
}

#[cfg(test)]
thread_local! {
  pub static USE_MOCKS: RefCell<bool> = RefCell::new(false);
}

#[cfg(test)]
pub struct MockHelper {}

#[cfg(test)]
impl MockHelper {
    pub fn inject() {
        USE_MOCKS.with(|use_mocks| {
            *use_mocks.borrow_mut() = true;
        });
    }

    pub fn is_injected() -> bool {
        USE_MOCKS.with(|use_mocks| {
            return *use_mocks.borrow();
        })
    }
}

#[cfg(test)]
pub fn bn_rand(size: usize) -> UrsaCryptoResult<BigNumber> {
    if MockHelper::is_injected() {
        return match size {
            LARGE_NONCE => Ok(BigNumber::from_dec("526193306511429638192053")?),
            LARGE_MASTER_SECRET => Ok(BigNumber::from_dec("21578029250517794450984707538122537192839006240802068037273983354680998203845")?),
            LARGE_ETILDE => Ok(BigNumber::from_dec("162083298053730499878539835193560156486733663622707027216327685550780519347628838870322946818623352681120371349972731968874009673965057322")?),
            LARGE_UTILDE => Ok(BigNumber::from_dec("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338")?),
            LARGE_RTILDE => Ok(BigNumber::from_dec("7575191721496255329790454166600075461811327744716122725414003704363002865687003988444075479817517968742651133011723131465916075452356777073568785406106174349810313776328792235352103470770562831584011847")?),
            LARGE_PRIME => Ok(BigNumber::from_dec("67940925789970108743024738273926421512152745397724199848594503731042154269417576665420030681245389493783225644817826683796657351721363490290016166310023506339911751676800452438014771736117676826911321621579680668201191205819012441197794443970687648330757835198888257781967404396196813475280544039772512800509")?),
            LARGE_VPRIME => Ok(BigNumber::from_dec("35131625843806290832574870589259287147303302356085937450138681169270844305658441640899780357851554390281352797472151859633451190372182905767740276000477099644043795107449461869975792759973231599572009337886283219344284767785705740629929916685684025616389621432096690068102576167647117576924865030253290356476886389376786906469624913865400296221181743871195998667521041628188272244376790322856843509187067488962831880868979749045372839549034465343690176440012266969614156191820420452812733264350018673445974099278245215963827842041818557926829011513408602244298030173493359464182527821314118075880620818817455331127028576670474022443879858290")?),
            LARGE_VPRIME_PRIME => Ok(BigNumber::from_dec("6620937836014079781509458870800001917950459774302786434315639456568768602266735503527631640833663968617512880802104566048179854406925811731340920442625764155409951969854303612644121780700879432308016935250101960876405664503219252820761501606507817390189252221968804450207070282033815280889897882643560437257171838117793768660731379360330750300543760457608638753190279419951706206819943151918535286779337023708838891906829360439545064730288538139152367417882097349210427894031568623898916625312124319876670702064561291393993815290033742478045530118808274555627855247830659187691067893683525651333064738899779446324124393932782261375663033826174482213348732912255948009062641783238846143256448824091556005023241191311617076266099622843011796402959351074671886795391490945230966123230485475995208322766090290573654498779155")?),
            LARGE_VTILDE => Ok(BigNumber::from_dec("241132863422049783305938184561371219250127488499746090592218003869595412171810997360214885239402274273939963489505434726467041932541499422544431299362364797699330176612923593931231233163363211565697860685967381420219969754969010598350387336530924879073366177641099382257720898488467175132844984811431059686249020737675861448309521855120928434488546976081485578773933300425198911646071284164884533755653094354378714645351464093907890440922615599556866061098147921890790915215227463991346847803620736586839786386846961213073783437136210912924729098636427160258710930323242639624389905049896225019051952864864612421360643655700799102439682797806477476049234033513929028472955119936073490401848509891547105031112859155855833089675654686301183778056755431562224990888545742379494795601542482680006851305864539769704029428620446639445284011289708313620219638324467338840766574612783533920114892847440641473989502440960354573501")?),
            LARGE_ALPHATILDE => Ok(BigNumber::from_dec("15019832071918025992746443764672619814038193111378331515587108416842661492145380306078894142589602719572721868876278167686578705125701790763532708415180504799241968357487349133908918935916667492626745934151420791943681376124817051308074507483664691464171654649868050938558535412658082031636255658721308264295197092495486870266555635348911182100181878388728256154149188718706253259396012667950509304959158288841789791483411208523521415447630365867367726300467842829858413745535144815825801952910447948288047749122728907853947789264574578039991615261320141035427325207080621563365816477359968627596441227854436137047681372373555472236147836722255880181214889123172703767379416198854131024048095499109158532300492176958443747616386425935907770015072924926418668194296922541290395990933578000312885508514814484100785527174742772860178035596639")?),
            LARGE_MTILDE => Ok(BigNumber::from_dec("10838856720335086997514319917662253919386665513436731291879876033663916796845905483096428365331456535021555195228705107240745433186472885370026158281452488750543836812854534798015")?),
            LARGE_VPRIME_TILDE => Ok(BigNumber::from_dec("270298478417095479220290594584939047494346369147130625108591856876117642868384581126125783954421760120577629749641226846121717203028533346759100110785712141640560127342213391944485939721690475622269446352076925746031688944474239002873223246082659545835862203324527060373195507623970150203119643721810930015338375780971579576793925694267571879407191707981773572210444428542162229763930927238351508059716880136045903789030790652455164621105198032833923907461267590398142725202091851402685994954911410422001894367996342090912801956301144967233896238762263421366525202483740826305755322465437271844697666681531541885251237239852498850301814902435663338193987341790780575615266435607053286091159594260827197490278550174978")?),
            _ => {
                panic!("Uncovered case: {}", size);
            }
        };
    }
    _bn_rand(size)
}

#[cfg(not(test))]
pub fn bn_rand(size: usize) -> UrsaCryptoResult<BigNumber> {
    _bn_rand(size)
}

pub fn _bn_rand(size: usize) -> UrsaCryptoResult<BigNumber> {
    trace!("Helpers::bn_rand: >>> size:: {:?}", size);

    let res = BigNumber::rand(size)?;

    trace!("Helpers::bn_rand: <<< res: {:?}", res);

    Ok(res)
}

#[cfg(test)]
pub fn bn_rand_range(_bn: &BigNumber) -> UrsaCryptoResult<BigNumber> {
    BigNumber::from_dec("6355086599653879826316700099928903465759924565682653297540990486160410136991969646604012568191576052570982028627086748382054319397088948628665022843282950799083156383516421449932691541760677147872377591267323656783938723945915297920233965100454678367417561768144216659060966399182536425206811620699453941460281449071103436526749575365638254352831881150836568830779323361579590121888491911166612382507532248659384681554612887580241255323056245170208421770819447066550669981130450421507202133758209950007973511221223647764045990479619451838104977691662868482078262695232806059726002249095643117917855811948311863670130")
}

#[cfg(not(test))]
pub fn bn_rand_range(bn: &BigNumber) -> UrsaCryptoResult<BigNumber> {
    _bn_rand_range(bn)
}

pub fn _bn_rand_range(bn: &BigNumber) -> UrsaCryptoResult<BigNumber> {
    trace!("Helpers::bn_rand_range: >>> bn:: {:?}", bn);

    let res = bn.rand_range()?;

    trace!("Helpers::bn_rand_range: <<< res: {:?}", res);

    Ok(res)
}

pub fn encode_attribute(attribute: &str, byte_order: ByteOrder) -> UrsaCryptoResult<BigNumber> {
    trace!(
        "Helpers::encode_attribute: >>> attribute: {:?}, byte_order: {:?}",
        attribute,
        byte_order
    );
    let mut result = BigNumber::hash(attribute.as_bytes())?;

    if let ByteOrder::Little = byte_order {
        result.reverse();
    }

    let encoded_attribute = BigNumber::from_bytes(&result)?;

    trace!(
        "Helpers::encode_attribute: <<< encoded_attribute: {:?}",
        encoded_attribute
    );

    Ok(encoded_attribute)
}

#[cfg(test)]
pub fn generate_v_prime_prime() -> UrsaCryptoResult<BigNumber> {
    if MockHelper::is_injected() {
        return BigNumber::from_dec("6620937836014079781509458870800001917950459774302786434315639456568768602266735503527631640833663968617512880802104566048179854406925811731340920442625764155409951969854303612644125623549271204625894424804352003689903192473464433927658013251120302922648839652919662117216521257876025436906282750361355336367533874548955283776610021309110505377492806210342214471251451681722267655419075635703240258044336607001296052867746675049720589092355650996711033859489737240617860392914314205277920274997312351322125481593636904917159990500837822414761512231315313922792934655437808723096823124948039695324591344458785345326611693414625458359651738188933757751726392220092781991665483583988703321457480411992304516676385323318285847376271589157730040526123521479652961899368891914982347831632139045838008837541334927738208491424027");
    }
    _generate_v_prime_prime()
}

#[cfg(not(test))]
pub fn generate_v_prime_prime() -> UrsaCryptoResult<BigNumber> {
    _generate_v_prime_prime()
}

pub fn _generate_v_prime_prime() -> UrsaCryptoResult<BigNumber> {
    trace!("Helpers::generate_v_prime_prime: >>>");

    let a = bn_rand(LARGE_VPRIME_PRIME)?;

    let v_prime_prime = bitwise_or_big_int(&a, &LARGE_VPRIME_PRIME_VALUE)?;

    trace!(
        "Helpers::generate_v_prime_prime: <<< v_prime_prime: {:?}",
        secret!(&v_prime_prime)
    );

    Ok(v_prime_prime)
}

#[cfg(test)]
pub fn generate_prime_in_range(start: &BigNumber, end: &BigNumber) -> UrsaCryptoResult<BigNumber> {
    if MockHelper::is_injected() {
        return BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930201588264091397308910346117473868881");
    }
    _generate_prime_in_range(start, end)
}

#[cfg(not(test))]
pub fn generate_prime_in_range(start: &BigNumber, end: &BigNumber) -> UrsaCryptoResult<BigNumber> {
    _generate_prime_in_range(start, end)
}

pub fn _generate_prime_in_range(start: &BigNumber, end: &BigNumber) -> UrsaCryptoResult<BigNumber> {
    trace!(
        "Helpers::generate_prime_in_range: >>> start: {:?}, end: {:?}",
        secret!(start),
        secret!(end)
    );

    let prime = BigNumber::generate_prime_in_range(start, end)?;

    trace!(
        "Helpers::generate_prime_in_range: <<< prime: {:?}",
        secret!(&prime)
    );

    Ok(prime)
}

#[cfg(test)]
pub fn generate_safe_prime(size: usize) -> UrsaCryptoResult<BigNumber> {
    if MockHelper::is_injected() {
        match size {
            LARGE_PRIME => return Ok(BigNumber::from_dec("298425477551432359319017298068281828134535746771300905126443720735756534287270383542467183175737460443806952398210045827718115111810885752229119677470711305345901926067944629292942471551423868488963517954094239606951758940767987427212463600313901180668176172283994206392965011112962119159458674722785709556623")?),
            _ => {
                panic!("Uncovered case: {}", size);
            }
        }
    }
    _generate_safe_prime(size)
}

#[cfg(not(test))]
pub fn generate_safe_prime(size: usize) -> UrsaCryptoResult<BigNumber> {
    _generate_safe_prime(size)
}

pub fn _generate_safe_prime(size: usize) -> UrsaCryptoResult<BigNumber> {
    trace!("Helpers::generate_safe_prime: >>> size: {:?}", size);

    let safe_prime = BigNumber::generate_safe_prime(size)?;

    trace!(
        "Helpers::generate_safe_prime: <<< safe_prime: {:?}",
        secret!(&safe_prime)
    );

    Ok(safe_prime)
}

#[cfg(test)]
pub fn gen_x(p: &BigNumber, q: &BigNumber) -> UrsaCryptoResult<BigNumber> {
    if MockHelper::is_injected() {
        return BigNumber::from_dec("21756443327382027172985704617047967597993694788495380290694324827806324727974811069286883097008098972826137846700650885182803802394920367284736320514617598740869006348763668941791139304299497512001555851506177534398138662287596439312757685115968057647052806345903116050638193978301573172649243964671896070438965753820826200974052042958554415386005813811429117062833340444950490735389201033755889815382997617514953672362380638953231325483081104074039069074312082459855104868061153181218462493120741835250281211598658590317583724763093211076383033803581749876979865965366178002285968278439178209181121479879436785731938");
    }
    _gen_x(p, q)
}

#[cfg(not(test))]
pub fn gen_x(p: &BigNumber, q: &BigNumber) -> UrsaCryptoResult<BigNumber> {
    _gen_x(p, q)
}

pub fn _gen_x(p: &BigNumber, q: &BigNumber) -> UrsaCryptoResult<BigNumber> {
    trace!("Helpers::gen_x: >>> p: {:?}, q: {:?}", p, q);

    let mut x = p.mul(&q, None)?.sub_word(3)?.rand_range()?;

    x.add_word(2)?;

    trace!("Helpers::gen_x: <<< x: {:?}", x);

    Ok(x)
}

#[cfg(test)]
pub fn random_qr(n: &BigNumber) -> UrsaCryptoResult<BigNumber> {
    if MockHelper::is_injected() {
        return BigNumber::from_dec("64684820421150545443421261645532741305438158267230326415141505826951816460650437611148133267480407958360035501128469885271549378871140475869904030424615175830170939416512594291641188403335834762737251794282186335118831803135149622404791467775422384378569231649224208728902565541796896860352464500717052768431523703881746487372385032277847026560711719065512366600220045978358915680277126661923892187090579302197390903902744925313826817940566429968987709582805451008234648959429651259809188953915675063700676546393568304468609062443048457324721450190021552656280473128156273976008799243162970386898307404395608179975243");
    }
    _random_qr(n)
}

#[cfg(not(test))]
pub fn random_qr(n: &BigNumber) -> UrsaCryptoResult<BigNumber> {
    _random_qr(n)
}

pub fn _random_qr(n: &BigNumber) -> UrsaCryptoResult<BigNumber> {
    trace!("Helpers::random_qr: >>> n: {:?}", n);

    let qr = BigNumber::random_qr(n)?;

    trace!("Helpers::random_qr: <<< qr: {:?}", qr);

    Ok(qr)
}

//TODO: FIXME very inefficient code
pub fn bitwise_or_big_int(a: &BigNumber, b: &BigNumber) -> UrsaCryptoResult<BigNumber> {
    trace!("Helpers::bitwise_or_big_int: >>> a: {:?}, b: {:?}", a, b);

    let significant_bits = max(a.num_bits()?, b.num_bits()?);
    let mut result = BigNumber::new()?;
    for i in 0..significant_bits {
        if a.is_bit_set(i)? || b.is_bit_set(i)? {
            result.set_bit(i)?;
        }
    }

    trace!("Helpers::bitwise_or_big_int: <<<  res: {:?}", result);

    Ok(result)
}

//Byte order: Little
pub fn transform_u32_to_array_of_u8(x: u32) -> Vec<u8> {
    trace!("Helpers::transform_u32_to_array_of_u8: >>> x: {:?}", x);

    let mut result: Vec<u8> = Vec::new();
    for i in (0..4).rev() {
        result.push((x >> (i * 8)) as u8);
    }

    trace!(
        "Helpers::transform_u32_to_array_of_u8: <<< res: {:?}",
        result
    );

    result
}

pub fn get_mtilde<S: ::std::hash::BuildHasher>(
    unrevealed_attrs: &HashSet<String, S>,
    mtilde: &mut HashMap<String, BigNumber, S>,
) -> UrsaCryptoResult<()> {
    trace!(
        "Helpers::get_mtilde: >>> unrevealed_attrs: {:?}",
        unrevealed_attrs
    );

    for attr in unrevealed_attrs {
        if !mtilde.contains_key(attr) {
            mtilde.insert(attr.clone(), bn_rand(LARGE_MVECT)?);
        }
    }

    trace!("Helpers::get_mtilde: <<< mtilde: {:?}", mtilde);

    Ok(())
}

pub fn calc_teq<S: ::std::hash::BuildHasher>(
    p_pub_key: &CredentialPrimaryPublicKey,
    a_prime: &BigNumber,
    e: &BigNumber,
    v: &BigNumber,
    m_tilde: &HashMap<String, BigNumber, S>,
    m2tilde: &BigNumber,
    unrevealed_attrs: &HashSet<String, S>,
) -> UrsaCryptoResult<BigNumber> {
    trace!("Helpers::calc_teq: >>> p_pub_key: {:?}, p_pub_key: {:?}, e: {:?}, v: {:?}, m_tilde: {:?}, m2tilde: {:?}, \
    unrevealed_attrs: {:?}", p_pub_key, a_prime, e, v, m_tilde, m2tilde, unrevealed_attrs);

    let mut ctx = BigNumber::new_context()?;
    // a_prime^e % p_pub_key.n
    let mut result: BigNumber = a_prime.mod_exp(&e, &p_pub_key.n, Some(&mut ctx))?;

    for k in unrevealed_attrs.iter() {
        let cur_r = p_pub_key.r.get(k).ok_or_else(|| {
            err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                format!("Value by key '{}' not found in pk.r", k),
            )
        })?;
        let cur_m = m_tilde.get(k).ok_or_else(|| {
            err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                format!("Value by key '{}' not found in m_tilde", k),
            )
        })?;

        // result = result * (cur_r^cur_m % p_pub_key.n) % p_pub_key.n
        result = cur_r
            .mod_exp(&cur_m, &p_pub_key.n, Some(&mut ctx))?
            .mod_mul(&result, &p_pub_key.n, Some(&mut ctx))?;
    }

    result = p_pub_key
        .s
        .mod_exp(&v, &p_pub_key.n, Some(&mut ctx))?
        .mod_mul(&result, &p_pub_key.n, Some(&mut ctx))?;

    result = p_pub_key
        .rctxt
        .mod_exp(&m2tilde, &p_pub_key.n, Some(&mut ctx))?
        .mod_mul(&result, &p_pub_key.n, Some(&mut ctx))?;

    trace!("Helpers::calc_teq: <<< t: {:?}", result);

    Ok(result)
}

pub fn calc_tne<S: ::std::hash::BuildHasher>(
    p_pub_key: &CredentialPrimaryPublicKey,
    u: &HashMap<String, BigNumber, S>,
    r: &HashMap<String, BigNumber, S>,
    mj: &BigNumber,
    alpha: &BigNumber,
    t: &HashMap<String, BigNumber, S>,
    is_less: bool,
) -> UrsaCryptoResult<Vec<BigNumber>> {
    trace!(
        "Helpers::calc_tge: >>> p_pub_key: {:?}, u: {:?}, r: {:?}, mj: {:?}, alpha: {:?}, t: {:?}",
        p_pub_key,
        u,
        r,
        mj,
        alpha,
        t
    );

    let mut tau_list: Vec<BigNumber> = Vec::new();
    let mut ctx = BigNumber::new_context()?;

    for i in 0..ITERATION {
        let cur_u = u.get(&i.to_string()).ok_or_else(|| {
            err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                format!("Value by key '{}' not found in u", i),
            )
        })?;
        let cur_r = r.get(&i.to_string()).ok_or_else(|| {
            err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                format!("Value by key '{}' not found in r", i),
            )
        })?;

        let t_tau = p_pub_key
            .z
            .mod_exp(&cur_u, &p_pub_key.n, Some(&mut ctx))?
            .mod_mul(
                &p_pub_key.s.mod_exp(&cur_r, &p_pub_key.n, Some(&mut ctx))?,
                &p_pub_key.n,
                Some(&mut ctx),
            )?;

        tau_list.push(t_tau);
    }

    let delta = r.get("DELTA").ok_or_else(|| {
        err_msg(
            UrsaCryptoErrorKind::InvalidStructure,
            format!("Value by key '{}' not found in r", "DELTA"),
        )
    })?;
    let delta_predicate = if is_less {
        delta.set_negative(true)?
    } else {
        delta.try_clone()?
    };

    let t_tau = p_pub_key
        .z
        .mod_exp(&mj, &p_pub_key.n, Some(&mut ctx))?
        .mod_mul(
            &p_pub_key
                .s
                .mod_exp(&delta_predicate, &p_pub_key.n, Some(&mut ctx))?,
            &p_pub_key.n,
            Some(&mut ctx),
        )?;

    tau_list.push(t_tau);

    let mut q: BigNumber = BIGNUMBER_1.try_clone()?;

    for i in 0..ITERATION {
        let cur_t = t.get(&i.to_string()).ok_or_else(|| {
            err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                format!("Value by key '{}' not found in t", i),
            )
        })?;
        let cur_u = u.get(&i.to_string()).ok_or_else(|| {
            err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                format!("Value by key '{}' not found in u", i),
            )
        })?;

        q = cur_t
            .mod_exp(&cur_u, &p_pub_key.n, Some(&mut ctx))?
            .mul(&q, Some(&mut ctx))?;
    }

    q = p_pub_key
        .s
        .mod_exp(&alpha, &p_pub_key.n, Some(&mut ctx))?
        .mod_mul(&q, &p_pub_key.n, Some(&mut ctx))?;

    tau_list.push(q);

    trace!("Helpers::calc_tne: <<< tau_list: {:?}", tau_list);

    Ok(tau_list)
}

fn largest_square_less_than(delta: usize) -> usize {
    (delta as f64).sqrt().floor() as usize
}

//Express the natural number `delta` as a sum of four integer squares,
// i.e `delta = a^2 + b^2 + c^2 + d^2` using Lagrange's four-square theorem
pub fn four_squares(delta: i32) -> UrsaCryptoResult<HashMap<String, BigNumber>> {
    trace!("Helpers::four_squares: >>> delta: {:?}", delta);

    if delta < 0 {
        return Err(err_msg(
            UrsaCryptoErrorKind::InvalidStructure,
            format!(
                "Cannot express a negative number as sum of four squares {} ",
                delta
            ),
        ));
    }

    let d = delta as usize;
    let mut roots: [usize; 4] = [largest_square_less_than(d), 0, 0, 0];

    'outer: for i in (1..=roots[0]).rev() {
        roots[0] = i;
        if d == roots[0].pow(2) {
            roots[1] = 0;
            roots[2] = 0;
            roots[3] = 0;
            break 'outer;
        }
        roots[1] = largest_square_less_than(d - roots[0].pow(2));
        for j in (1..=roots[1]).rev() {
            roots[1] = j;
            if d == roots[0].pow(2) + roots[1].pow(2) {
                roots[2] = 0;
                roots[3] = 0;
                break 'outer;
            }
            roots[2] = largest_square_less_than(d - roots[0].pow(2) - roots[1].pow(2));
            for k in (1..=roots[2]).rev() {
                roots[2] = k;
                if d == roots[0].pow(2) + roots[1].pow(2) + roots[2].pow(2) {
                    roots[3] = 0;
                    break 'outer;
                }
                roots[3] = largest_square_less_than(
                    d - roots[0].pow(2) - roots[1].pow(2) - roots[2].pow(2),
                );
                if d == roots[0].pow(2) + roots[1].pow(2) + roots[2].pow(2) + roots[3].pow(2) {
                    break 'outer;
                }
            }
        }
    }

    let res = hashmap![
        "0".to_string() => BigNumber::from_dec(&roots[0].to_string()[..])?,
        "1".to_string() => BigNumber::from_dec(&roots[1].to_string()[..])?,
        "2".to_string() => BigNumber::from_dec(&roots[2].to_string()[..])?,
        "3".to_string() => BigNumber::from_dec(&roots[3].to_string()[..])?
    ];

    trace!("Helpers::four_squares: <<< res: {:?}", res);

    Ok(res)
}

pub fn group_element_to_bignum(el: &GroupOrderElement) -> UrsaCryptoResult<BigNumber> {
    Ok(BigNumber::from_bytes(&el.to_bytes()?)?)
}

pub fn bignum_to_group_element(num: &BigNumber) -> UrsaCryptoResult<GroupOrderElement> {
    Ok(GroupOrderElement::from_bytes(&num.to_bytes()?)?)
}

pub fn create_tau_list_expected_values(
    r_pub_key: &CredentialRevocationPublicKey,
    rev_reg: &RevocationRegistry,
    rev_acc_pub_key: &RevocationKeyPublic,
    proof_c: &NonRevocProofCList,
) -> UrsaCryptoResult<NonRevocProofTauList> {
    trace!("Helpers::create_tau_list_expected_values: >>> r_pub_key: {:?}, rev_reg: {:?}, rev_acc_pub_key: {:?}, proof_c: {:?}",
           r_pub_key, rev_reg, rev_acc_pub_key, proof_c);

    let t1 = proof_c.e;
    let t2 = PointG1::new_inf()?;
    let t3 = Pair::pair(&r_pub_key.h0.add(&proof_c.g)?, &r_pub_key.h_cap)?
        .mul(&Pair::pair(&proof_c.a, &r_pub_key.y)?.inverse()?)?;
    let t4 = Pair::pair(&proof_c.g, &rev_reg.accum)?.mul(
        &Pair::pair(&r_pub_key.g, &proof_c.w)?
            .mul(&rev_acc_pub_key.z)?
            .inverse()?,
    )?;
    let t5 = proof_c.d;
    let t6 = PointG1::new_inf()?;
    let t7 = Pair::pair(&r_pub_key.pk.add(&proof_c.g)?, &proof_c.s)?
        .mul(&Pair::pair(&r_pub_key.g, &r_pub_key.g_dash)?.inverse()?)?;
    let t8 = Pair::pair(&proof_c.g, &r_pub_key.u)?
        .mul(&Pair::pair(&r_pub_key.g, &proof_c.u)?.inverse()?)?;

    let non_revoc_proof_tau_list = NonRevocProofTauList {
        t1,
        t2,
        t3,
        t4,
        t5,
        t6,
        t7,
        t8,
    };

    trace!(
        "Helpers::create_tau_list_expected_values: <<< non_revoc_proof_tau_list: {:?}",
        non_revoc_proof_tau_list
    );

    Ok(non_revoc_proof_tau_list)
}

pub fn create_tau_list_values(
    r_pub_key: &CredentialRevocationPublicKey,
    rev_reg: &RevocationRegistry,
    params: &NonRevocProofXList,
    proof_c: &NonRevocProofCList,
) -> UrsaCryptoResult<NonRevocProofTauList> {
    trace!("Helpers::create_tau_list_values: >>> r_pub_key: {:?}, rev_reg: {:?}, params: {:?}, proof_c: {:?}",
           r_pub_key, rev_reg, params, proof_c);

    let t1 = r_pub_key
        .h
        .mul(&params.rho)?
        .add(&r_pub_key.htilde.mul(&params.o)?)?;
    let mut t2 = proof_c
        .e
        .mul(&params.c)?
        .add(&r_pub_key.h.mul(&params.m.mod_neg()?)?)?
        .add(&r_pub_key.htilde.mul(&params.t.mod_neg()?)?)?;
    if t2.is_inf()? {
        t2 = PointG1::new_inf()?;
    }
    let t3 = Pair::pair(&proof_c.a, &r_pub_key.h_cap)?
        .pow(&params.c)?
        .mul(&Pair::pair(&r_pub_key.htilde, &r_pub_key.h_cap)?.pow(&params.r)?)?
        .mul(
            &Pair::pair(&r_pub_key.htilde, &r_pub_key.y)?
                .pow(&params.rho)?
                .mul(&Pair::pair(&r_pub_key.htilde, &r_pub_key.h_cap)?.pow(&params.m)?)?
                .mul(&Pair::pair(&r_pub_key.h1, &r_pub_key.h_cap)?.pow(&params.m2)?)?
                .mul(&Pair::pair(&r_pub_key.h2, &r_pub_key.h_cap)?.pow(&params.s)?)?
                .inverse()?,
        )?;
    let t4 = Pair::pair(&r_pub_key.htilde, &rev_reg.accum)?
        .pow(&params.r)?
        .mul(&Pair::pair(&r_pub_key.g.neg()?, &r_pub_key.h_cap)?.pow(&params.r_prime)?)?;
    let t5 = r_pub_key
        .g
        .mul(&params.r)?
        .add(&r_pub_key.htilde.mul(&params.o_prime)?)?;
    let mut t6 = proof_c
        .d
        .mul(&params.r_prime_prime)?
        .add(&r_pub_key.g.mul(&params.m_prime.mod_neg()?)?)?
        .add(&r_pub_key.htilde.mul(&params.t_prime.mod_neg()?)?)?;
    if t6.is_inf()? {
        t6 = PointG1::new_inf()?;
    }
    let t7 = Pair::pair(&r_pub_key.pk.add(&proof_c.g)?, &r_pub_key.h_cap)?
        .pow(&params.r_prime_prime)?
        .mul(&Pair::pair(&r_pub_key.htilde, &r_pub_key.h_cap)?.pow(&params.m_prime.mod_neg()?)?)?
        .mul(&Pair::pair(&r_pub_key.htilde, &proof_c.s)?.pow(&params.r)?)?;
    let t8 = Pair::pair(&r_pub_key.htilde, &r_pub_key.u)?
        .pow(&params.r)?
        .mul(
            &Pair::pair(&r_pub_key.g.neg()?, &r_pub_key.h_cap)?.pow(&params.r_prime_prime_prime)?,
        )?;

    let non_revoc_proof_tau_list = NonRevocProofTauList {
        t1,
        t2,
        t3,
        t4,
        t5,
        t6,
        t7,
        t8,
    };

    trace!(
        "Helpers::create_tau_list_values: <<< non_revoc_proof_tau_list: {:?}",
        non_revoc_proof_tau_list
    );

    Ok(non_revoc_proof_tau_list)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cl::{issuer, prover};

    #[test]
    fn encode_attribute_works() {
        let test_str = "5435";
        let test_answer =
            "83761840706354868391674207739241454863743470852830526299004654280720761327142";
        assert_eq!(
            test_answer,
            encode_attribute(test_str, ByteOrder::Big)
                .unwrap()
                .to_dec()
                .unwrap()
        );
    }

    #[test]
    fn generate_v_prime_prime_works() {
        MockHelper::inject();

        let result = BigNumber::from_dec("6620937836014079781509458870800001917950459774302786434315639456568768602266735503527631640833663968617512880802104566048179854406925811731340920442625764155409951969854303612644125623549271204625894424804352003689903192473464433927658013251120302922648839652919662117216521257876025436906282750361355336367533874548955283776610021309110505377492806210342214471251451681722267655419075635703240258044336607001296052867746675049720589092355650996711033859489737240617860392914314205277920274997312351322125481593636904917159990500837822414761512231315313922792934655437808723096823124948039695324591344458785345326611693414625458359651738188933757751726392220092781991665483583988703321457480411992304516676385323318285847376271589157730040526123521479652961899368891914982347831632139045838008837541334927738208491424027").unwrap();
        assert_eq!(generate_v_prime_prime().unwrap(), result);
    }

    #[test]
    fn bitwise_or_big_int_works() {
        let a = BigNumber::from_dec("778378032744961463933002553964902776831187587689736807008034459507677878432383414623740074");
        let b = BigNumber::from_dec("1018517988167243043134222844204689080525734196832968125318070224677190649881668353091698688");
        let result = BigNumber::from_dec("1796896020912204507067225398169591857356921784522704932326104684184868528314051767715438762");
        assert_eq!(
            result.unwrap(),
            bitwise_or_big_int(&a.unwrap(), &b.unwrap()).unwrap()
        );
    }

    #[test]
    fn four_squares_works() {
        let res = four_squares(107 as i32);
        let res_data = res.unwrap();

        assert_eq!(
            "9".to_string(),
            res_data.get("0").unwrap().to_dec().unwrap()
        );
        assert_eq!(
            "5".to_string(),
            res_data.get("1").unwrap().to_dec().unwrap()
        );
        assert_eq!(
            "1".to_string(),
            res_data.get("2").unwrap().to_dec().unwrap()
        );
        assert_eq!(
            "0".to_string(),
            res_data.get("3").unwrap().to_dec().unwrap()
        );

        let res = four_squares(112 as i32);
        let res_data = res.unwrap();

        assert_eq!(
            "10".to_string(),
            res_data.get("0").unwrap().to_dec().unwrap()
        );
        assert_eq!(
            "2".to_string(),
            res_data.get("1").unwrap().to_dec().unwrap()
        );
        assert_eq!(
            "2".to_string(),
            res_data.get("2").unwrap().to_dec().unwrap()
        );
        assert_eq!(
            "2".to_string(),
            res_data.get("3").unwrap().to_dec().unwrap()
        );

        let res = four_squares(253 as i32);
        let res_data = res.unwrap();

        assert_eq!(
            "14".to_string(),
            res_data.get("0").unwrap().to_dec().unwrap()
        );
        assert_eq!(
            "7".to_string(),
            res_data.get("1").unwrap().to_dec().unwrap()
        );
        assert_eq!(
            "2".to_string(),
            res_data.get("2").unwrap().to_dec().unwrap()
        );
        assert_eq!(
            "2".to_string(),
            res_data.get("3").unwrap().to_dec().unwrap()
        );

        let res = four_squares(1506099439 as i32);
        let res_data = res.unwrap();

        assert_eq!(
            "38807".to_string(),
            res_data.get("0").unwrap().to_dec().unwrap()
        );
        assert_eq!(
            "337".to_string(),
            res_data.get("1").unwrap().to_dec().unwrap()
        );
        assert_eq!(
            "50".to_string(),
            res_data.get("2").unwrap().to_dec().unwrap()
        );
        assert_eq!(
            "11".to_string(),
            res_data.get("3").unwrap().to_dec().unwrap()
        );
    }

    #[test]
    fn transform_u32_to_array_of_u8_works() {
        let int = 0x74BA7445;
        let answer = vec![0x74, 0xBA, 0x74, 0x45];
        assert_eq!(transform_u32_to_array_of_u8(int), answer)
    }

    #[test]
    fn test_encode_attribute_fail_simple_collision_on_internal_truncate() {
        let ea3079 = encode_attribute("3079", ByteOrder::Big).unwrap();
        let ea6440 = encode_attribute("6440", ByteOrder::Big).unwrap();
        assert_ne!(ea3079, ea6440);

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
    fn calc_tne_works() {
        let proof = prover::mocks::ne_proof();
        let pk = issuer::mocks::credential_primary_public_key();

        let res = calc_tne(
            &pk,
            &proof.u,
            &proof.r,
            &proof.mj,
            &proof.alpha,
            &proof.t,
            proof.predicate.is_less(),
        );

        assert!(res.is_ok());

        let res_data = res.unwrap();

        assert_eq!("65515179709108026467913442253499099801966907020745255347110398650355916665803837\
        07074374285625623992618258034482874705637485499638759374334111906777998444597195962882137495\
        46241252599867765887126944842605322232431550047077300912325544804771322199929454027075662773\
        58152501360632014253935013985662381916247720671148707249946908885935798495651223006117551824\
        33699034819414235909521498375093876684792233526390609966850211010821350981640872720328541779\
        97327105574647318106219933086355568371491060691278794120258318319023486167854894518658221865\
        24800436027192696216152105090506015757266556255232306144655608567343136505670", res_data[1].to_dec().unwrap());

        assert_eq!("37533780917779531511237145959836444300689607963031476900866684621488489918126566\
        54952188995351472791057578124947683585454675784622178441108808918503618679224678596364814336\
        63975021590121523531457538883313658539633581551354420547514166200076285563937951004982609082\
        94371022811442070620351098758127098244798879430407810333937749563329381152076445529402863878\
        16882342579670134371608309243324042556315552335708289143881109111122601942672089350483029204\
        32781521417367911232887738135274550782236554694976666166990482622538324995757159182681616076\
        20654341861117070040350723055043721492475393447378422268465089327305214127497", res_data[4].to_dec().unwrap());

        assert_eq!("85792352895820240333890789102145726421844499161302737480886489756497939690747882\
        47623299361945003435808043132166100712819619828180642308596640747304600618705399424545299874\
        18436312019502751107773643122490033193620386977937753770823229496538888267752454217128873324\
        20051752162962176051068381742850661487019199688955385460549344136833325388021671633290649550\
        40515565389149016308077954851808706083095582109248170847463880536249366156605714267596752766\
        31839937087680336690781266325043663083854158029559611517721678702314741440737728022831823751\
        45256219426454149503998537986414519426715148839164974816475472185621648644891", res_data[5].to_dec().unwrap());
    }

    #[test]
    fn calc_teq_works() {
        let proof = prover::mocks::eq_proof();
        let pk = issuer::mocks::credential_primary_public_key();
        let unrevealed_attrs = prover::mocks::unrevealed_attrs();

        let res = calc_teq(
            &pk,
            &proof.a_prime,
            &proof.e,
            &proof.v,
            &proof.m,
            &proof.m2,
            &unrevealed_attrs,
        );

        assert!(res.is_ok());
        assert_eq!("91264240506826174927348047353965425159860757123338479073424113940259806551851229\
        29223711966727033722604489188203150739124733516450682232344417480340482341559520998831392577\
        94116014271631698674027316835357321996906259424466546451562774161140030976964596027597723555\
        89838338098112196343083991333232435443953495090160789157756256594127180544038043918022344493\
        84865179215464700548799307482303595441481342427878016310830209497605585249372185396761509717\
        23513431038543455953776634428397886712772493416769127589401268192936635379602026733723945633\
        53933943790374230983129060596346889726181201177754774157687114812348019929279", res.unwrap().to_dec().unwrap());
    }
}
