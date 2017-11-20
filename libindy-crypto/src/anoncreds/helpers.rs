use bn::BigNumber;
use errors::IndyCryptoError;
use pair::{GroupOrderElement, PointG1, Pair};

use super::constants::*;

use std::hash::Hash;
use std::cmp::max;
use std::collections::HashMap;

pub enum ByteOrder {
    Big,
    Little
}

pub fn encode_attribute(attribute: &str, byte_order: ByteOrder) -> Result<BigNumber, IndyCryptoError> {
    let mut result = BigNumber::hash(attribute.as_bytes())?;
    let index = result.iter().position(|&value| value == 0);

    if let Some(position) = index {
        result.truncate(position);
    }

    if let ByteOrder::Little = byte_order {
        result.reverse();
    }

    Ok(BigNumber::from_bytes(&result)?)
}

pub fn generate_v_prime_prime() -> Result<BigNumber, IndyCryptoError> {
    let a = BigNumber::rand(LARGE_VPRIME_PRIME)?;

    let b = BigNumber::from_u32(2)?
        .exp(&BigNumber::from_u32(LARGE_VPRIME_PRIME - 1)?, None)?;

    let v_prime_prime = bitwise_or_big_int(&a, &b)?;
    Ok(v_prime_prime)
}

#[cfg(not(test))]
pub fn generate_safe_prime(size: usize) -> Result<BigNumber, IndyCryptoError> {
    BigNumber::generate_safe_prime(usize);
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

pub fn get_mtilde(unrevealed_attrs: &Vec<String>)
                  -> Result<HashMap<String, BigNumber>, IndyCryptoError> {
    let mut mtilde: HashMap<String, BigNumber> = HashMap::new();

    for attr in unrevealed_attrs.iter() {
        mtilde.insert(attr.clone(), BigNumber::rand(LARGE_MVECT)?);
    }
    Ok(mtilde)
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


pub trait BytesView {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError>;
}

impl BytesView for PointG1 {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.to_bytes()?)
    }
}

impl BytesView for GroupOrderElement {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.to_bytes()?)
    }
}

impl BytesView for Pair {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.to_bytes()?)
    }
}

pub trait AppendByteArray {
    fn append_vec<T: BytesView>(&mut self, other: &Vec<T>) -> Result<(), IndyCryptoError>;
}

impl AppendByteArray for Vec<Vec<u8>> {
    fn append_vec<T: BytesView>(&mut self, other: &Vec<T>) -> Result<(), IndyCryptoError> {
        for el in other.iter() {
            self.push(el.to_bytes()?);
        }
        Ok(())
    }
}

pub fn clone_bignum_map<K: Clone + Eq + Hash>(other: &HashMap<K, BigNumber>)
                                              -> Result<HashMap<K, BigNumber>, IndyCryptoError> {
    let mut res: HashMap<K, BigNumber> = HashMap::new();
    for (k, v) in other {
        res.insert(k.clone(), v.clone()?);
    }
    Ok(res)
}

pub fn group_element_to_bignum(el: &GroupOrderElement) -> Result<BigNumber, IndyCryptoError> {
    Ok(BigNumber::from_bytes(&el.to_bytes()?)?)
}

pub fn bignum_to_group_element(num: &BigNumber) -> Result<GroupOrderElement, IndyCryptoError> {
    Ok(GroupOrderElement::from_bytes(&num.to_bytes()?)?)
}

pub fn get_composite_id(issuer_did: &str, schema_seq_no: i32) -> String {
    issuer_did.to_string() + ":" + &schema_seq_no.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

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
}