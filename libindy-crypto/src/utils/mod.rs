#[macro_use]
pub mod ctypes;
pub mod commitment;
pub mod rsa;

use bn::BigNumber;
use errors::IndyCryptoError;

pub fn get_hash_as_int(nums: &Vec<Vec<u8>>) -> Result<BigNumber, IndyCryptoError> {
    trace!("Helpers::get_hash_as_int: >>> nums: {:?}", nums);

    let hash = BigNumber::from_bytes(&BigNumber::hash_array(&nums)?);

    trace!("Helpers::get_hash_as_int: <<< hash: {:?}", hash);

    hash
}

pub fn clone_option_bignum(b: &Option<BigNumber>) -> Result<Option<BigNumber>, IndyCryptoError> {
    match *b {
        Some(ref bn) => Ok(Some(bn.clone()?)),
        None => Ok(None)
    }
}

macro_rules! hashset {
    ( $( $x:expr ),* ) => {
        {
            let mut set = ::std::collections::HashSet::new();
            $(
                set.insert($x);
            )*
            set
        }
    }
}

macro_rules! hashmap {
    ($( $key: expr => $val: expr ),*) => {
        {
            let mut map = ::std::collections::HashMap::new();
            $(
                map.insert($key, $val);
            )*
            map
        }
    }
}

macro_rules! btreeset {
    ( $( $x:expr ),* ) => {
        {
            let mut set = ::std::collections::BTreeSet::new();
            $(
                set.insert($x);
            )*
            set
        }
    }
}

macro_rules! btreemap {
    ($( $key: expr => $val: expr ),*) => {
        {
            let mut map = ::std::collections::BTreeMap::new();
            $(
                map.insert($key, $val);
            )*
            map
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_hash_as_int_works() {
        let mut nums = vec![
            BigNumber::from_hex("ff9d2eedfee9cffd9ef6dbffedff3fcbef4caecb9bffe79bfa94d3fdf6abfbff").unwrap().to_bytes().unwrap(),
            BigNumber::from_hex("ff9d2eedfee9cffd9ef6dbffedff3fcbef4caecb9bffe79bfa9168615ccbc546").unwrap().to_bytes().unwrap()
        ];
        let res = get_hash_as_int(&mut nums);

        assert!(res.is_ok());
        assert_eq!("2C2566C22E04AB3F18B3BA693823175002F10F400811363D26BBB33633AC8BAD", res.unwrap().to_hex().unwrap());
    }
}
