use bn::BigNumber;
use errors::prelude::*;

pub fn get_hash_as_int(nums: &[Vec<u8>]) -> UrsaCryptoResult<BigNumber> {
    trace!("Helpers::get_hash_as_int: >>> nums: {:?}", nums);

    let hash = BigNumber::from_bytes(&BigNumber::hash_array(&nums)?);

    trace!("Helpers::get_hash_as_int: <<< hash: {:?}", hash);

    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_hash_as_int_works() {
        let mut nums = vec![
            BigNumber::from_hex("ff9d2eedfee9cffd9ef6dbffedff3fcbef4caecb9bffe79bfa94d3fdf6abfbff")
                .unwrap()
                .to_bytes()
                .unwrap(),
            BigNumber::from_hex("ff9d2eedfee9cffd9ef6dbffedff3fcbef4caecb9bffe79bfa9168615ccbc546")
                .unwrap()
                .to_bytes()
                .unwrap(),
        ];
        let res = get_hash_as_int(&mut nums);

        assert!(res.is_ok());
        assert_eq!(
            "2C2566C22E04AB3F18B3BA693823175002F10F400811363D26BBB33633AC8BAD",
            res.unwrap().to_hex().unwrap()
        );
    }
}
