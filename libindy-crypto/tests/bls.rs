extern crate indy_crypto;

#[macro_use]
extern crate lazy_static;
extern crate log;

#[macro_use]
mod utils;

use utils::bls::BlsUtils;

use indy_crypto::api::ErrorCode;

#[cfg(test)]
mod tests {
    use super::*;

//    #[test]
//    fn indy_crypto_generate_keys_works() {
//        let g = "false 664A118778294F 8F4B91D0B55BEA 6906BB430A6501 D00B17A7FC60D7 6DA182D7ED7457 765B025552F2CA 9789944C2F7 A19E2AA795BAED 763469C4704932 7A111FBB355FA3 95F132248AAE46 6CA91CD71F5879 E13AA094B70B7 2036D474F403 16CE7D356D5E51 6C1B619289C278 7C5863EC09B9A8 39CD4063B98D4D 518A3F8D834A15 EBB3025700D244 58608C8C66D8 EFC319C5DC2CC3 D97BA80CCB6866 7B2F12D0391E49 CD6354022E060C AFE9C33DD6B5AC 56E8113AE474BD 512427C556A 8094CE251D2839 5A656663FA5F96 157FD83C6B2426 2FEC3584898982 617BEAC39065DB A9FEFC2AE937BB 6393541E1FFC 0 0 0 0 0 0 0";
//        BlsUtils::generate_keys(g).unwrap();
//    }

    #[test]
    fn indy_crypto_generate_keys_works_for_invalid_g() {
//        assert_eq!(BlsUtils::generate_keys("").unwrap_err(), ErrorCode::CommonInvalidParam2);
    }
}