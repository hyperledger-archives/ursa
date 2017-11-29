extern crate serde;
extern crate serde_json;

use self::serde::{Serialize, Deserialize};
use std::string::String;
use errors::IndyCryptoError;


pub trait JsonEncodable: Serialize + Sized {
    fn to_json(&self) -> Result<String, IndyCryptoError> {
        serde_json::to_string(self)
            .map_err(|err| IndyCryptoError::from(err))
    }
}

pub trait JsonDecodable<'a>: Deserialize<'a> {
    fn from_json(to_string: &'a str) -> Result<Self, IndyCryptoError> {
        serde_json::from_str(to_string)
            .map_err(|err| IndyCryptoError::from(err))
    }
}
