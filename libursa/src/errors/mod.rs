#[cfg(feature = "serialization")]
extern crate serde_json;
extern crate log;

use std::error::Error;
use std::{fmt, io};

#[derive(Debug, PartialEq, Copy, Clone, Serialize)]
#[repr(usize)]
pub enum ErrorCode
{
    Success = 0,

    // Common errors

    // Caller passed invalid value as param 1 (null, invalid json and etc..)
    CommonInvalidParam1 = 100,

    // Caller passed invalid value as param 2 (null, invalid json and etc..)
    CommonInvalidParam2 = 101,

    // Caller passed invalid value as param 3 (null, invalid json and etc..)
    CommonInvalidParam3 = 102,

    // Caller passed invalid value as param 4 (null, invalid json and etc..)
    CommonInvalidParam4 = 103,

    // Caller passed invalid value as param 5 (null, invalid json and etc..)
    CommonInvalidParam5 = 104,

    // Caller passed invalid value as param 6 (null, invalid json and etc..)
    CommonInvalidParam6 = 105,

    // Caller passed invalid value as param 7 (null, invalid json and etc..)
    CommonInvalidParam7 = 106,

    // Caller passed invalid value as param 8 (null, invalid json and etc..)
    CommonInvalidParam8 = 107,

    // Caller passed invalid value as param 9 (null, invalid json and etc..)
    CommonInvalidParam9 = 108,

    // Caller passed invalid value as param 10 (null, invalid json and etc..)
    CommonInvalidParam10 = 109,

    // Caller passed invalid value as param 11 (null, invalid json and etc..)
    CommonInvalidParam11 = 110,

    // Caller passed invalid value as param 11 (null, invalid json and etc..)
    CommonInvalidParam12 = 111,

    // Invalid library state was detected in runtime. It signals library bug
    CommonInvalidState = 112,

    // Object (json, config, key, credential and etc...) passed by library caller has invalid structure
    CommonInvalidStructure = 113,

    // IO Error
    CommonIOError = 114,

    // Trying to issue non-revocation credential with full anoncreds revocation accumulator
    AnoncredsRevocationAccumulatorIsFull = 115,

    // Invalid revocation accumulator index
    AnoncredsInvalidRevocationAccumulatorIndex = 116,

    // Credential revoked
    AnoncredsCredentialRevoked = 117,

    // Proof rejected
    AnoncredsProofRejected = 118,
}

pub trait ToErrorCode {
    fn to_error_code(&self) -> ErrorCode;
}

#[derive(Debug)]
pub enum HLCryptoError {
    InvalidParam1(String),
    InvalidParam2(String),
    InvalidParam3(String),
    InvalidParam4(String),
    InvalidParam5(String),
    InvalidParam6(String),
    InvalidParam7(String),
    InvalidParam8(String),
    InvalidParam9(String),
    InvalidState(String),
    InvalidStructure(String),
    IOError(io::Error),
    AnoncredsRevocationAccumulatorIsFull(String),
    AnoncredsInvalidRevocationAccumulatorIndex(String),
    AnoncredsCredentialRevoked(String),
    AnoncredsProofRejected(String),
}

impl fmt::Display for HLCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HLCryptoError::InvalidParam1(ref description) => write!(f, "Invalid param 1: {}", description),
            HLCryptoError::InvalidParam2(ref description) => write!(f, "Invalid param 2: {}", description),
            HLCryptoError::InvalidParam3(ref description) => write!(f, "Invalid param 3: {}", description),
            HLCryptoError::InvalidParam4(ref description) => write!(f, "Invalid param 4: {}", description),
            HLCryptoError::InvalidParam5(ref description) => write!(f, "Invalid param 4: {}", description),
            HLCryptoError::InvalidParam6(ref description) => write!(f, "Invalid param 4: {}", description),
            HLCryptoError::InvalidParam7(ref description) => write!(f, "Invalid param 4: {}", description),
            HLCryptoError::InvalidParam8(ref description) => write!(f, "Invalid param 4: {}", description),
            HLCryptoError::InvalidParam9(ref description) => write!(f, "Invalid param 4: {}", description),
            HLCryptoError::InvalidState(ref description) => write!(f, "Invalid library state: {}", description),
            HLCryptoError::InvalidStructure(ref description) => write!(f, "Invalid structure: {}", description),
            HLCryptoError::IOError(ref err) => err.fmt(f),
            HLCryptoError::AnoncredsRevocationAccumulatorIsFull(ref description) => write!(f, "Revocation accumulator is full: {}", description),
            HLCryptoError::AnoncredsInvalidRevocationAccumulatorIndex(ref description) => write!(f, "Invalid revocation accumulator index: {}", description),
            HLCryptoError::AnoncredsCredentialRevoked(ref description) => write!(f, "Credential revoked: {}", description),
            HLCryptoError::AnoncredsProofRejected(ref description) => write!(f, "Proof rejected: {}", description),
        }
    }
}

impl Error for HLCryptoError {
    fn description(&self) -> &str {
        match *self {
            HLCryptoError::InvalidParam1(ref description) => description,
            HLCryptoError::InvalidParam2(ref description) => description,
            HLCryptoError::InvalidParam3(ref description) => description,
            HLCryptoError::InvalidParam4(ref description) => description,
            HLCryptoError::InvalidParam5(ref description) => description,
            HLCryptoError::InvalidParam6(ref description) => description,
            HLCryptoError::InvalidParam7(ref description) => description,
            HLCryptoError::InvalidParam8(ref description) => description,
            HLCryptoError::InvalidParam9(ref description) => description,
            HLCryptoError::InvalidState(ref description) => description,
            HLCryptoError::InvalidStructure(ref description) => description,
            HLCryptoError::IOError(ref err) => err.description(),
            HLCryptoError::AnoncredsRevocationAccumulatorIsFull(ref description) => description,
            HLCryptoError::AnoncredsInvalidRevocationAccumulatorIndex(ref description) => description,
            HLCryptoError::AnoncredsCredentialRevoked(ref description) => description,
            HLCryptoError::AnoncredsProofRejected(ref description) => description,
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            HLCryptoError::InvalidParam1(_) |
            HLCryptoError::InvalidParam2(_) |
            HLCryptoError::InvalidParam3(_) |
            HLCryptoError::InvalidParam4(_) |
            HLCryptoError::InvalidParam5(_) |
            HLCryptoError::InvalidParam6(_) |
            HLCryptoError::InvalidParam7(_) |
            HLCryptoError::InvalidParam8(_) |
            HLCryptoError::InvalidParam9(_) |
            HLCryptoError::InvalidState(_) |
            HLCryptoError::InvalidStructure(_) => None,
            HLCryptoError::IOError(ref err) => Some(err),
            HLCryptoError::AnoncredsRevocationAccumulatorIsFull(_) => None,
            HLCryptoError::AnoncredsInvalidRevocationAccumulatorIndex(_) => None,
            HLCryptoError::AnoncredsCredentialRevoked(_) => None,
            HLCryptoError::AnoncredsProofRejected(_) => None,
        }
    }
}

impl ToErrorCode for HLCryptoError {
    fn to_error_code(&self) -> ErrorCode {
        match *self {
            HLCryptoError::InvalidParam1(_) => ErrorCode::CommonInvalidParam1,
            HLCryptoError::InvalidParam2(_) => ErrorCode::CommonInvalidParam2,
            HLCryptoError::InvalidParam3(_) => ErrorCode::CommonInvalidParam3,
            HLCryptoError::InvalidParam4(_) => ErrorCode::CommonInvalidParam4,
            HLCryptoError::InvalidParam5(_) => ErrorCode::CommonInvalidParam5,
            HLCryptoError::InvalidParam6(_) => ErrorCode::CommonInvalidParam6,
            HLCryptoError::InvalidParam7(_) => ErrorCode::CommonInvalidParam7,
            HLCryptoError::InvalidParam8(_) => ErrorCode::CommonInvalidParam8,
            HLCryptoError::InvalidParam9(_) => ErrorCode::CommonInvalidParam9,
            HLCryptoError::InvalidState(_) => ErrorCode::CommonInvalidState,
            HLCryptoError::InvalidStructure(_) => ErrorCode::CommonInvalidStructure,
            HLCryptoError::IOError(_) => ErrorCode::CommonIOError,
            HLCryptoError::AnoncredsRevocationAccumulatorIsFull(_) => ErrorCode::AnoncredsRevocationAccumulatorIsFull,
            HLCryptoError::AnoncredsInvalidRevocationAccumulatorIndex(_) => ErrorCode::AnoncredsInvalidRevocationAccumulatorIndex,
            HLCryptoError::AnoncredsCredentialRevoked(_) => ErrorCode::AnoncredsCredentialRevoked,
            HLCryptoError::AnoncredsProofRejected(_) => ErrorCode::AnoncredsProofRejected,
        }
    }
}

impl From<serde_json::Error> for HLCryptoError {
    fn from(err: serde_json::Error) -> HLCryptoError {
        HLCryptoError::InvalidStructure(err.to_string())
    }
}

impl From<log::SetLoggerError> for HLCryptoError {
    fn from(err: log::SetLoggerError) -> HLCryptoError{
        HLCryptoError::InvalidState(err.description().to_owned())
    }
}