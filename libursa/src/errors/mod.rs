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
pub enum UrsaCryptoError {
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

impl fmt::Display for UrsaCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UrsaCryptoError::InvalidParam1(ref description) => write!(f, "Invalid param 1: {}", description),
            UrsaCryptoError::InvalidParam2(ref description) => write!(f, "Invalid param 2: {}", description),
            UrsaCryptoError::InvalidParam3(ref description) => write!(f, "Invalid param 3: {}", description),
            UrsaCryptoError::InvalidParam4(ref description) => write!(f, "Invalid param 4: {}", description),
            UrsaCryptoError::InvalidParam5(ref description) => write!(f, "Invalid param 4: {}", description),
            UrsaCryptoError::InvalidParam6(ref description) => write!(f, "Invalid param 4: {}", description),
            UrsaCryptoError::InvalidParam7(ref description) => write!(f, "Invalid param 4: {}", description),
            UrsaCryptoError::InvalidParam8(ref description) => write!(f, "Invalid param 4: {}", description),
            UrsaCryptoError::InvalidParam9(ref description) => write!(f, "Invalid param 4: {}", description),
            UrsaCryptoError::InvalidState(ref description) => write!(f, "Invalid library state: {}", description),
            UrsaCryptoError::InvalidStructure(ref description) => write!(f, "Invalid structure: {}", description),
            UrsaCryptoError::IOError(ref err) => err.fmt(f),
            UrsaCryptoError::AnoncredsRevocationAccumulatorIsFull(ref description) => write!(f, "Revocation accumulator is full: {}", description),
            UrsaCryptoError::AnoncredsInvalidRevocationAccumulatorIndex(ref description) => write!(f, "Invalid revocation accumulator index: {}", description),
            UrsaCryptoError::AnoncredsCredentialRevoked(ref description) => write!(f, "Credential revoked: {}", description),
            UrsaCryptoError::AnoncredsProofRejected(ref description) => write!(f, "Proof rejected: {}", description),
        }
    }
}

impl Error for UrsaCryptoError {
    fn description(&self) -> &str {
        match *self {
            UrsaCryptoError::InvalidParam1(ref description) => description,
            UrsaCryptoError::InvalidParam2(ref description) => description,
            UrsaCryptoError::InvalidParam3(ref description) => description,
            UrsaCryptoError::InvalidParam4(ref description) => description,
            UrsaCryptoError::InvalidParam5(ref description) => description,
            UrsaCryptoError::InvalidParam6(ref description) => description,
            UrsaCryptoError::InvalidParam7(ref description) => description,
            UrsaCryptoError::InvalidParam8(ref description) => description,
            UrsaCryptoError::InvalidParam9(ref description) => description,
            UrsaCryptoError::InvalidState(ref description) => description,
            UrsaCryptoError::InvalidStructure(ref description) => description,
            UrsaCryptoError::IOError(ref err) => err.description(),
            UrsaCryptoError::AnoncredsRevocationAccumulatorIsFull(ref description) => description,
            UrsaCryptoError::AnoncredsInvalidRevocationAccumulatorIndex(ref description) => description,
            UrsaCryptoError::AnoncredsCredentialRevoked(ref description) => description,
            UrsaCryptoError::AnoncredsProofRejected(ref description) => description,
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            UrsaCryptoError::InvalidParam1(_) |
            UrsaCryptoError::InvalidParam2(_) |
            UrsaCryptoError::InvalidParam3(_) |
            UrsaCryptoError::InvalidParam4(_) |
            UrsaCryptoError::InvalidParam5(_) |
            UrsaCryptoError::InvalidParam6(_) |
            UrsaCryptoError::InvalidParam7(_) |
            UrsaCryptoError::InvalidParam8(_) |
            UrsaCryptoError::InvalidParam9(_) |
            UrsaCryptoError::InvalidState(_) |
            UrsaCryptoError::InvalidStructure(_) => None,
            UrsaCryptoError::IOError(ref err) => Some(err),
            UrsaCryptoError::AnoncredsRevocationAccumulatorIsFull(_) => None,
            UrsaCryptoError::AnoncredsInvalidRevocationAccumulatorIndex(_) => None,
            UrsaCryptoError::AnoncredsCredentialRevoked(_) => None,
            UrsaCryptoError::AnoncredsProofRejected(_) => None,
        }
    }
}

impl ToErrorCode for UrsaCryptoError {
    fn to_error_code(&self) -> ErrorCode {
        match *self {
            UrsaCryptoError::InvalidParam1(_) => ErrorCode::CommonInvalidParam1,
            UrsaCryptoError::InvalidParam2(_) => ErrorCode::CommonInvalidParam2,
            UrsaCryptoError::InvalidParam3(_) => ErrorCode::CommonInvalidParam3,
            UrsaCryptoError::InvalidParam4(_) => ErrorCode::CommonInvalidParam4,
            UrsaCryptoError::InvalidParam5(_) => ErrorCode::CommonInvalidParam5,
            UrsaCryptoError::InvalidParam6(_) => ErrorCode::CommonInvalidParam6,
            UrsaCryptoError::InvalidParam7(_) => ErrorCode::CommonInvalidParam7,
            UrsaCryptoError::InvalidParam8(_) => ErrorCode::CommonInvalidParam8,
            UrsaCryptoError::InvalidParam9(_) => ErrorCode::CommonInvalidParam9,
            UrsaCryptoError::InvalidState(_) => ErrorCode::CommonInvalidState,
            UrsaCryptoError::InvalidStructure(_) => ErrorCode::CommonInvalidStructure,
            UrsaCryptoError::IOError(_) => ErrorCode::CommonIOError,
            UrsaCryptoError::AnoncredsRevocationAccumulatorIsFull(_) => ErrorCode::AnoncredsRevocationAccumulatorIsFull,
            UrsaCryptoError::AnoncredsInvalidRevocationAccumulatorIndex(_) => ErrorCode::AnoncredsInvalidRevocationAccumulatorIndex,
            UrsaCryptoError::AnoncredsCredentialRevoked(_) => ErrorCode::AnoncredsCredentialRevoked,
            UrsaCryptoError::AnoncredsProofRejected(_) => ErrorCode::AnoncredsProofRejected,
        }
    }
}

impl From<serde_json::Error> for UrsaCryptoError {
    fn from(err: serde_json::Error) -> UrsaCryptoError {
        UrsaCryptoError::InvalidStructure(err.to_string())
    }
}

impl From<log::SetLoggerError> for UrsaCryptoError {
    fn from(err: log::SetLoggerError) -> UrsaCryptoError{
        UrsaCryptoError::InvalidState(err.description().to_owned())
    }
}
