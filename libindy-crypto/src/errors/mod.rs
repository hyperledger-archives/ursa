use ffi::ErrorCode;

use std::error::Error;
use std::{fmt, io};

pub trait ToErrorCode {
    fn to_error_code(&self) -> ErrorCode;
}

#[derive(Debug)]
pub enum IndyCryptoError {
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
    AnoncredsClaimRevoked(String),
}

impl fmt::Display for IndyCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            IndyCryptoError::InvalidParam1(ref description) => write!(f, "Invalid param 1: {}", description),
            IndyCryptoError::InvalidParam2(ref description) => write!(f, "Invalid param 2: {}", description),
            IndyCryptoError::InvalidParam3(ref description) => write!(f, "Invalid param 3: {}", description),
            IndyCryptoError::InvalidParam4(ref description) => write!(f, "Invalid param 4: {}", description),
            IndyCryptoError::InvalidParam5(ref description) => write!(f, "Invalid param 4: {}", description),
            IndyCryptoError::InvalidParam6(ref description) => write!(f, "Invalid param 4: {}", description),
            IndyCryptoError::InvalidParam7(ref description) => write!(f, "Invalid param 4: {}", description),
            IndyCryptoError::InvalidParam8(ref description) => write!(f, "Invalid param 4: {}", description),
            IndyCryptoError::InvalidParam9(ref description) => write!(f, "Invalid param 4: {}", description),
            IndyCryptoError::InvalidState(ref description) => write!(f, "Invalid library state: {}", description),
            IndyCryptoError::InvalidStructure(ref description) => write!(f, "Invalid structure: {}", description),
            IndyCryptoError::IOError(ref err) => err.fmt(f),
            IndyCryptoError::AnoncredsRevocationAccumulatorIsFull(ref description) => write!(f, "Revocation accumulator is full: {}", description),
            IndyCryptoError::AnoncredsInvalidRevocationAccumulatorIndex(ref description) => write!(f, "Invalid revocation accumulator index: {}", description),
            IndyCryptoError::AnoncredsClaimRevoked(ref description) => write!(f, "Claim revoked {}", description),
        }
    }
}

impl Error for IndyCryptoError {
    fn description(&self) -> &str {
        match *self {
            IndyCryptoError::InvalidParam1(ref description) => description,
            IndyCryptoError::InvalidParam2(ref description) => description,
            IndyCryptoError::InvalidParam3(ref description) => description,
            IndyCryptoError::InvalidParam4(ref description) => description,
            IndyCryptoError::InvalidParam5(ref description) => description,
            IndyCryptoError::InvalidParam6(ref description) => description,
            IndyCryptoError::InvalidParam7(ref description) => description,
            IndyCryptoError::InvalidParam8(ref description) => description,
            IndyCryptoError::InvalidParam9(ref description) => description,
            IndyCryptoError::InvalidState(ref description) => description,
            IndyCryptoError::InvalidStructure(ref description) => description,
            IndyCryptoError::IOError(ref err) => err.description(),
            IndyCryptoError::AnoncredsRevocationAccumulatorIsFull(ref description) => description,
            IndyCryptoError::AnoncredsInvalidRevocationAccumulatorIndex(ref description) => description,
            IndyCryptoError::AnoncredsClaimRevoked(ref description) => description,
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            IndyCryptoError::InvalidParam1(_) |
            IndyCryptoError::InvalidParam2(_) |
            IndyCryptoError::InvalidParam3(_) |
            IndyCryptoError::InvalidParam4(_) |
            IndyCryptoError::InvalidParam5(_) |
            IndyCryptoError::InvalidParam6(_) |
            IndyCryptoError::InvalidParam7(_) |
            IndyCryptoError::InvalidParam8(_) |
            IndyCryptoError::InvalidParam9(_) |
            IndyCryptoError::InvalidState(_) |
            IndyCryptoError::InvalidStructure(_) => None,
            IndyCryptoError::IOError(ref err) => Some(err),
            IndyCryptoError::AnoncredsRevocationAccumulatorIsFull(_) => None,
            IndyCryptoError::AnoncredsInvalidRevocationAccumulatorIndex(_) => None,
            IndyCryptoError::AnoncredsClaimRevoked(_) => None,
        }
    }
}

impl ToErrorCode for IndyCryptoError {
    fn to_error_code(&self) -> ErrorCode {
        match *self {
            IndyCryptoError::InvalidParam1(_) => ErrorCode::CommonInvalidParam1,
            IndyCryptoError::InvalidParam2(_) => ErrorCode::CommonInvalidParam2,
            IndyCryptoError::InvalidParam3(_) => ErrorCode::CommonInvalidParam3,
            IndyCryptoError::InvalidParam4(_) => ErrorCode::CommonInvalidParam4,
            IndyCryptoError::InvalidParam5(_) => ErrorCode::CommonInvalidParam5,
            IndyCryptoError::InvalidParam6(_) => ErrorCode::CommonInvalidParam6,
            IndyCryptoError::InvalidParam7(_) => ErrorCode::CommonInvalidParam7,
            IndyCryptoError::InvalidParam8(_) => ErrorCode::CommonInvalidParam8,
            IndyCryptoError::InvalidParam9(_) => ErrorCode::CommonInvalidParam9,
            IndyCryptoError::InvalidState(_) => ErrorCode::CommonInvalidState,
            IndyCryptoError::InvalidStructure(_) => ErrorCode::CommonInvalidStructure,
            IndyCryptoError::IOError(_) => ErrorCode::CommonIOError,
            IndyCryptoError::AnoncredsRevocationAccumulatorIsFull(_) => ErrorCode::AnoncredsRevocationAccumulatorIsFull,
            IndyCryptoError::AnoncredsInvalidRevocationAccumulatorIndex(_) => ErrorCode::AnoncredsInvalidRevocationAccumulatorIndex,
            IndyCryptoError::AnoncredsClaimRevoked(_) => ErrorCode::AnoncredsClaimRevoked,
        }
    }
}