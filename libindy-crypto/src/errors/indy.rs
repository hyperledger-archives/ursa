use errors::common::CommonError;

use api::ErrorCode;
use errors::ToErrorCode;

use std::error;
use std::fmt;

#[derive(Debug)]
pub enum IndyError {
    CommonError(CommonError)
}

impl fmt::Display for IndyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            IndyError::CommonError(ref err) => err.fmt(f)
        }
    }
}

impl error::Error for IndyError {
    fn description(&self) -> &str {
        match *self {
            IndyError::CommonError(ref err) => err.description()
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            IndyError::CommonError(ref err) => Some(err)
        }
    }
}

impl ToErrorCode for IndyError {
    fn to_error_code(&self) -> ErrorCode {
        error!("Casting error to ErrorCode: {}", self);
        match *self {
            IndyError::CommonError(ref err) => err.to_error_code()
        }
    }
}

impl From<CommonError> for IndyError {
    fn from(err: CommonError) -> IndyError {
        IndyError::CommonError(err)
    }
}