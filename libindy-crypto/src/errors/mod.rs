pub mod common;
pub mod indy;

use ffi::ErrorCode;

pub trait ToErrorCode {
    fn to_error_code(&self) -> ErrorCode;
}