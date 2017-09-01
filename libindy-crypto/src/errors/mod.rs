pub mod common;
pub mod indy;

use api::ErrorCode;

pub trait ToErrorCode {
    fn to_error_code(&self) -> ErrorCode;
}