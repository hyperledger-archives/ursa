extern crate libc;

use std::sync::mpsc::channel;
use std::ffi::CString;

use indy_crypto::api::bls::*;
use indy_crypto::api::ErrorCode;

use utils::callback::CallbackUtils;
use utils::timeout::TimeoutUtils;


pub struct BlsUtils {}

impl BlsUtils {
//    pub fn generate_keys(g: &str) -> Result<(String, String), ErrorCode> {
//        let (sender, receiver) = channel();
//
//        let cb = Box::new(move |err, sign_key, ver_key| {
//            sender.send((err, sign_key, ver_key)).unwrap();
//        });
//
//        let (command_handle, cb) = CallbackUtils::closure_to_generate_keys_cb_cb(cb);
//
//        let g = CString::new(g).unwrap();
//
//        let err =
//            indy_crypto_generate_keys(command_handle,
//                                      g.as_ptr(),
//                                      cb);
//
//        if err != ErrorCode::Success {
//            return Err(err);
//        }
//
//        let (err, sign_key, ver_key) = receiver.recv_timeout(TimeoutUtils::long_timeout()).unwrap();
//
//        if err != ErrorCode::Success {
//            return Err(err);
//        }
//
//        Ok((sign_key, ver_key))
//    }
//
//    pub fn sign(g: &str) -> Result<(String), ErrorCode> {
//        let (sender, receiver) = channel();
//
//        let cb = Box::new(move |err, signature| {
//            sender.send((err, sign_key, ver_key)).unwrap();
//        });
//
//        let (command_handle, cb) = CallbackUtils::closure_to_generate_keys_cb_cb(cb);
//
//        let g = CString::new(g).unwrap();
//
//        let err =
//            indy_crypto_generate_keys(command_handle,
//                                      g.as_ptr(),
//                                      cb);
//
//        if err != ErrorCode::Success {
//            return Err(err);
//        }
//
//        let (err, sign_key, ver_key) = receiver.recv_timeout(TimeoutUtils::long_timeout()).unwrap();
//
//        if err != ErrorCode::Success {
//            return Err(err);
//        }
//
//        Ok((sign_key, ver_key))
//    }
}
