#!/bin/sh
set -eo pipefail

PKG_DIR=../wrappers/javascript/dist

cd ../../libindy-crypto
PKG_CONFIG_ALLOW_CROSS=1 cargo +nightly build --lib --release --target wasm32-unknown-unknown \
--features wasm,serialization,pair_amcl --no-default-features
rm -rf $PKG_DIR && mkdir $PKG_DIR
wasm-bindgen target/wasm32-unknown-unknown/release/indy_crypto.wasm \
--out-dir $PKG_DIR --nodejs
