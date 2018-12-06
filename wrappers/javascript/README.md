## Indy Crypto for JavaScript

This is a JavaScript wrapper for [Hyperledger Indy](https://www.hyperledger.org/projects/indy).
It is implemented as [WebAssembly](https://webassembly.org/) (WASM) bindings generated from the
original Rust library, using [wasm-bindgen](https://rustwasm.github.io/wasm-bindgen/).

The WASM bindings code exists beneath the directory src/wasm, and is all organized into a feature
called 'wasm'. This feature is disabled by default. The bindings expose only the BLS functionality
of libindy-crypto.

### How to Build

Within this directory, do the following:

1. Verify that rustc is v1.30 or higher
2. Install rustup: `curl https://sh.rustup.rs -sSf | sh`
3. `rustup target add --toolchain nightly wasm32-unknown-unknown`
4. `cargo +nightly install wasm-bindgen-cli`
5. `npm install`
6. `npm run build`

### How to Test

Within this directory, invoke `npm test`.

### Examples
There are examples of using this library in the examples/ directory.