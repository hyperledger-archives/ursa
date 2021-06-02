# HYPERLEDGER URSA

[![Ursa CI](https://github.com/hyperledger/ursa/workflows/Ursa%20CI/badge.svg)](https://github.com/hyperledger/ursa/actions?query=workflow%3A%22Ursa+CI%22)
[![Build status](https://ci.appveyor.com/api/projects/status/1htmp82mdvmfjjap?svg=true)](https://ci.appveyor.com/project/hyperledger/ursa)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/2447/badge)](https://bestpractices.coreinfrastructure.org/projects/2447)

- [Introduction](#introduction)
- [Features](#features)
    - [Libursa](#Libursa)
    - [Libzmix](#libzmix)
- [Dependencies](#dependencies)
- [Building from source](#building-from-source)
- [Contributing](#contributing)

# Introduction

Ursa was created because people in the Hyperledger community realized that it
would save time and effort and improve security if we all collaborated on our
cryptographic code. Since cryptographic APIs are relatively straightforward to
define, it would be possible for many different projects to utilize the same
code without too much difficulty.

First and foremost, we hope in the long run that Ursa provides open-source
blockchain developers with reliable, secure, easy-to-use, and pluggable
cryptographic implementations.

# Features

The major artifacts of Ursa are:

- C-callable library interface
- Rust crate

Ursa is divided into two sub libraries: libursa and libzmix.

## Libursa

Designed for cryptographic primitives like simple digital signatures, encryption
schemes, and key exchange.

### Supported Signatures

- ECDSA
  - Secp256k1
- EdDSA
  - Ed25519 (Curve25519 in Twisted Edwards Form)
- Boneh Lynn Shacham (BLS) Signature
  - Any Pairing friendly curves
- Camenisch Lysyanskaya
  - RSA based
- Shamir Secret Sharing

### Supported Key Agreement

- ECDH
  - Secp256k1
  - X25519 (Curve25519 in Montgomery Form)

### Symmetric Encryption

- AES-CBC
- AES-GCM
- XCHACHA20-POLY1305

## Libzmix

A generic way to create zero-knowledge proofs, proving statements
about multiple cryptographic building blocks, containing signatures,
commitments, and verifiable encryption. Libzmix uses many of the building blocks
found in Libursa.

### Supported Zero Knowledge Proof capabilities
- Signature Proofs of Knowledge
- Bulletproofs
- Range proofs
- Set Membership

### Supported Signatures

- Boneh Boyen Shacham (BBS+)
  - Any Pairing friendly curves
- Pointcheval Saunders
  - Any pairing friendly curves
- Groth
  - Any Pairing friendly curves

# Dependencies

Ursa uses the following external dependencies:

- [openssl 1.1.0j or greater](https://www.openssl.org/source/openssl-1.1.0j.tar.gz) (Written in C)
- [libsodium 1.0.18 or greater](https://github.com/jedisct1/libsodium/archive/1.0.18.tar.gz) (Written in C)
- [libsecp256k1](https://github.com/bitcoin-core/secp256k1) (Written in C)

These dependencies are used when building in the default secure mode. These
libraries are widely known.  There is a goal to be able to compile Ursa from
rust only code for portability reasons like generating web assemblies without
the worry of compatibility issues from C code. For this reason, Ursa can be
compiled with *portable* mode which replaces any external libraries with rust
compatible code. Ursa developers take care when choosing suitable replacements
that are cryptographically safe to use but may not have been audited and vetted
in a similar manner to these external libraries. Ursa consumers should note this
when using portable mode for their applications.

# Building from Source

Libursa and Libzmix rely on libsodium for the default
secure mode. Please see the following document for specific platform
installations [here](docs/build-environment.md).

## Libursa

Libursa uses the rustc compiler with cargo. Go into the libursa
folder where the *Cargo.toml* lives.  Run the following commands to get the
default secure mode:
```bash
cargo build --release
```

Run the following commands to build in portable mode:

```bash
cargo build --release --no-default-features --features=portable
```

If you wish to take advantage of assembly level features, you can build
Ursa using the nightly compiler of rust.

```bash
cargo build --release --no-default-features --features=asm
```

The resulting artifact(s) can be found in the *target/release* folder. They
include:

    libursa.so (Linux)
    libursa.dylib (Mac OS X)
    libursa.a (Linux, Mac OS X)
    libursa.dll (Windows)
    libursa.lib (Windows)


## Packaging
Libursa can be packaged for debian builds using [cargo-deb](https://github.com/mmstick/cargo-deb).
To create a debian package, run the following command with cargo-deb installed

`cargo deb -p ursa` 

### Libursa Documentation

Libursa API documentation is now available as rust doc in code. See:
* C API
    - [BLS](./libursa/src/ffi/bls.rs)
    - [CL](./libursa/src/ffi/cl/)
* Rust API
    - [BLS](./libursa/src/bls/mod.rs)
    - [CL](./libursa/src/cl)

## Libzmix

Libzmix uses the rustc compiler with cargo. Go into the libzmix folder where the
*Cargo.toml* lives.  Run the following commands to get the default secure mode:
```bash
cargo build --release
```

Run the following commands to build in portable mode:

```bash
cargo build --release --no-default-features --features=portable
```

If you wish to take advantage of assembly level features, you can build
ZMix using the nightly compiler of rust.

```bash
cargo build --release --no-default-features --features=asm
```

The resulting artifact(s) can be found in the *target/release* folder. They
include:

    libzmix.so (Linux)
    libzmix.dylib (Mac OS X)
    libzmix.a (Linux, Mac OS X)
    libzmix.dll (Windows)
    libzmix.lib (Windows)
    
# Contributing

All bugs, stories, and backlog for this project are managed through
Hyperledger's Jira in project IS (note that regular Ursa tickets are in the URSA
project).

Also, join us on [Hyperledger Rocket.Chat](https://chat.hyperledger.org) at #ursa to discuss.

The ursa group also meets biweekly on Wednesday's at 7 AM PST at
https://zoom.us/my/hyperledger.community. The meeting notes are available
[here](https://wiki.hyperledger.org/display/ursa/Meeting+Agendas+and+Notes).

Major modifications to ursa are submitted as RFCs to the [Ursa RFC
repo](https://github.com/hyperledger/ursa-rfcs). 

For more details on contributing see [CONTRIBUTING](CONTRIBUTING.md)
