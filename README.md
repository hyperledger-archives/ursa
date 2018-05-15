
## Before you Continue

If you haven't done so already, please visit the main resource for all things "Indy" to get acquainted with the code base, helpful resources, and up-to-date information: [Hyperledger Wiki-Indy](https://wiki.hyperledger.org/projects/indy).

# Indy Crypto

This is the shared crypto libirary for [Hyperledger Indy](https://www.hyperledger.org/projects) components.

[Hyperledger Indy](https://www.hyperledger.org/projects) provides a distributed-ledger-based foundation for [self-sovereign identity](https://sovrin.org).

The major artifacts of the Indy Crypto are:
* С-callable library interface
* Rust сrate
* Python wrapper

All bugs, stories, and backlog for this project are managed through [Hyperledger's Jira](https://jira.hyperledger.org)
in project IS (note that regular Indy tickets are in the INDY project instead...). Also, join
us on [Jira's Rocket.Chat](chat.hyperledger.org) at #indy-sdk to discuss.

## Building Indy Crypto

1. Install Rust and rustup (https://www.rust-lang.org/install.html).
1. Checkout and build the library:

   ```
   git clone https://github.com/hyperledger/indy-crypto.git
   cd ./indy-crypto/libindy-crypto
   cargo build
   cd ..
   ```
1. Run tests
   ```
   cd libindy-crypto
   cargo test
   ```
**Note:**
By default `cargo build` produce debug artifacts with a large amount of run-time checks.
It's good for development, but this build can be in 100+ times slower for some math calculation.
If you would like to analyse CPU performance of libindy-crypto for your use case, you have to use release artifacts (`cargo build --release`).

### Windows build dependency
System OpenSSL library is required.
- Download the prebuilt dependencies [here](https://repo.sovrin.org/windows/libindy_crypto/deps/)
- Extract them into the folder _C:\BIN\x64_
> It really doesn't matter where you put these as long as you remember where so you can set
> the environment variables to this path
- Point path to this directory using environment variables:
  - set INDY_CRYPTO_PREBUILT_DEPS_DIR=C:\BIN\x64
  - set OPENSSL_DIR=C:\BIN\x64

## API Documentation

API documentation is now available as rust doc in code. See:
* C API
    - [BLS](libindy-crypto/src/ffi/bls.rs)
    - [CL](libindy-crypto/src/ffi/cl)
* Rust API
    - [BLS](libindy-crypto/src/bls/mod.rs)
    - [CL](libindy-crypto/src/cl)

## Wrappers documentation

* [Python](wrappers/python/README.md)

## Binaries

Note: Binaries creation is in progress now!!!

Builded binaries can be downloaded from https://repo.sovrin.org:
* sdk/lib/apt/xenial/{master,stable,rc} - Ubuntu deb packages
* windows/libindy_crypto/{master,stable,rc} - Windows zip-archive with all required DLLs (include libindy itself) and headers
* ios/libindy_crypto/stable/ - Pods for iOS
* rhel/libindy_crypto/{master,stable,rc} - RHEL rpms

Also Ubundu deb packages can be installed from APT repository:
```
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 68DB5E88
sudo add-apt-repository "deb https://repo.sovrin.org/sdk/deb xenial stable"
sudo apt-get update
sudo apt-get install -y libindy-crypto
```

