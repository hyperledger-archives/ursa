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

## Wrappers documentation

Note: Wrappers creation is in progress now!!!
* [Python](wrappers/python/README.md)

## Binaries

Note: Binaries creation is in progress now!!!

Builded binaries can be downloaded from https://repo.evernym.com/libindy-crypto:
* ubuntu/{master,stable,rc} - Ubuntu deb packages
* windows/{master,stable,rc} - Windows zip-archive with all required DLLs (include libindy itself) and headers
* ios/stable/ - Pods for iOS
* rhel/{master,stable,rc} - RHEL rpms
