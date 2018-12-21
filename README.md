# Hyperledger Ursa

Ursa was created because people in the Hyperledger community realized that it would save time and effort and improve security if we all collaborated on our cryptographic code. Since cryptographic APIs are relatively straightforward to define, it would be possible for many different projects to utilize the same code without too much difficulty.

First and foremost, we hope in the long run that Ursa provides open-source blockchain developers with reliable, secure, easy-to-use, and pluggable cryptographic implementations.

The major artifacts of Ursa are:
- C-callable library interface
- Rust crate

All bugs, stories, and backlog for this project are managed through Hyperledger's Jira in project IS (note that regular Ursa tickets are in the URSA project). Also, join us on [Hyperledger Rocket.Chat](https://chat.hyperledger.org) at #ursa to discuss. The ursa group also meets biweekly on Wednesday's at 7 AM PST at https://zoom.us/my/hyperledger.community. The meeting notes are available [here](https://docs.google.com/document/d/1Z_8o8k_PFRM4XfZyv9jH1_-IyN0CsCMI2JlrGsCX378/edit).

Major modifications to ursa are submitted as RFCs to the [Ursa RFC repo](https://github.com/hyperledger/ursa-rfcs). 

Ursa is divided into two sub libraries: libursa and libzmix.

Libursa is designed for cryptographic primitives like simple digital signatures, encryption schemes, and key exchange.

Libzmix offers a generic way to create zero-knowledge proofs, proving statements about multiple cryptographic building blocks, containing signatures, commitments, and verifiable encryption. Libzmix uses many of the building blocks found in Libursa.

## Dependencies

Ursa and zmix use the following external dependencies:

- libsodium 1.0.14 (Written in C)
- openssl 1.1.0j or newer (Written in C)
- libsecp256k1 (Written in C)

These dependencies are used when building in the default secure mode. These libraries are widely known.
There is a goal to be able to compile Ursa from rust only code for portability reasons like generating web assemblies without
the worry of compatibility issues from C code. For this reason, Ursa can be compiled with *portable* mode which replaces any external
libraries with rust compatible code. Ursa developers take care when choosing suitable replacements that are cryptographically safe to use
but may not have been audited and vetted in a similar manner to these external libraries. Ursa consumers should note this when using
portable mode for their applications.

## Building Libursa from Source

Libursa uses the rustc compiler with cargo. Go into the libursa folder where the *Cargo.toml* lives.
Run the following commands to get the default secure mode:
```bash
cargo build --release
```

Run the following commands to build in portable mode:

```bash
cargo build --release --no-default-features --features=portable
```

The resulting artifact(s) can be found in the *target/release* folder. They include:

    libursa.so (Linux)
    libursa.dylib (Mac OS X)
    libursa.a (Linux, Mac OS X)
    libursa.dll (Windows)
    libursa.lib (Windows)

## Building Libzmix from Source

Libzmix uses the rustc compiler with cargo. Go into the libzmix folder where the *Cargo.toml* lives.
Run the following commands to get the default secure mode:
```bash
cargo build --release
```

Run the following commands to build in portable mode:

```bash
cargo build --release --no-default-features --features=portable
```

The resulting artifact(s) can be found in the *target/release* folder. They include:

    libzmix.so (Linux)
    libzmix.dylib (Mac OS X)
    libzmix.a (Linux, Mac OS X)
    libzmix.dll (Windows)
    libzmix.lib (Windows)

## Setup the build environment
Libursa relies on libsodium for the default secure mode. The instructions below show the necessary steps to configure the environment to build all modes of libursa. There are convienance docker images in the **docker** folder that can be used.

### Fedora, RedHat, CentOS
1. Install build tools
```bash
yum -y install make autoconf libtool curl python3 pkg-config openssl-devel
```
2. Install rust
```bash
curl -sSf https://sh.rustup.rs | sh -s -- -y
```
3. Initialize rust environment
```bash
source ~/.cargo/env
```
4. Compile and install libsodium 1.0.14
```bash
curl -fsSL https://github.com/jedisct1/libsodium/releases/download/1.0.14/libsodium-1.0.14.tar.gz | tar -xz
cd libsodium-1.0.14
./autogen.sh
./configure --disable-dependency-tracking
make
sudo make install
```
5. Add the libsodium environment variable
```bash
export SODIUM_LIB_DIR=/usr/local/lib
export LD_LIBRARY_PATH=/usr/local/lib
```

### OpenSUSE
1. Install build tools
```bash
zypper --non-interactive install make gcc autoconf libtool curl python3 pkg-config openssl-devel
```
2. Install rust
```bash
curl -sSf https://sh.rustup.rs | sh -s -- -y
```
3. Initialize rust environment
```bash
source ~/.cargo/env
```
4. Compile and install libsodium 1.0.14
```bash
curl -fsSL https://github.com/jedisct1/libsodium/releases/download/1.0.14/libsodium-1.0.14.tar.gz | tar -xz
cd libsodium-1.0.14
./autogen.sh
./configure
make
sudo make install
```
5. Add the libsodium environment variable
```bash
export SODIUM_LIB_DIR=/usr/local/lib
export LD_LIBRARY_PATH=/usr/local/lib
```

### Debian, Ubuntu
1. Install build tools
```bash
apt-get install -y cmake autoconf libtool curl python3 pkg-config libssl-dev
```
2. Install rust
```bash
curl -sSf https://sh.rustup.rs | sh -s -- -y
```
3. Initialize rust environment
```bash
source ~/.cargo/env
```
4. Compile and install libsodium 1.0.14
```bash
curl -fsSL https://github.com/jedisct1/libsodium/releases/download/1.0.14/libsodium-1.0.14.tar.gz | tar -xz
cd libsodium-1.0.14
./autogen.sh
./configure
make
sudo make install
```
5. Add the libsodium environment variable
```bash
export SODIUM_LIB_DIR=/usr/local/lib
export LD_LIBRARY_PATH=/usr/local/lib
```

### Mac OS X
1. Install xcode command line tools 
```bash
xcode-select --install
```
2. Install rust
```bash
curl -sSf https://sh.rustup.rs | sh -s -- -y
```
3. Install brew
```bash
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```
4. Install build tools
```bash
brew install pkg-config
brew install automake
brew install autoconf
brew install cmake
brew install libtool
```
5. Initialize rust environment
```bash
source ~/.cargo/env
```
6. Compile and install libsodium 1.0.14
```bash
curl -fsSL https://github.com/jedisct1/libsodium/releases/download/1.0.14/libsodium-1.0.14.tar.gz | tar -xz
cd libsodium-1.0.14
./autogen.sh
./configure --prefix=/usr/local
make
sudo make install
```
7. Add the libsodium environment variable
```bash
export SODIUM_LIB_DIR=/usr/local/lib
```

## Windows 10

1. Setup a windows virtual machine. Free images are available [here](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/)
1. Download Visual Studio Community Edition 2017 [here](https://visualstudio.microsoft.com/downloads/)
1. Check the boxes for *Desktop development with C++* and *Linux Development with C++*
1. In the summary portion on the right hand side also check *C++/CLI support*
1. Click install
1. Download git-scm for windows [here](https://git-scm.com/downloads/win)
1. Install git for windows using:
    - *Use Git from Git Bash Only* so it doesn't change any path settings of the command prompt
    - *Checkout as is, commit Unix-style line endings*
    - *Use MinTTY*
    - Check all the boxes for:
        1. Enable file system caching
        1. Enable Git Credential Manager
        1. Enable symbolic links
1. Download rust for windows [here](https://win.rustup.rs)
    - Choose option *1*
1. Download openssl for windows [here](https://slproweb.com/download/Win64OpenSSL-1_1_0j.exe)
    - Choose for "Copy OpenSSL DLLs to:" *The OpenSSL binaries (/bin) directory*
1. Set the environment variables
    - Windows command prompt:
        1. set OPENSSL_DIR "C:\OpenSSL-Win64"
        1. set SODIUM_BUILD_STATIC "1"
    - Git Bash
        1. export OPENSSL_DIR=/c/OpenSSL-Win64
        1. export SODIUM_BUILD_STATIC=1
