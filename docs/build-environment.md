# Setup your build environment
Libursa relies on libsodium for the default secure mode. The instructions below show the necessary steps to configure the environment to build all modes of libursa. There are convienance docker images in the **docker** folder that can be used.

## Fedora, RedHat, CentOS
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
4. Compile and install libsodium 1.0.16
```bash
curl -fsSL https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz | tar -xz
cd libsodium-1.0.16
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

## OpenSUSE
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
4. Compile and install libsodium 1.0.16
```bash
curl -fsSL https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz | tar -xz
cd libsodium-1.0.16
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

## Debian, Ubuntu
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
4. Compile and install libsodium 1.0.16
```bash
curl -fsSL https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz | tar -xz
cd libsodium-1.0.16
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

## Mac OS X
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
6. Compile and install libsodium 1.0.16
```bash
curl -fsSL https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz | tar -xz
cd libsodium-1.0.16
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

1. Download the most recent Visual Studio Community Edition [here](https://visualstudio.microsoft.com/vs/).  This is currently the 2019 version.
    - Check the box for *Desktop development with C++*
    - In the small menu on the right hand side also check the box for *C++/CLI support*
1. Download git-scm for windows [here](https://git-scm.com/download/win)
    - Install git for windows using:
    - *Use Git from Git Bash Only* so it doesn't change any path settings of the command prompt
    - *Checkout as is, commit Unix-style line endings*
    - *Use MinTTY*
    - Check all the boxes for:
        1. Enable file system caching
        1. Enable Git Credential Manager
        1. Enable symbolic links
1. Download rust for windows [here](https://rustup.rs)
    - Choose option 1: proceed with installation (default)
    - Note:  if you have antivirus software on your computer, you will likely have to disable it for Rust to correctly install.  In addition, it is advisable to install in a terminal that is "run as an administrator."
1. Download the most recent OpenSSL for windows [here](https://slproweb.com/products/Win32OpenSSL.html)
    - Choose for "Copy OpenSSL DLLs to:" *The OpenSSL binaries (/bin) directory*
1. Set the environment variables
    - Note that these may vary.  If your Ursa build fails because it cannot find OpenSSL, check your environment variables!
    - Windows command prompt:
        1. set OPENSSL_DIR "C:\Program Files\OpenSSL-Win64"
        1. set SODIUM_BUILD_STATIC "1"
    - Git Bash
        1. export OPENSSL_DIR=/c/Program Files/OpenSSL-Win64
        1. export SODIUM_BUILD_STATIC=1
