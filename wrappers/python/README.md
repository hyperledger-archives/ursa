<a href="https://sovrin.org/" target="_blank"><img src="https://avatars2.githubusercontent.com/u/22057628?v=3&s=50" align="right"></a>

## Indy Crypto for Python

This is a Python wrapper for [Indy](https://www.hyperledger.org/projects/indy). It is implemented using a foreign function interface (FFI) to a native library written in Rust. Indy is the
open-source codebase behind the Sovrin network for self-sovereign digital identity.

This Python wrapper currently requires python 3.6.

Pull requests welcome!

### How to build

- Install native "Indy Crypto" library:
	* Ubuntu:  https://repo.evernym.com/libindy-crypto/ubuntu/
	* Windows: https://repo.evernym.com/libindy-crypto/windows/

- Clone indy-crypto repo from https://github.com/hyperledger/indy-crypto

- Move to python wrapper directory 
```
	cd wrappers/python
```
- Create virtual env if you want

- Install dependencies with pip install

- Execute tests with pytest


### PyPi package
[python3-indy_crypto](https://pypi.python.org/pypi/python3-indy-crypto) package is available.

### Example use
For the main workflow examples check sample project: https://github.com/hyperledger/indy-crypto/samples/python
