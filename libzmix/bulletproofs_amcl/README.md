# Bulletproofs

1. Bulletproofs, based on the paper [Bulletproofs: Short Proofs for Confidential Transactions and More](https://eprint.iacr.org/2017/1066)
1. Implementation primarily intended for a pairing friendly curve. Only 2 curves are supported, BLS12-381 and BN254 for now. 
Defaults to BLS12-381. Curve can be changed by changing default feature.
1. Largely based on [dalek's Bulletproof implementation](https://github.com/dalek-cryptography/bulletproofs). 
dalek's is not used since it works over Ristretto curve but since Ursa's credentials are on a pairing friendly curve, 
the Bulletproof needs to work over the same curve. The code is distributed under the terms of both the MIT license and the Apache 2.0 License.
1. Uses [Apache Milagro](https://github.com/milagro-crypto/amcl) for finite field and elliptic curve operations.
1. R1CS support is present though the API differs from dalek's. For gadgets, check [here](src/r1cs/gadgets).

## License
Licensed under either of
- Apache License, Version 2.0, ([LICENSE-APACHE](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](./LICENSE-MIT) or http://opensource.org/licenses/MIT)
at your option.