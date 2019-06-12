# Bulletproofs

1. Bulletproofs implementation primarily intended for a pairing friendly curve. Only 2 curves are supported, BLS12-381 and BN254 for now. 
Defaults to BLS12-381. Curve can be changed by changing default feature.
2. Largely based on [dalek's Bulletproof implementation](https://github.com/dalek-cryptography/bulletproofs). 
dalek's is not used since it works over Ristretto curve but since Ursa's credentials are on a pairing friendly curve, 
the Bulletproof needs to work over the same curve. 
3. Uses [Apache Milagro](https://github.com/milagro-crypto/amcl) for finite field and elliptic curve operations.
4. R1CS support is present though the API differs from dalek's. For gadgets, check [here](src/r1cs/gadgets).