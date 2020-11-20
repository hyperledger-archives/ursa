# Ursa Sharing

This crate provides various cryptography secret sharing schemes.

This is intended to be a mid-level API by providing the secret sharing schemes without any specific
finite field or big number library. The only requirement, is to implement the traits `Group` and `Field` from this library.
The implementer must have a basic understanding of finite fields. The [examples](examples) folder shows
how this can be done for various elliptic curves.

The first scheme is by Adi Shamir in '79 - [Shamir Secret Sharing](#shamir).

The second scheme is by Paul Feldman in '87 - [Feldman Verifiable Secret Sharing](#feldman).

The third scheme is by Torben Pedersen in '91 - [Pedersen Verifiable Secret Sharing](#pedersen).

Each of these can be used in sub protocols like threshold signatures or [distributed key generation](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.134.6445&rep=rep1&type=pdf)  

## Getting started

Once these traits are implemented for the secret field, the secret can be split into shares using `shamir::Scheme`.

To use Feldman or Pedersen with elliptic curves, `Group` will need to be implemented for the group elements as well as the field elements.

Each scheme requires specifying the threshold and the maximum number of shares to create.

```rust
let scheme = Scheme::new(threshold, limit);
```

To split a secret, we also need a cryptographically secure pseudorandom number generator (CSPRNG).
Secrets should be valid members of the field to prevent malleability i.e. multiple values could represent the
same secret.

Shamir
```rust
let shares = scheme.split_secret(&mut rng, &secret)?;
```

Feldman's Verifiable Secret Sharing returns cryptographic commitments to the polynomial allowing the shares to be verified before
combining shares. The default generator to use for the commitments is the value returned by the field parameter `R::random()`.

Feldman
```rust
let (verifier, shares) = scheme.split_secret(&mut rng, &secret, None)?;

for share in &shares {
    scheme.verify_share(&share, &verifier)?;
}
``` 

Verify share returns void on success but an error on failure. Verification is performed by
computing the sum of products c_0 * c_1^i * c_2^{i^2} ... c_t^{i^t} and 
comparing against specified share.

Pedersen's Verifiable Secret Sharing adds an additional blinding factor when splitting and thus requires an additional
generator. If no generator is specified for the blinding factor, a random one is used.

Pedersen
```rust
let result = scheme.split_secret(&mut rng, &secret, None, None)?;

let secret_shares = result.secret_shares;
let blinding_shares = result.blinding_shares;

for i in 0..secret_shares.len() {
    scheme.verify_share(secret_shares[i], blinding_shares[i], &result.verifier)?;
}
```

Each scheme has the same API for combining shares to reconstruct the original secret.
Obviously, at least the threshold number of shares are required to combine successfully. Otherwise it returns an error.

```rust
let secret = scheme.combine_shares(shares.as_slice())?;
```

# References

1. [How to share a secret, Shamir, A. Nov, 1979](https://dl.acm.org/doi/pdf/10.1145/359168.359176)
1. [A Practical Scheme for Non-interactive Verifiable Secret Sharing, Feldman, P. 1987](https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf)
1. [Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing, Pedersen, T. 1991](https://link.springer.com/content/pdf/10.1007%2F3-540-46766-1_9.pdf)
