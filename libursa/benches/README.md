
# Ursa Benchmarks

All benchmarks were performed on a commodity machine running macOS.

Run benchmarks on your system using: `cargo bench -p ursa`

## Signatures

Ed25519 is fastest and therefore used as the baseline. All its operations were on
the order of 10<sup>1</sup> µs.

Numbers in the table reflect how long an operation took relative to the baseline.
For instance, 10<sup>2</sup> means that the operation took approximately 100 times
longer for the given signature than for Ed25519.


| Signature     | Path (from `src`)        | Create Key | Sign | Verify |
| ------------- | ------------------------ | --------:| --------:| --------:|
| Ed25519       | `signatures/ed25519.rs`  |   1 | 1 | 1 |
| Secp256k1     | `signatures/secp256k1.rs`| 10<sup>2</sup>| 10<sup>2</sup>| 10<sup>2</sup>|
| BLS           | `bls/mod.rs`             | 10<sup>1</sup>| 10<sup>1</sup>| 10<sup>2</sup>|
