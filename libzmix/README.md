# Short Description
z-mix is a general purpose library to create Zero-Knowledge proofs, proving statements about multiple cryptographic building blocks, containing signatures, commitments, and verifiable encryption.
z-mix facilitates

Multiple existing Hyperledger projects require Zero-Knowledge proofs, e.g., Fabric and Indy. The goal of this library is to provide a single flexible and secure implementation to construct such proofs.
z-mix is a C callable library but there are also convenience wrappers for various programming languages.

# Initial Committers
* Manu Drijvers (manudrijvers)
* Jan Camenisch (jancamenisch)
* Nathan George (nage)
* Daniel Hardman (dhh1128)
* Angelo De Caro (adecaro)
* Maria Dubovitskaya (dubovitskaya)
* Jason Law (jasonalaw)
* Michael Lodder (mikelodder7)
* Lovesh Harchandani (lovesh)

# Sponsors
* Nathan George
* Hart Montgomery

# Spec
z-mix uses JSON objects to provide a *zero knowledge language (ZKL)* to express

* Requests of attested attribute values
* Resolutions for requests that can be validated
* Proofs that satisfy requests

### Process
z-mix translates a ZKL-ProofSpec and a corresponding ZKL-Witness, both represented as JSON objects, into a ZKL-Proof JSON object.

The **ZKL-ProofSpec** defines the statement to be proven and contains all public information needed by a verifier \[e.g., Credential Definitions, Revocation Authority, Pseudonyms].

The **ZKL-Witness** contains the secrets required to compute a proof \[e.g. secret keys, all attribute values, the credentials involved, the randomness used to compute a pseudonym].

The **ZKL Proof** is the data that satisfies the statement to be proven.

### Examples

z-mix is written in Rust. z-mix can be included into other Rust projects by adding the following to the Cargo.toml:

```toml
z_mix = { version = "0.1", git = "https://github.com/hyperledger-labs/z-mix.git" }
```

An example how to use in your rust project

```rust
extern crate z_mix;

use z_mix::zkl::{Parser, ProofSpecBuilder, WitnessBuilder};

fn main() {
    let mut proof_spec_builder = ProofSpecBuilder::new();

    // Add proof spec data

    let mut witness_builder = WitnessBuilder::new();

    // Add witness data

    let proof_spec = proof_spec_builder.finish();
    let witness = witness_builder.finish();

    match Parser::parse(&proof_spec, &witness) {
        Ok(proof) => {
            match proof.verify(&proof_spec) {
                Ok(v) => println!("Proof result - {}", v),
                Err(pe) => panic!("Proof::verify encountered an error - {:?}", pe)
            }
        },
        Err(e) => panic!("Parser::parse encountered an error - {:?}", e)
    };
}
```

