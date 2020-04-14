[Short group signatures](https://crypto.stanford.edu/~xb/crypto04a/groupsigs.pdf) by Boneh, Boyen, and Shachum
and later improved in [ASM](http://web.cs.iastate.edu/~wzhang/teach-552/ReadingList/552-14.pdf) as BBS+ and touched on again
in section 4.3 in [CDL](https://eprint.iacr.org/2016/663.pdf).
---
This crate implements the BBS+ signature scheme which allows for signing many committed messages.

BBS+ signatures can be created in typical cryptographic fashion where the signer and signature holder are the same
party or where they are two distinct parties. BBS+ signatures can also be used to generate signature proofs of knowledge
and selective disclosure zero-knowledge proofs. To start, all that is needed is to add this to your `Cargo.toml`.

```toml
[dependencies]
bbs = "0.2"
```

Add in the main section of code to get all the traits, structs, and functions needed.

```rust
use bbs::prelude::*;
```

## Keygen

BBS+ supports two types of public keys. One that is created as described in the paper where the message specific generators
are randomly generated as 
and a deterministic version that looks like a BLS public key and the message specific generators are computed using
IETF's [Hash to Curve](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1) algorithm which is also constant time combined with known inputs.

`generate(message_count: usize)` - returns a keypair used for creating BBS+ signatures

`PublicKey` - *w &xlarr; &#x1D53E;<sub>2/sub>, h<sub>0</sub>, (h<sub>1</sub>, ... , h<sub>L</sub>) &xlarr; &#x1D53E;<sub>1</sub><sup>L</sup>*

`DeterministicPublicKey` - *w &xlarr; &#x1D53E;<sub>2</sub>*. This can be converted to a public key by calling the `to_public_key` method.

There is a convenience class `Issuer` that can be used for this as well.

```rust
let (pk, sk) = Issuer::new_keys(5).unwrap();
```

or 

```rust
let (dpk, sk) = Issuer::new_short_keys(None);
let dst = DomainSeparationTag::new("testgen", None, None, None).unwrap();
let pk = dpk.to_public_key(5, dst).unwrap();
```

## Signing

Signing can be done where the signer knows all the messages or where the signature recipient commits to some messages beforehand
and the signer completes the signature with the remaining messages.

To create a signature:

```rust
let messages = vec![
    SignatureMessage::from_msg(b"message 1"),
    SignatureMessage::from_msg(b"message 2"),
    SignatureMessage::from_msg(b"message 3"),
    SignatureMessage::from_msg(b"message 4"),
    SignatureMessage::from_msg(b"message 5"),
];

let signature = Signature::new(messages.as_slice(), &sk, &pk).unwrap();

assert!(signature.verify(messages.as_slice(), &pk));
```

or

```rust
// Done by the signature recipient
let message = SignatureMessage::from_msg_hash(b"message_0");

let signature_blinding = Signature::generate_blinding();

let commitment = &pk.h[0] *&messages[0] + &pk.h0 * &signature_blinding; 

// Completed by the signer
// `commitment` is received from the recipient

let mut messages = BTreeMap::new(); 
messages.insert(1, SignatureMessage::from_msg_hash(b"message_1"));
messages.insert(2, SignatureMessage::from_msg_hash(b"message_2"));
messages.insert(3, SignatureMessage::from_msg_hash(b"message_3"));
messages.insert(4, SignatureMessage::from_msg_hash(b"message_4"));

let blind_signature = BlindSignature::new(&commitment, &messages, &pk, &sk).unwrap();

// Completed by the recipient
// receives `blind_signature` from signer
// Recipient knows all `messages` that are signed

let signature = blind_signature.to_unblinded(&signature_blinding);

assert!(signature.verify(messages.as_slice(), &pk));
```

This by itself is considered insecure without the signer completing a proof of knowledge of committed messages generated
by the recipient and sent with the commitment. It is **IMPORTANT** that the signature issuer complete this step.
For simplicity, the `Issuer` and `Prover` structs can be used as follows to handle this.

```rust
let signing_nonce = Issuer::generate_signing_nonce();

// Send `signing_nonce` to holder

// Recipient wants to hide a message in each signature to be able to link 
// them together
let link_secret = Prover::new_link_secret();
let mut messages = BTreeMap::new();
messages.insert(0, link_secret);
let (ctx, signature_blinding) = Prover::new_blind_signature_context(&pk, &messages, &signing_nonce).unwrap();

// Send `ctx` to signer
let mut messages = BTreeMap::new(); 
messages.insert(1, SignatureMessage::from_msg_hash(b"message_1"));
messages.insert(2, SignatureMessage::from_msg_hash(b"message_2"));
messages.insert(3, SignatureMessage::from_msg_hash(b"message_3"));
messages.insert(4, SignatureMessage::from_msg_hash(b"message_4"));
// Will fail if `ctx` is invalid
let blind_signature = Issuer::blind_sign(&ctx, messages.as_slice(), &sk, &pk).unwrap();
 
// Send `blind_signature` to recipient
// Recipient knows all `messages` that are signed

let signature = Prover::complete_signature(&pk, messages.as_slice(), &blind_signature, &signature_blinding).unwrap();
```