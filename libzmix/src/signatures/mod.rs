use std::collections::HashMap;

/*
Say you want to have an ECDSA signature using curve secp256k1, and the implementation is called
ECDSA_secp256k1
```
impl SignatureScheme for ECDSA_secp256k1 .... {
    ......
}
let mut args = HashMap::new();
args.insert(
    "hash_function".to_string(), &[90, 12, 33, 45, .....], // results in string "RIPEMD160"
);
let sig_scheme = ECDSA_secp256k1::new(Some(&args));
let (sk, vk) = sig_scheme.gen_keypair(None);
let msg = vec![2, 4, 6, ...];
let sig = sig_scheme.sign(&msg, &sk, None);
sig_scheme.verify(&sig, &msg, &vk);
```
*/

trait SignatureScheme {
    // This outputs a new `SignatureScheme` object initialised with necessary system params.
    // Equivalent to "Setup" in literature
    fn new(args: Option<HashMap<String, &[u8]>>) -> Self;
    // Generates a Signing key, Verification key pair. The "seed" or other parameters
    // can be part of `args`
    fn gen_keypair(&self, args: Option<HashMap<String, &[u8]>>) -> (Vec<u8>, Vec<u8>);

    // Generate signature on a message `message` using signing key `sig_key`.
    fn sign(&self, message: &[u8], sig_key: &[u8], extra: Option<&[u8]>) -> Vec<u8>;

    // Verify signature `signature` on a message `message` using verification key `ver_key`
    fn verify(&self, signature: &[u8], message: &[u8], ver_key: &[u8]) -> bool;
}