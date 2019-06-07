use std::collections::HashMap;

/*
Hash function like hashing a message in a Group or a function like SHA-3 or BLAKE*.

Say you want to hash in group G1 of BLS12-381 curve, there would be an implementation of this
trait, say `BLS12_381_G1_Hash`
```
impl HashFunction for BLS12_381_G1_Hash .... {
    ......
}
let mut args = HashMap::new();
args.insert(
    "hash_function".to_string(), &[8, 198, 90, 120, .....], // results in string "SHA256"
);
let hf = BLS12_381_G1_Hash::new(Some(args));
let x = [100, 200, 250, 901, .....]
hf.update(&x)
hf.digest()
```

Say you want to hash with SHA-3 (or some new hash algo which does not have a vetted implementation),
there would be an implementation of this trait, say `SHA3_Hash`
``
impl HashFunction for SHA3_Hash .... {
    ......
}
let hf = BLS12_381_Hash::new(None);
let x = [100, 200, 250, 11, .....]
hf.update(&x)
let y = [234, 57, 99, 76, .....]
hf.update(&y)
hf.digest()
```
*/

#[derive(Debug)]
pub enum HashError {
    InvalidArgs(String),
    InvalidDigestLength(String),
}

pub trait HashFunction
where
    Self: Sized,
{
    // Creates a new one hash function. `args` is a map, some example args can be curve type,
    // curve order, key (in case of keyed hash function), compression support
    fn new(args: Option<HashMap<String, &[u8]>>) -> Result<Self, HashError>;

    // Updates the hash object. Can be called any number of times
    fn update(&mut self, input: &[u8]);

    // Returns the digest. Length is passed as `Some(<some lenght>)` in case of an XOF like SHAKE;
    // `None` otherwise
    fn digest(&self, length: Option<usize>) -> Result<Vec<u8>, HashError>;
}

pub mod bls12_381_hash;
