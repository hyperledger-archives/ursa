trait HashFunction {
    // Creates a new one hash function. `args` is a map, some example args can be curve type,
    // curve order, key (in case of keyed hash function), compression support
    fn new(args: Map<String, &[u8]>) -> Self;

    // Updates the hash object. Can be called any number of times
    fn update(&self, input: &[u8]);

    // Returns the digest. Length is passed as `Some(<some lenght>)` in case of an XOF like SHAKE;
    // `None` otherwise
    fn digest(&self, length: Option<usize>) -> Vec<u8>;
}