trait OneWayFunction {
    // Creates a new one way function. `args` is a map, some example args can be curve type,
    // curve order, compression support.
    fn new(args: Map<String, &[u8]>) -> Self;

    // Compute the one way function.
    fn compute(&self, input: &[u8]) -> Vec<u8>;
}