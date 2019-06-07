use std::collections::HashMap;

/*
Pseudo Random Function like modular exponentiation.
Say you want to exponentiate in a prime field `p` with generator `g`, there would be an implementation of this
trait, say `ModExpPrimeField`
```
impl PRF for ModExpPrimeField .... {
    ......
}
let mut args = HashMap::new();
args.insert(
    "field_size".to_string(), &[8, 198, 90, 120, .....],
    "generator".to_string(), &[90, 2, 34, 55, .....],
);
let owf = ModExpPrimeField::new(args);
let x = [100, 200, 250, 901, .....]
owf.compute(&x)
```
*/
trait PRF {
    // Creates a new Pseudo Random Function. `args` is a map, some example args can be curve type,
    // curve order, compression support.
    fn new(args: HashMap<String, &[u8]>) -> Self;

    // Compute the one way function.
    fn compute(&self, input: &[u8]) -> Vec<u8>;
}
