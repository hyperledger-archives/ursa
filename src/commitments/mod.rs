pub mod pedersen_BLS12_381;


// QUESTION: It would be better if we use generic group element for this trait so it can be used
// with Elliptic curves or IntegerMod groups like
// trait CommitmentScheme<T: Group> {
// fn setup(num_elements: u32) -> Vec<T:Element>;
trait CommitmentScheme {
    // Returns setup parameters.
    // The return type can be changed to Vec<GroupElement> when we define a `GroupElement` struct
    fn setup(num_elements: u32) -> Vec<Vec<u8>>;

    // Commits to `messages`. Returns a commitment
    fn commit(generators: &[&[u8]], messages: &[&[u8]]) -> Vec<u8>;

    // Takes the `opening` and check that the `commitment` was indeed done for the `messages`
    fn verify(commitment: &[u8], opening: &[u8], generators: &[&[u8]], messages: &[&[u8]]) -> bool;
}