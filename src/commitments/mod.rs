pub mod pedersen;


// QUESTION: It would be better if we use generic group element for this trait so it can be used
// with Elliptic curves or IntegerMod groups like
// trait CommitmentScheme<T: Group> {
// fn setup(num_elements: u32) -> Vec<T:Element>;
trait CommitmentScheme {
    // Returns `num_elements` + 1 generators. This is useful when committing to several messages say
    // m_1, m_2, m_3, and so on. `setup` will this output g_1, g_2, g_3, g_4 and so on which can then be
    // used for commitment f(g_1, g_2, g_3, g_4, ..., m_1, m_2, m_3...)
    // The return type can be changed to Vec<GroupElement> when
    // we define a `GroupElement` struct
    fn setup(num_elements: u32) -> Vec<Vec<u8>>;

    // Commits to `messages`. Returns a commitment
    fn commit(generators: &[&[u8]], messages: &[&[u8]]) -> Vec<u8>;

    // Takes the `secret` and check that the `commitment` was indeed done for the `messages`
    fn open(commitment: &[u8], secret: &[u8], generators: &[&[u8]], messages: &[&[u8]]) -> bool;
}