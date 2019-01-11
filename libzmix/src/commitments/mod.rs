use hash_functions::HashError;

#[derive(Debug)]
pub enum CommitmentError {
    ZeroCountInPedersenSetup(String),
    InvalidPointSize(usize, usize),
    InvalidBigNumSize(usize, usize),
    ZeroMessageCount(String),
    InvalidGeneratorCount(usize, usize),
    HashError(HashError)
}

impl From<HashError> for CommitmentError {
    fn from(err: HashError) -> CommitmentError {
        CommitmentError::HashError(err)
    }
}

// QUESTION: It would be better if we use generic group element for this trait so it can be used
// with Elliptic curves or IntegerMod groups like
// trait CommitmentScheme<T: Group> {
// fn setup(num_elements: u32) -> Vec<T:Element>;
trait CommitmentScheme {
    // Returns setup parameters.
    // The return type can be changed to Vec<GroupElement> when we define a `GroupElement` struct
    fn setup(num_elements: usize) -> Result<Vec<Vec<u8>>, CommitmentError>;

    // Commits to `messages`. Returns a commitment
    fn commit(generators: &[&[u8]], messages: &[&[u8]]) -> Result<(Vec<u8>, Vec<u8>), CommitmentError>;

    // Takes the `opening` and check that the `commitment` was indeed done for the `messages`
    fn verify(commitment: &[u8], opening: &[u8], generators: &[&[u8]], messages: &[&[u8]]) -> Result<bool, CommitmentError>;
}

pub mod pedersen_BLS12_381;
