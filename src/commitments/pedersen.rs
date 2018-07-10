use commitments::CommitmentScheme;

struct PedersenCommitment {}

impl CommitmentScheme for PedersenCommitment {
    fn setup(num_elements: u32) -> Vec<Vec<u8>> {
        unimplemented!();
    }

    fn commit(generators: &[&[u8]], messages: &[&[u8]]) -> Vec<u8> {
        unimplemented!();
    }

    fn open(commitment: &[u8], secret: &[u8], generators: &[&[u8]], messages: &[&[u8]]) -> bool {
        unimplemented!();
    }
}

// Alternate implementation

/*
impl<Group> CommitmentScheme for PedersenCommitment {
    fn setup(num_elements: u32) -> Vec<Group::Element> {
        unimplemented!();
    }
}
*/