use commitments::CommitmentScheme;

struct PedersenCommitment {}

impl CommitmentScheme for PedersenCommitment {
    // Returns `num_elements` + 1 generators. This is useful when committing to several messages say
    // m_1, m_2, m_3, and so on. `setup` will this output g_1, g_2, g_3, g_4 and so on which can then be
    // used for commitment f(g_1, g_2, g_3, g_4, ..., m_1, m_2, m_3...)
    fn setup(num_elements: u32) -> Vec<Vec<u8>> {
        unimplemented!();
    }

    fn commit(generators: &[&[u8]], messages: &[&[u8]]) -> Vec<u8> {
        unimplemented!();
    }

    fn verify(commitment: &[u8], opening: &[u8], generators: &[&[u8]], messages: &[&[u8]]) -> bool {
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