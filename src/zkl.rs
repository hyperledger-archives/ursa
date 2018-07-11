pub struct Parser {}

impl Parser {
    pub fn parse(proof_spec: &ProofSpec, witness: &Witness) -> Result<Proof, ParseError> {
        unimplemented!();
    }
}

pub struct ProofSpec {}

pub struct ProofSpecBuilder {}

pub struct Witness {}

pub struct WitnessBuilder {}

pub struct Proof {}

impl Proof {
    pub fn verify(&self, proof_spec: &ProofSpec) -> Result<bool, ParseError> {
        unimplemented!();
    }
}

#[repr(i32)]
#[derive(Debug, Eq, PartialEq)]
pub enum ParseError {
    InvalidProofSpec = 1,
    InvalidWitness = 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_clause() {
        let proof_spec = ProofSpec{};
        let witness = Witness{};
        let result = Parser::parse(&proof_spec, &witness);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, ParseError::InvalidProofSpec);
        }
    }

    #[test]
    fn parse_credential_clause() {
        //TODO: Add credential clause to the proof_spec
        let proof_spec = ProofSpec{};
        let witness = Witness{};
        assert!(Parser::parse(&proof_spec, &witness).is_ok());
    }

    #[test]
    fn parse_interval_clause() {
        //TODO: Add interval clause to the proof_spec
        let proof_spec = ProofSpec{};
        let witness = Witness{};
        assert!(Parser::parse(&proof_spec, &witness).is_ok());
    }

    #[test]
    fn parse_set_membership_clause() {
        //TODO: Add set membership clause to the proof_spec
        let proof_spec = ProofSpec{};
        let witness = Witness{};
        assert!(Parser::parse(&proof_spec, &witness).is_ok());
    }

    #[test]
    fn parse_verifiable_encryption_clause() {
        //TODO: Add verifiable encryption clause to the proof_spec
        let proof_spec = ProofSpec{};
        let witness = Witness{};
        assert!(Parser::parse(&proof_spec, &witness).is_ok());
    }

    #[test]
    fn parse_nym_clause() {
        //TODO: Add nym clause to the proof_spec
        let proof_spec = ProofSpec{};
        let witness = Witness{};
        assert!(Parser::parse(&proof_spec, &witness).is_ok());
    }

    #[test]
    fn proof_verify() {
        let proof_spec = ProofSpec{};
        let witness = Witness{};
        let proof = Parser::parse(&proof_spec, &witness).unwrap();

        assert!(proof.verify(&proof_spec).is_ok());
    }
}
