pub mod spec;

pub struct Parser {}

#[allow(unused_variables)]
impl Parser {
    pub fn parse(proof_spec: &spec::ProofSpec, witness: &Witness) -> Result<Proof, ZKLError> {
        unimplemented!();
    }
}

pub struct Witness {}

pub struct WitnessBuilder {}

impl WitnessBuilder {
    pub fn new() -> WitnessBuilder {
        WitnessBuilder {}
    }
}

pub struct Proof {}

#[allow(unused_variables)]
impl Proof {
    pub fn verify(&self, proof_spec: &spec::ProofSpec) -> Result<bool, ZKLError> {
        unimplemented!();
    }
}

#[repr(i32)]
#[derive(Debug, Eq, PartialEq)]
pub enum ZKLError {
    InvalidProofSpec = 1,
    InvalidWitness = 2,
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkl::spec::ProofSpecBuilder;

    #[test]
    #[ignore]
    fn parse_empty_clause() {
        let pb = ProofSpecBuilder::new();
        let proof_spec = pb.finalize();
        let witness = Witness {};
        let result = Parser::parse(&proof_spec, &witness);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, ZKLError::InvalidProofSpec);
        }
    }

    #[test]
    #[ignore]
    fn parse_credential_clause() {
        //TODO: Add credential clause to the proof_spec
        let pb = ProofSpecBuilder::new();
        let proof_spec = pb.finalize();
        let witness = Witness {};
        assert!(Parser::parse(&proof_spec, &witness).is_ok());
    }

    #[test]
    #[ignore]
    fn parse_interval_clause() {
        //TODO: Add interval clause to the proof_spec
        let pb = ProofSpecBuilder::new();
        let proof_spec = pb.finalize();
        let witness = Witness {};
        assert!(Parser::parse(&proof_spec, &witness).is_ok());
    }

    #[test]
    #[ignore]
    fn parse_set_membership_clause() {
        //TODO: Add set membership clause to the proof_spec
        let pb = ProofSpecBuilder::new();
        let proof_spec = pb.finalize();
        let witness = Witness {};
        assert!(Parser::parse(&proof_spec, &witness).is_ok());
    }

    #[test]
    #[ignore]
    fn parse_verifiable_encryption_clause() {
        //TODO: Add verifiable encryption clause to the proof_spec
        let pb = ProofSpecBuilder::new();
        let proof_spec = pb.finalize();
        let witness = Witness {};
        assert!(Parser::parse(&proof_spec, &witness).is_ok());
    }

    #[test]
    #[ignore]
    fn parse_nym_clause() {
        //TODO: Add nym clause to the proof_spec
        let pb = ProofSpecBuilder::new();
        let proof_spec = pb.finalize();
        let witness = Witness {};
        assert!(Parser::parse(&proof_spec, &witness).is_ok());
    }

    #[test]
    #[ignore]
    fn proof_verify() {
        let pb = ProofSpecBuilder::new();
        let proof_spec = pb.finalize();
        let witness = Witness {};
        let proof = Parser::parse(&proof_spec, &witness).unwrap();

        assert!(proof.verify(&proof_spec).is_ok());
    }

    #[test]
    #[ignore]
    fn proof_verify_fail_attribute_mismatch() {
        let pb = ProofSpecBuilder::new();
        let proof_spec = pb.finalize();
        let witness = Witness {};
        let proof = Parser::parse(&proof_spec, &witness).unwrap();

        //Different proof spec
        let pb = ProofSpecBuilder::new();
        let proof_spec = pb.finalize();
        assert!(proof.verify(&proof_spec).is_err());
    }
}
