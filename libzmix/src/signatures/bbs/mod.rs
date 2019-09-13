pub mod keys;
pub mod pok_sig;
pub mod signature;

pub mod prelude {
    pub use super::keys::{generate, PublicKey, SecretKey};
    pub use super::pok_sig::{
        PoKOfSignature, PoKOfSignatureProof, ProofG1, ProverCommittedG1, ProverCommittingG1,
    };
    pub use super::signature::Signature;
}

// TODO: Add "setup" to generate g1 and g2 and use them in-place of G1::generator() and G2::generator()
