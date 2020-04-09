//! Implements the BBS+ signature as defined in <https://eprint.iacr.org/2016/663.pdf>
//! in Section 4.3. Also included is ability to do zero-knowledge proofs as described
//! in Section 4.4 and 4.5.
//!
//! The BBS+ signature is a pairing-based ECC signature
//! that signs multiple messages instead of just one.
//! The signature and messages can be used to create signature proofs of knowledge
//! in zero-knowledge proofs in which the signature is not revealed and messages
//! can be selectively disclosed––some are revealed and some remain hidden.
//!
//! The signature also supports separating the signer and signature holder
//! where the holder creates commitments to messages which are hidden from the signer
//! and a signature blinding factor which is retained. The holder sends the commitment
//! to the signer who completes the signing process and sends the blinded signature back.
//! The holder can then un-blind the signature finishing a 2-PC computation
//!
//! BBS+ signatures can be used for TPM DAA attestations or Verifiable Credentials.

#![deny(
    warnings,
    missing_docs,
    unsafe_code,
    unused_import_braces,
    unused_lifetimes,
    unused_qualifications
)]

#[macro_use]
extern crate arrayref;

use amcl_wrapper::{
    field_elem::{FieldElement, FieldElementVector},
    group_elem_g1::{G1Vector, G1},
};

/// Macros and classes used for creating proofs of knowledge
#[macro_use]
pub mod pok_vc;
/// The errors that BBS+ throws
pub mod errors;
/// Represents steps taken by the issuer to create a BBS+ signature
/// whether its 2PC or all in one
pub mod issuer;
/// BBS+ key classes
pub mod keys;
/// Methods and structs for creating signature proofs of knowledge
pub mod pok_sig;
/// Methods and structs for creating signatures
pub mod signature;

/// The type for creating commitments to messages that are hidden during issuance.
pub type BlindedSignatureCommitment = G1;
/// The type for managing lists of generators
pub type SignaturePointVector = G1Vector;
/// The type for messages
pub type SignatureMessage = FieldElement;
/// The type for managing lists of messages
pub type SignatureMessageVector = FieldElementVector;
/// The type for nonces
pub type SignatureNonce = FieldElement;
/// The type for blinding factors
pub type SignatureBlinding = FieldElement;

mod types {
    pub use super::{
        BlindedSignatureCommitment, SignatureBlinding, SignatureMessage, SignatureMessageVector,
        SignatureNonce, SignaturePointVector,
    };
}

/// Convenience importing module
pub mod prelude {
    pub use super::keys::prelude::*;
    pub use super::pok_sig::prelude::*;
    pub use super::pok_vc::prelude::*;
    pub use super::signature::prelude::*;
    pub use super::{
        BlindedSignatureCommitment, SignatureBlinding, SignatureMessage, SignatureMessageVector,
        SignatureNonce, SignaturePointVector,
    };
    pub use amcl_wrapper::constants::FieldElement_SIZE as SECRET_KEY_SIZE;
    pub use amcl_wrapper::constants::FieldElement_SIZE as MESSAGE_SIZE;
    pub use amcl_wrapper::constants::GroupG1_SIZE as COMMITMENT_SIZE;
    pub use amcl_wrapper::types_g2::GroupG2_SIZE as PUBLIC_KEY_SIZE;
    pub use generic_array::typenum::U192 as DeterministicPublicKeySize;
    pub use generic_array::GenericArray;
    pub use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
}
