#![allow(non_snake_case)]

#[cfg(all(feature = "PS_Signature_G2", feature = "PS_Signature_G1"))]
compile_error!("features `PS_Signature_G2` and `PS_Signature_G1` are mutually exclusive");

use amcl_wrapper::extension_field_gt::GT;

#[cfg(feature = "PS_Signature_G2")]
pub type SignatureGroup = amcl_wrapper::group_elem_g2::G2;
#[cfg(feature = "PS_Signature_G2")]
pub type SignatureGroupVec = amcl_wrapper::group_elem_g2::G2Vector;
#[cfg(feature = "PS_Signature_G2")]
pub type OtherGroup = amcl_wrapper::group_elem_g1::G1;
#[cfg(feature = "PS_Signature_G2")]
pub type OtherGroupVec = amcl_wrapper::group_elem_g1::G1Vector;
#[cfg(feature = "PS_Signature_G2")]
pub(crate) fn ate_2_pairing(
    g1: &SignatureGroup,
    g2: &OtherGroup,
    h1: &SignatureGroup,
    h2: &OtherGroup,
) -> GT {
    GT::ate_2_pairing(g2, g1, h2, h1)
}

#[cfg(feature = "PS_Signature_G1")]
pub type SignatureGroup = amcl_wrapper::group_elem_g1::G1;
#[cfg(feature = "PS_Signature_G1")]
pub type SignatureGroupVec = amcl_wrapper::group_elem_g1::G1Vector;
#[cfg(feature = "PS_Signature_G1")]
pub type OtherGroup = amcl_wrapper::group_elem_g2::G2;
#[cfg(feature = "PS_Signature_G1")]
pub type OtherGroupVec = amcl_wrapper::group_elem_g2::G2Vector;
#[cfg(feature = "PS_Signature_G1")]
pub(crate) fn ate_2_pairing(
    g1: &SignatureGroup,
    g2: &OtherGroup,
    h1: &SignatureGroup,
    h2: &OtherGroup,
) -> GT {
    GT::ate_2_pairing(g1, g2, h1, h2)
}

pub mod errors;
pub mod keys;
pub mod pok_sig;
pub mod signature;

pub mod prelude {
    pub use super::keys::{keygen as generate, Sigkey as SecretKey, Verkey as PublicKey};
    pub use super::pok_sig::{
        PoKOfSignature, PoKOfSignatureProof, ProofSignatureGroup, ProverCommittedSignatureGroup,
        ProverCommittingSignatureGroup,
    };
    pub use super::signature::Signature;
    pub use super::{SignatureGroup, SignatureGroupVec};
}
