#![allow(non_snake_case)]

#[cfg(all(feature = "G1G2", feature = "G2G1"))]
compile_error!("features `G1G2` and `G2G1` are mutually exclusive");

#[macro_use]
extern crate amcl_wrapper;

use amcl_wrapper::extension_field_gt::GT;

#[cfg(feature = "G1G2")]
pub type SignatureGroup = amcl_wrapper::group_elem_g2::G2;
#[cfg(feature = "G1G2")]
pub type SignatureGroupVec = amcl_wrapper::group_elem_g2::G2Vector;
#[cfg(feature = "G1G2")]
pub type OtherGroup = amcl_wrapper::group_elem_g1::G1;
#[cfg(feature = "G1G2")]
pub type OtherGroupVec = amcl_wrapper::group_elem_g1::G1Vector;
#[cfg(feature = "G1G2")]
pub(crate) fn ate_2_pairing(
    g1: &SignatureGroup,
    g2: &OtherGroup,
    h1: &SignatureGroup,
    h2: &OtherGroup,
) -> GT {
    GT::ate_2_pairing(g2, g1, h2, h1)
}

#[cfg(feature = "G2G1")]
pub type SignatureGroup = amcl_wrapper::group_elem_g1::G1;
#[cfg(feature = "G2G1")]
pub type SignatureGroupVec = amcl_wrapper::group_elem_g1::G1Vector;
#[cfg(feature = "G2G1")]
pub type OtherGroup = amcl_wrapper::group_elem_g2::G2;
#[cfg(feature = "G2G1")]
pub type OtherGroupVec = amcl_wrapper::group_elem_g2::G2Vector;
#[cfg(feature = "G2G1")]
pub(crate) fn ate_2_pairing(
    g1: &SignatureGroup,
    g2: &OtherGroup,
    h1: &SignatureGroup,
    h2: &OtherGroup,
) -> GT {
    GT::ate_2_pairing(g1, g2, h1, h2)
}

extern crate rand;
#[macro_use]
extern crate failure;

pub mod errors;
pub mod keys;
#[macro_use]
pub mod pok_vc;
pub mod pok_sig;
pub mod signature;
