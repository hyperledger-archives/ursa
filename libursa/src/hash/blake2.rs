#[cfg(target_pointer_width = "64")]
pub use crate::blake2::Blake2b as Blake2;
#[cfg(target_pointer_width = "32")]
pub use crate::blake2::Blake2s as Blake2;
