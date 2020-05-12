/// Creates the BTreeMap used for blind signing
#[macro_export]
macro_rules! sm_map {
    ($($index:expr => $data:expr),*) => {
        {
            let mut msgs = std::collections::BTreeMap::new();
            $(
                msgs.insert($index, crate::SignatureMessage::hash($data));
            )*
            msgs
        }
    };
}

/// Creates a proof message to be revealed
#[macro_export]
macro_rules! pm_revealed {
    ($data:expr) => {
        ProofMessage::Revealed(SignatureMessage::hash($data))
    };
}

/// Wrap a raw message in a revealed enum
#[macro_export]
macro_rules! pm_revealed_raw {
    ($data:expr) => {
        ProofMessage::Revealed($data)
    };
}

/// Creates a proof message that is hidden based on the number of parameters
/// One means hidden and only used in this proof
/// Two means hidden but can be used in other proofs
#[macro_export]
macro_rules! pm_hidden {
    ($data:expr) => {
        ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(
            SignatureMessage::hash($data),
        ))
    };
    ($data:expr, $bf:expr) => {
        ProofMessage::Hidden(HiddenMessage::ExternalBlinding(
            SignatureMessage::hash($data),
            $bf,
        ))
    };
}

/// Wrap a raw message in its respective hidden
#[macro_export]
macro_rules! pm_hidden_raw {
    ($data:expr) => {
        ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding($data))
    };
    ($data:expr, $bf:expr) => {
        ProofMessage::Hidden(HiddenMessage::ExternalBlinding($data, $bf))
    };
}

use crate::{ProofNonce, SignatureMessage};

/// A message classification by the prover
pub enum ProofMessage {
    /// Message will be revealed to a verifier
    Revealed(SignatureMessage),
    /// Message will be hidden from a verifier
    Hidden(HiddenMessage),
}

impl ProofMessage {
    /// Extract the internal message
    pub fn get_message(&self) -> SignatureMessage {
        match *self {
            ProofMessage::Revealed(ref r) => r.clone(),
            ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(ref p)) => p.clone(),
            ProofMessage::Hidden(HiddenMessage::ExternalBlinding(ref m, _)) => m.clone(),
        }
    }
}

/// Two types of hidden messages
pub enum HiddenMessage {
    /// Indicates the message is hidden and no other work is involved
    ///     so a blinding factor will be generated specific to this proof
    ProofSpecificBlinding(SignatureMessage),
    /// Indicates the message is hidden but it is involved with other proofs
    ///     like boundchecks, set memberships or inequalities, so the blinding factor
    ///     is provided from an external source.
    ExternalBlinding(SignatureMessage, ProofNonce),
}
