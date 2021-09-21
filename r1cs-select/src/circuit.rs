use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CircuitDescription {
    /// Hex encoded private inputs
    pub inputs: Vec<String>,
    /// Hex encoded public inputs
    pub public_inputs: Vec<String>,
    /// The circuit operations
    pub circuit: Vec<String>,
}
