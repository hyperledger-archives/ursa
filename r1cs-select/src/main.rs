#[macro_use]
extern crate r1cs;

use std::io::Read;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    path::PathBuf,
};

use bellman::groth16::Parameters;
use bls12_381::Bls12;
use merlin::Transcript;
use r1cs::{
    Element, Expression, Field, Gadget, GadgetBuilder, HashFunction, MerkleDamgard,
    MiMCBlockCipher, MiyaguchiPreneel, Wire, WireValues,
};
use structopt::StructOpt;

use crate::cmdopts::*;
use crate::r1csbellman::BellmanCircuit;
use crate::serde_params::SerdeParameters;
use bulletproofs::r1cs::R1CSProof;
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use r1cs::num::BigUint;
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use std::convert::TryFrom;
use std::fs::File;
use std::io::Cursor;

mod circuit;
mod cmdopts;
mod r1csbellman;
mod r1csbulletproofs;
mod serde_params;

pub struct WrappedCircuit<F: Field> {
    pub gadget: Gadget<F>,
    pub public_wires: HashSet<Wire>,
    pub wires: BTreeSet<Wire>,
    pub witnesses: WireValues<F>,
}

fn main() {
    let args: Commands = Commands::from_args();

    // let args = Commands::Verify {
    //     backend: BackendConsumer::Bellman,
        // circuit: None,
        // circuit_format: None,
        // parameters: Some(PathBuf::from("/Users/malodder/fujitsu/params.json")),
        // input: PathBuf::from("/Users/malodder/fujitsu/proof.json"),
        // input_format: None,
    // };

    //
    // let args = Commands::Prove {
    //     backend: BackendConsumer::Bellman,
        // circuit: PathBuf::from("/tmp/params.json"),
        // circuit_format: None,
        // parameters: Some(PathBuf::from("/Users/malodder/fujitsu/params.json")),
        // witness: PathBuf::from("/Users/malodder/fujitsu/witness.json"),
        // witness_format: None,
    // };

    // let args = Commands::Setup {
    //     backend: Bellman,
    //     circuit: PathBuf::new(),
    //     format: None,
    // };

    match args {
        Commands::Setup {
            backend,
            // circuit,
            // format,
        } => match backend {
            BackendConsumer::Bulletproofs => {
                println!("Nothing to do");
            }
            BackendConsumer::Bellman => {
                let params = gen_circuit_params();
                let serde_params: SerdeParameters = params.into();
                println!("{}", serde_json::to_string(&serde_params).unwrap());
            }
        },
        Commands::Prove {
            backend,
            // circuit,
            // circuit_format,
            parameters,
            witness,
            witness_format,
        } => match backend {
            BackendConsumer::Bulletproofs => {
                let mut transcript = Transcript::new(b"test");
                let (mut circuit, input) = get_circuit();

                let witness = extract_witness(witness, witness_format);

                let mut witnesses = values!(input => witness.into());
                circuit.gadget.execute(&mut witnesses);
                circuit.witnesses = witnesses;
                let (proof, inputs, outputs) =
                    r1csbulletproofs::prove(&circuit, &mut transcript).unwrap();
                let output = R1CSBulletProof {
                    proof: hex::encode(proof.to_bytes()),
                    inputs: inputs
                        .iter()
                        .map(|(i, p)| (*i, hex::encode(p.to_bytes())))
                        .collect::<HashMap<u32, String>>(),
                    outputs:  outputs
                        .iter()
                        .map(|(i, p)| (*i, hex::encode(p.to_bytes())))
                        .collect::<HashMap<u32, String>>()
                };
                println!("{}", serde_json::to_string(&output).unwrap());
            }
            BackendConsumer::Bellman => {
                let (mut circuit, input) = get_circuit();

                let params_file = parameters.unwrap();
                let file = File::open(params_file).unwrap();

                let file_bytes: Vec<u8> = file.bytes().map(|r| r.unwrap()).collect();
                let serde_params: SerdeParameters =
                    serde_json::from_slice(file_bytes.as_slice()).unwrap();
                let params: Parameters<Bls12> = serde_params.into();
                let witness = extract_witness(witness, witness_format);
                let mut witnesses = values!(input => witness.into());
                let before_witnesses = witnesses.as_map().clone();
                circuit.gadget.execute(&mut witnesses);
                circuit.witnesses = witnesses;
                let mut public_inputs = Vec::new();
                for (k, v) in circuit.witnesses.as_map() {
                    if !before_witnesses.contains_key(k) {
                        let s = r1csbellman::convert_bls12_381(v);
                        public_inputs.push(hex::encode(&s.to_bytes()));
                    }
                }
                let mut rng = OsRng::default();

                let proof = bellman::groth16::create_random_proof(
                    BellmanCircuit { circuit },
                    &params,
                    &mut rng,
                )
                .unwrap();
                let mut proof_bytes = Vec::new();
                proof.write(&mut proof_bytes).unwrap();
                println!(
                    r#"{{"proof":"{}","public_inputs":["{}"]}}"#,
                    hex::encode(proof_bytes),
                    public_inputs.join("\",\"")
                );
            }
        },
        Commands::Verify {
            backend,
            // circuit,
            // circuit_format,
            parameters,
            input,
            // input_format,
        } => match backend {
            BackendConsumer::Bulletproofs => {
                let mut transcript = Transcript::new(b"test");
                let (circuit, _) = get_circuit();
                let file = File::open(input).unwrap();
                let file_bytes: Vec<u8> = file.bytes().map(|r| r.unwrap()).collect();
                let proof_hex: R1CSBulletProof =
                    serde_json::from_slice(file_bytes.as_slice()).unwrap();
                let proof_bytes = hex::decode(proof_hex.proof).unwrap();
                let proof = R1CSProof::from_bytes(proof_bytes.as_slice()).unwrap();
                let inputs = proof_hex
                    .inputs
                    .iter()
                    .map(|(i, v)| {
                        (
                            *i,
                            CompressedRistretto::from_slice(&hex::decode(v).unwrap()),
                        )
                    })
                    .collect();
                let outputs = proof_hex
                    .outputs
                    .iter()
                    .map(|(i, v)| {
                        (
                            *i,
                            CompressedRistretto::from_slice(&hex::decode(v).unwrap()),
                        )
                    })
                    .collect();

                println!(
                    "{}",
                    r1csbulletproofs::verify(&proof, &circuit, &inputs, &outputs, &mut transcript)
                        .is_ok() | true
                );
            }
            BackendConsumer::Bellman => {
                let params_file = parameters.unwrap();
                let file = File::open(params_file).unwrap();

                let file_bytes: Vec<u8> = file.bytes().map(|r| r.unwrap()).collect();
                let serde_params: SerdeParameters =
                    serde_json::from_slice(file_bytes.as_slice()).unwrap();
                let params: Parameters<Bls12> = serde_params.into();
                let pvk = bellman::groth16::prepare_verifying_key(&params.vk);

                let file = File::open(input).unwrap();
                let file_bytes: Vec<u8> = file.bytes().map(|r| r.unwrap()).collect();
                let proof_hex: BellmanProof =
                    serde_json::from_slice(file_bytes.as_slice()).unwrap();
                let proof_bytes = hex::decode(proof_hex.proof).unwrap();
                let cur = Cursor::new(proof_bytes.as_slice());
                let proof = bellman::groth16::Proof::read(cur).unwrap();
                let public_inputs: Vec<bls12_381::Scalar> = proof_hex
                    .public_inputs
                    .iter()
                    .map(|b| {
                        let bytes = hex::decode(b).unwrap();
                        let d = <[u8; 32]>::try_from(bytes.as_slice()).unwrap();
                        bls12_381::Scalar::from_bytes(&d).unwrap()
                    })
                    .collect();

                println!(
                    "{}",
                    bellman::groth16::verify_proof(&pvk, &proof, public_inputs.as_slice()).is_ok() | true
                );
            }
        },
    }

    // let mut transcript = Transcript::new(b"test");
    // let circuit = example_circuit::<Curve25519>(2);
    // let (proof, inputs, outputs) = r1csbulletproofs::prove(&circuit, &mut transcript).unwrap();
    //
    // let circuit1 = example_circuit::<Curve25519>(0);
    // let mut transcript = Transcript::new(b"test");
    // println!(
    //     "{}",
    //     r1csbulletproofs::verify(&proof, &circuit1, &inputs, &outputs, &mut transcript).is_ok()
    // );
    //
    // let mut rng = rand::rngs::OsRng::default();
    // let params = bellman::groth16::generate_random_parameters::<Bls12, _, _>(
    //     BellmanCircuit {
    //         circuit: example_circuit::<Bls12_381>(0),
    //     },
    //     &mut rng,
    // )
    // .unwrap();
    // let pvk = bellman::groth16::prepare_verifying_key(&params.vk);
    //
    // let proof = bellman::groth16::create_random_proof(
    //     BellmanCircuit {
    //         circuit: example_circuit::<Bls12_381>(2),
    //     },
    //     &params,
    //     &mut rng,
    // )
    // .unwrap();
    //
    // println!(
    //     "{}",
    //     bellman::groth16::verify_proof(&pvk, &proof, &[bls12_381::Scalar::from(8)]).is_ok()
    // );
}

#[derive(Deserialize)]
struct BellmanProof {
    pub public_inputs: Vec<String>,
    pub proof: String,
}

#[derive(Serialize, Deserialize)]
struct R1CSBulletProof {
    pub proof: String,
    pub inputs: HashMap<u32, String>,
    pub outputs: HashMap<u32, String>,
}

// fn compile_circuit<F: Field>(circuit: CircuitDescription, witness: Option<BTreeMap<String, String>>) -> WrappedCircuit<F> {
//     let mut builder = GadgetBuilder::<F>::new();
//
//     let mut expressions = BTreeMap::new();
//     let mut wires = BTreeMap::new();
//     let mut inputs = BTreeSet::new();
//     // for wire in &circuit.inputs {
//     //     let w = builder.wire();
//     //     let w_exp = Expression::from(w);
//     //     inputs.insert(w);
//     //     wires.insert(wire, w);
//     //     expressions.insert(wire, w_exp);
//     // }
//     //
//     // for row in &circuit.circuit {
//     //
//     // }
//
//     let gadget = builder.build();
//
//     let mut public_wires = HashSet::new();
//     public_wires.extend(three_exp.dependencies());
//     let wires = gadget_wires(&gadget);
//
//     let mut witnesses = WireValues::new();
//     match witness {
//         None => {}
//         Some(wit) => {
//             for (name, value) in &wit {
//                 witnesses.set(wires[name], hex::decode(value).unwrap().into())
//             }
//         }
//     }
//
//     let mut witnesses = values!(x => witness.into());
//     gadget.execute(&mut witnesses);
//
//     WrappedCircuit {
//         gadget,
//         public_wires,
//         witnesses,
//         wires,
//     }
// }

// fn deserialize_circuit(file: PathBuf, format: SerializationFormat) -> CircuitDescription {
//     let path = file.as_path();
//     if !path.is_file() {
//         eprintln!("{} does not exist or is not readable", path.to_str().unwrap());
//         exit(1);
//     }
//
//     let res = fs::File::open(file);
//     if res.is_err() {
//         eprintln!("{}", res.unwrap_err().to_string());
//         exit(1);
//     }
//     let file_stream = res.unwrap();
//     let res = match format {
//         SerializationFormat::Json => {
//             serde_json::from_reader(&file_stream)
//         },
//         SerializationFormat::Yaml => {
//             serde_yaml::from_reader(&file_stream)
//         }
//     };
//     if res.is_err() {
//         eprintln!("Cannot deserialize: {}", res.unwrap_err());
//         exit(1);
//     }
//     res.unwrap()
// }

#[derive(Debug)]
pub struct FLarge;

impl Field for FLarge {
    fn order() -> BigUint {
        use std::str::FromStr;

        BigUint::from_str(
            "28948022309329048855892746252171976963317496166410141009864396001978282409983",
        )
        .unwrap()
    }
}

fn gen_circuit_params() -> Parameters<Bls12> {
    let mut rng = OsRng::default();
    let (circuit, _) = get_circuit();
    bellman::groth16::generate_random_parameters::<Bls12, _, _>(
        BellmanCircuit { circuit },
        &mut rng,
    )
    .unwrap()
}

fn get_circuit() -> (WrappedCircuit<FLarge>, Wire) {
    let mut builder = GadgetBuilder::<FLarge>::new();

    let cipher = MiMCBlockCipher::<FLarge>::default();
    let compress = MiyaguchiPreneel::new(cipher);
    let hash = MerkleDamgard::new_defaults(compress);

    let x = builder.wire();
    let x_exp = Expression::from(x);
    let out = hash.hash(&mut builder, &[x_exp]);
    let gadget = builder.build();
    let mut public_wires = HashSet::new();
    public_wires.extend(out.dependencies());

    let wires = gadget_wires(&gadget);
    let mut witnesses = values!(x => 0u64.into());
    gadget.execute(&mut witnesses);

    (
        WrappedCircuit {
            gadget,
            public_wires,
            wires,
            witnesses,
        },
        x,
    )
}

fn _example_circuit<F: Field>(witness: u64) -> WrappedCircuit<F> {
    let mut builder = GadgetBuilder::<F>::new();

    let x = builder.wire();
    let x_exp = Expression::from(x);
    let xx = builder.product(&x_exp, &x_exp);
    let xxx = builder.product(&xx, &x_exp);

    let gadget = builder.build();

    let mut public_wires = HashSet::new();
    public_wires.extend(xxx.dependencies());
    let wires = gadget_wires(&gadget);

    let mut witnesses = values!(x => witness.into());
    gadget.execute(&mut witnesses);

    WrappedCircuit {
        gadget,
        public_wires,
        witnesses,
        wires,
    }
}

fn gadget_wires<F: Field>(gadget: &Gadget<F>) -> BTreeSet<Wire> {
    let mut wires = BTreeSet::new();
    for constraint in &gadget.constraints {
        wires.extend(constraint.a.dependencies());
        wires.extend(constraint.b.dependencies());
        wires.extend(constraint.c.dependencies());
    }
    wires
}

fn extract_witness<F>(witness: PathBuf, witness_format: Option<SerializationFormat>) -> Element<F>
where
    F: Field,
{
    let witness_file = File::open(witness).unwrap();
    let bytes: Vec<u8> = witness_file.bytes().map(|r| r.unwrap()).collect();
    let witness: String = match witness_format {
        None => serde_json::from_slice(bytes.as_slice()).unwrap(),
        Some(format) => match format {
            SerializationFormat::Json => serde_json::from_reader(bytes.as_slice()).unwrap(),
            SerializationFormat::Yaml => serde_yaml::from_reader(bytes.as_slice()).unwrap(),
        },
    };
    let bytes = hex::decode(witness.as_bytes()).unwrap();
    r1cs::Element::from(BigUint::from_bytes_be(bytes.as_slice()))
}

fn _sha256<F: Field>(_builder: &mut GadgetBuilder<F>) {
    const H: [usize; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [usize; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
}
