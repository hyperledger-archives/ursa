use std::{path::PathBuf, str::FromStr};
use structopt::StructOpt;

#[derive(Clone, Debug, StructOpt)]
pub enum Commands {
    Setup {
        #[structopt(short, long)]
        backend: BackendConsumer,
        // #[structopt(short, long, parse(from_os_str))]
        // circuit: PathBuf,
        // #[structopt(short, long)]
        // format: Option<SerializationFormat>,
    },
    Prove {
        #[structopt(short, long)]
        backend: BackendConsumer,
        // #[structopt(long, parse(from_os_str))]
        // circuit: PathBuf,
        // #[structopt(long)]
        // circuit_format: Option<SerializationFormat>,
        #[structopt(long)]
        parameters: Option<PathBuf>,
        #[structopt(long)]
        witness: PathBuf,
        #[structopt(long)]
        witness_format: Option<SerializationFormat>,
    },
    Verify {
        #[structopt(short, long)]
        backend: BackendConsumer,
        // #[structopt(long, parse(from_os_str))]
        // circuit: Option<PathBuf>,
        // #[structopt(long)]
        // circuit_format: Option<SerializationFormat>,
        #[structopt(long)]
        parameters: Option<PathBuf>,
        #[structopt(long, parse(from_os_str))]
        input: PathBuf,
        // #[structopt(long)]
        // input_format: Option<SerializationFormat>,
    },
}

#[derive(Copy, Clone, Debug)]
pub enum BackendConsumer {
    Bellman,
    Bulletproofs,
}

impl FromStr for BackendConsumer {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bellman" => Ok(Self::Bellman),
            "bulletproofs" => Ok(Self::Bulletproofs),
            _ => Err("Invalid backend specified"),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum SerializationFormat {
    Json,
    Yaml,
}

impl FromStr for SerializationFormat {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "yaml" => Ok(Self::Yaml),
            _ => Err("Invalid format specified"),
        }
    }
}
