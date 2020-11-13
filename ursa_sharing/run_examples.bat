@ECHO OFF

cargo run --features=impl_tests --example curve25519
cargo run --features=impl_tests --example bn3072
cargo run --features=impl_tests --example k256
cargo run --features=impl_tests --example p256
cargo run --features=impl_tests --example bls12381
