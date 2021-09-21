# Fujitsu

This project demonstrates R1CS logic with backends to Bellman and Bulletproofs.

Use the following commands to execute each step of the process which is: setup (bellman), prove, and verify.

## Setup

`cargo run -- setup --backend=bellman | tee params.json`

## Prove

`echo '"1234"' > witness.hex`
`cargo run -- prove --backend=bellman --parameters=params.json --witness=witness.hex | tee proof.json`

or 

`cargo run -- prove --backend=bulletproofs --witness=witness.hex | tee proof.json`

## Verify

`cargo run -- verify --backend=bellman --parameters=params.json --input=proof.json`

or

`cargo run -- verify --backend=bulletproofs --input=proof.json`
