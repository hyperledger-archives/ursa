Each gadgets contains a method like
 
- `gen_proof....` which are used to generate the proof. It also returns the commitments that need to be given to the verifier. Apart from inputs, it optionally takes the randomness for commitments in case gadget is part of a sub-protocol.
- `verify_proof.....` which will be used to verify the proof.
