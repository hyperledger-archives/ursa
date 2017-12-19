# Shared anoncreds math in Indy Crypto
Initial version of anoncreds protocol was implemented as part of Indy SDK (https://github.com/hyperledger/indy-sdk). After some discussion and community requests we decided to move low level anoncreds crypto code to indy-crypto project. This should allow the crypto to be audited and shared with other projects.

## Main ideas
1. Indy-crypto will not provide high level anoncreds protocol details and persistence. It will operate low level crypto entities only. 
1. API defines 3 actors:
    * Issuer - trust source that provides credentials to prover
    * Prover - credentials owner that can proof and partially disclose the credentials to verifier
    * Verifier - party that wants to check that prover has some credentials provided by issuer
1. The list of entities that indy-crypto operates:
    * Claim Schema” - a list of attributes a Claim is based on
    * “Claim Values” - values of attributes from Claim Schema (must be integers)
    * “Claim Signature” - signed by the Issuer part of the Claim
    * “Issuer public key” and “issuer private key”. Keys will contain 2 internal parts. One for signing primary claims and second for signing non-revocation claims. These keys are used to proof that claim was issued and doesn’t revoked by this issuer. Issuer keys have global identifier that must be known to all parties.
    * “Revocation registry public” and “revocation registry private”. Internally them will contain revocation keys, accumulator and accumulator tails. Public part of revocation registry must be shared by issuer in trusted place and can be used to proof that concrete claim wasn’t revoked.
    * “Master secret” - secret prover data that is used to proof that prover owns the claim. Prover blinds master secret be generating “blinded master secret” and “master secret blinding data” and sends “blinded master secret” to isser that uses “blinded master secret” in claim creation. It allows to use this claim by prover only.
    * “Proof” is complex crypto structure created by proved over multiple claims that allows to proof that prover:
      * Owns claims issued with specific issuer keys (identified by key id)
      * Claim contains attributes with specific values that prover wants to disclose
      * Claim contains attributes with valid predicates that prover wants to disclose
    * “Sub Proof request” - input to create a Proof for a claim; contains attrs to be revealed and predicates.
1. For each entity API will provide the methods to perform serialization and deserialization that will allow network entities transfer between actors.
1. FFI C API will use OpenSSL style entities handling. Entities referenced will be represent as untyped pointers. Library will provide functions for entities allocation, manipulation and deallocation. 

## API 

### Claim and Proof attributes builders
```Rust
ClaimSchemaBuilder::new() -> Result<ClaimSchemaBuilder, IndyCryptoError>

ClaimSchemaBuilder::add_attr(mut self, attr: &str) ->  
                                       Result<ClaimSchemaBuilder, IndyCryptoError>

ClaimSchemaBuilder::finalize(self) -> Result<ClaimSchema, IndyCryptoError>

ClaimValuesBuilder::new() -> Result<ClaimValuesBuilder, IndyCryptoError>

ClaimValuesBuilder::add_value(mut self, attr: &str, dec_value: &str) -> 
                                 Result<ClaimValuesBuilder, IndyCryptoError>

ClaimValuesBuilder::finalize(self) -> Result<ClaimValues, 
                                                                      IndyCryptoError>

SubProofRequestBuilder::new() -> Result<SubProofRequestBuilder, IndyCryptoError>

SubProofRequestBuilder::add_revealed_attr(mut self, attr: &str) -> 
                                      Result<SubProofRequestBuilder, IndyCryptoError>


SubProofRequestBuilder::add_predicate(mut self, predicate: &Predicate) -> 
                                      Result<SubProofRequestBuilder, IndyCryptoError>

SubProofRequestBuilder::finalize(self) -> Result<SubProofRequest, IndyCryptoError>
```

### Issuer
```Rust
Issuer::new_keys(attrs: &ClaimSchema, non_revocation_part: bool) ->    
                          Result<(IssuerPublicKey, IssuerPrivateKey), IndyCryptoError>

Issuer::new_revocation_registry(issuer_pub_key: &IssuerPublicKey,
                              max_claim_num: u32) -> Result<(RevocationRegistryPublic,                                                              
                                                           RevocationRegistryPrivate), 
                                                                      IndyCryptoError>
Issuer::sign_claim(prover_id: &str,
                 blnd_ms: &BlindedMasterSecret,
                 claim_values: &ClaimValues,
                 issuer_pub_key: &IssuerPublicKey,
                 issuer_priv_key: &IssuerPrivateKey,
                 rev_idx: Option<u32>,
                 r_reg_pub: Option<&mut RevocationRegistryPublic>,
                 r_reg_priv: Option<&RevocationRegistryPrivate>) ->         
                                        Result<ClaimSignature, IndyCryptoError>

Issuer::revoke_claim(r_reg_pub: &mutRevocationRegistryPublic,
               rev_idx: u32) -> Result<(), IndyCryptoError>
```

### Prover
```Rust
Prover::new_master_secret() -> Result<MasterSecret, IndyCryptoError>

Prover::blind_master_secret(pub_key: &IssuerPublicKey,
                            ms: &MasterSecret) ->  Result<(BlindedMasterSecret,                                                                    
                                                           BlindedMasterSecretData), 
                                                                     IndyCryptoError>
Prover::process_claim_signature(claim_signature: &mut ClaimSignature,
                      blinded_master_secret_data: &BlindedMasterSecretData,
                      pub_key: &IssuerPublicKey,
                      r_reg: Option<&RevocationRegistryPublic>) -> Result<(), 
                                                                      IndyCryptoError>
Prover::new_proof_builder() -> Result<ProofBuilder, IndyCryptoError>

ProofBuilder::add_sub_proof_request(&mut self,
                        key_id: &str,
                        schema: &ClaimSchema,
                        claim_signature: &ClaimSignature,
                        claim_values: &ClaimValues,
                        pub_key: &IssuerPublicKey,
                        r_reg: Option<&RevocationRegistryPublic>,
                        sub_proof_req: &SubProofRequest) 
                                    -> Result<(),  IndyCryptoError>

ProofBuilder::finalize(&mut self,
                       nonce: &Nonce,
                       ms: &MasterSecret) -> Result<Proof, IndyCryptoError>
```

### Verifier
```Rust
Verifier::new_nonce() -> Result<Nonce, IndyCryptoError>

Verifier::new_proof_verifier() -> Result<ProofVerifier, IndyCryptoError>

ProofVerifier::add_sub_proof_request(&mut self,
                              key_id: &str,
                              schema: &ClaimSchema,
                              p_pub_key: &IssuerPublicKey,
                              r_pub_key: Option<&IssuerRevocationPublicKey>,
                              r_reg: Option<&RevocationRegistryPublic>,
                              sub_proof_req: &SubProofRequest) 
                                           -> Result<(), IndyCryptoError>


ProofVerifier::verify(self,
                      proof: &Proof,
                      nonce: &Nonce) -> Result<bool, IndyCryptoError>
```