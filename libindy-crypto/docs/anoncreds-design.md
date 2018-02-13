# Anonymous Credentials (anoncreds) crypto support
Initial version of anoncreds protocol was implemented as part of Indy SDK (https://github.com/hyperledger/indy-sdk). After some discussion and community requests we decided to move low level anoncreds crypto code to indy-crypto project. This should allow the crypto to be audited and shared with other projects.

## Main ideas
1. Indy-crypto will not provide high level anoncreds protocol details and persistence. It will support low level crypto entities only. 
1. API defines 3 actors:
    * Issuer - trust source that provides credentials to prover
    * Prover - credentials owner that can proof and partially disclose the credentials to verifier
    * Verifier - party that wants to check that prover has some credentials provided by issuer
1. The list of entities that indy-crypto operates on:
    * Claim Schema - a list of attribute names in a Claim
    * Claim Values - values of a Claim Schema's attributes corresponding to a specific prover (must be integers)
    * Claim Signature - Issuer's signature over Claim Values
    * Issuer keys (public). Contains 2 parts. One for signing primary claims (claim values) and second for signing non-revocation part of the claim. These keys are used to prove that claim was issued and has not been revoked by the issuer. Issuer keys must be uniquely identifiable and accessible by all parties.
    * Revocation Registry. Contains revocation keys, accumulator and accumulator tails. Public part of revocation registry must be published by Issuer on a tamper-evident and highly available storage and can be used to prove that the claim hasn't been revoked.
    * Master secret - Secret key encoded in a claim that is used to prove that prover owns the claim. Prover blinds the master secret, gives it to the issuer who then encodes this blinded secret in the claim. The objective of blinding the master secret is preventing the "identity leak" of the prover even if the Issuer and Verifier collude.
    * Predicate - Some condition that must be satisfied. The verifier can either ask the prover to reveal the attributes or satisfy some predicate over the attribute.
    * Proof is complex crypto structure created by prover over multiple claims that allows to prove that prover:
      * Knows signature over claims issued with specific issuer keys (identified by key id)
      * Claim contains attributes with specific values that prover wants to disclose
      * Claim contains attributes with valid predicates that verifier wants the prover to satisfy.
    * Sub Proof request - input to create a Proof from a specific claim; contains attributes to be revealed and predicates to be satisfied. A proof can be composed of several Sub proofs.
    * Revocation - An issuer while issuing a claim can embed an special attribute called revocation id/index. To revoke the claim, the issuer publishes to the world that claim with a particular id is revoked.  
    * Accumulator - A data structure used to hold the ids of non-revoked claims. While issuing the claim, issuer adds the revocation id to the accumulator and while revoking that claim, the issuer removes that claim's id from the accumulator. Since an accumulator can hold only a fixed number of elements, multiple accumulators can be used by the issuer.
    * Witness - Data required by the prover to prove that a particular claim is not revoked; i.e claim id is present in accumulator.
    * Tails - The user's witness has to be updated each time a claim is revoked, the user calculates the updates witness using already published data by the Issuer, this data is called validity tails or just "tails". The "tails" don't change with the accumulator. 
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
Issuer::new_cred_def(attrs: &ClaimSchema, support_revocation: bool) ->    
                          Result<(CredentialPublicKey, CredentialPrivateKey), IndyCryptoError>

Issuer::new_revocation_registry_def(issuer_pub_key: &CredentialPublicKey,
                              max_claim_num: u32) -> Result<(RevocationRegistryDefPublic,                                                              
                                                           RevocationRegistryDefPrivate), 
                                                                      IndyCryptoError>
Issuer::sign_claim(prover_id: &str,
                 blnd_ms: &BlindedMasterSecret,
                 claim_values: &ClaimValues,
                 issuer_pub_key: &CredentialPublicKey,
                 issuer_priv_key: &CredentialPrivateKey,
                 rev_idx: Option<u32>,
                 r_reg_pub: Option<&mut RevocationRegistryDefPublic>,
                 r_reg_priv: Option<&RevocationRegistryDefPrivate>) ->         
                                        Result<ClaimSignature, IndyCryptoError>

Issuer::revoke_claim(r_reg_pub: &mutRevocationRegistryPublic,
               rev_idx: u32) -> Result<(), IndyCryptoError>
```

### Prover
```Rust
Prover::new_master_secret() -> Result<MasterSecret, IndyCryptoError>

Prover::blind_master_secret(pub_key: &CredentialPublicKey,
                            ms: &MasterSecret) ->  Result<(BlindedMasterSecret,                                                                    
                                                           BlindedMasterSecretData), 
                                                                     IndyCryptoError>
Prover::process_claim_signature(claim_signature: &mut ClaimSignature,
                      blinded_master_secret_data: &BlindedMasterSecretData,
                      pub_key: &CredentialPublicKey,
                      r_reg: Option<&RevocationRegistryDefPublic>) -> Result<(), 
                                                                      IndyCryptoError>
Prover::new_proof_builder() -> Result<ProofBuilder, IndyCryptoError>

ProofBuilder::add_sub_proof_request(&mut self,
                        key_id: &str,
                        schema: &ClaimSchema,
                        claim_signature: &ClaimSignature,
                        claim_values: &ClaimValues,
                        pub_key: &CredentialPublicKey,
                        r_reg: Option<&RevocationRegistryDefPublic>,
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
                              p_pub_key: &CredentialPublicKey,
                              r_pub_key: Option<&CredentialRevocationPublicKey>,
                              r_reg: Option<&RevocationRegistryDefPublic>,
                              sub_proof_req: &SubProofRequest) 
                                           -> Result<(), IndyCryptoError>


ProofVerifier::verify(self,
                      proof: &Proof,
                      nonce: &Nonce) -> Result<bool, IndyCryptoError>
```