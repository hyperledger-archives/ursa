# Anonymous Credentials (anoncreds) crypto support
Initial version of anoncreds protocol was implemented as part of Indy SDK (https://github.com/hyperledger/indy-sdk). After some discussion and community requests we decided to move low level anoncreds crypto code to indy-crypto project. This should allow the crypto to be audited and shared with other projects.  
The math for the crypto is described in the latex docs [here](https://github.com/hyperledger/ursa-docs/tree/master/specs/anoncreds1).

## Main ideas
1. Indy-crypto will not provide high level anoncreds protocol details and persistence. It will support low level crypto entities only. 
1. API defines 3 actors:
    * Issuer - trust source that provides credentials to prover
    * Prover - credentials owner that can proof and partially disclose the credentials to verifier
    * Verifier - party that wants to check that prover has some credentials provided by issuer
1. The list of entities that indy-crypto operates on:
    * Credential Schema - a list of attribute names in a Credential
    * Credential Values - values of a Credential Schema's attributes corresponding to a specific prover (must be integers)
    * Credential Signature - Issuer's signature over Credential Values
    * Issuer keys (public). Contains 2 parts. One for signing primary credentials (credential values) and second for signing non-revocation part of the credential. These keys are used to prove that credential was issued and has not been revoked by the issuer. Issuer keys must be uniquely identifiable and accessible by all parties.
    * Revocation Registry. Contains revocation keys, accumulator and accumulator tails. Public part of revocation registry must be published by Issuer on a tamper-evident and highly available storage and can be used to prove that the credential hasn't been revoked.
    * Master secret - Secret key encoded in a credential that is used to prove that prover owns the credential. Prover blinds the master secret, gives it to the issuer who then encodes this blinded secret in the credential. The objective of blinding the master secret is preventing the "identity leak" of the prover even if the Issuer and Verifier collude.
    * Predicate - Some condition that must be satisfied. The verifier can either ask the prover to reveal the attributes or satisfy some predicate over the attribute.
    * Proof is complex crypto structure created by prover over multiple credentials that allows to prove that prover:
      * Knows signature over credentials issued with specific issuer keys (identified by key id)
      * Credential contains attributes with specific values that prover wants to disclose
      * Credential contains attributes with valid predicates that verifier wants the prover to satisfy.
    * Sub Proof request - input to create a Proof from a specific credential; contains attributes to be revealed and predicates to be satisfied. A proof can be composed of several Sub proofs.
    * Revocation - An issuer while issuing a credential can embed an special attribute called revocation id/index. To revoke the credential, the issuer publishes to the world that credential with a particular id is revoked.
    * Accumulator - A data structure used to hold the ids of non-revoked credentials. While issuing the credential, issuer adds the revocation id to the accumulator and while revoking that credential, the issuer removes that credential's id from the accumulator. Since an accumulator can hold only a fixed number of elements, multiple accumulators can be used by the issuer.
    * Witness - Data required by the prover to prove that a particular credential is not revoked; i.e credential id is present in accumulator.
    * Tails - The user's witness has to be updated each time a credential is revoked, the user calculates the updates witness using already published data by the Issuer, this data is called validity tails or just "tails". The "tails" don't change with the accumulator.
1. For each entity API will provide the methods to perform serialization and deserialization that will allow network entities transfer between actors.
1. FFI C API will use OpenSSL style entities handling. Entities referenced will be represent as untyped pointers. Library will provide functions for entities allocation, manipulation and deallocation. 

## API 
### API V2
#### Goals
* Indy Crypto should have ability to work with large volume of Tails (can be larger rather RAM)
  *  should allow to calculate revocation witness on cloud agent with minimal disclosing sensitive data
* API entities should be consistent with Indy Ledger transactions

#### Changes
* `RevocationRegistry` now will be created without full `Tails` in RAM as part of returned value.
Instead of it, TailsGenerator will be returned to generate all tails one by one and store in application manner.
* `Witness` now became in separate entity and should be updated out of call `ProofBuilder::add_sub_proof_request`
* IndyCrypto defines `RevocationTailAccessor` trait. Application should implement this and handle calls from IndyCrypto such as `access_tail(id, ursa_cb(tail))`

### Credential and Proof attributes builders
```Rust
CredentialSchemaBuilder::new() -> Result<CredentialSchemaBuilder, IndyCryptoError>

CredentialSchemaBuilder::add_attr(mut self, attr: &str) ->
                                       Result<CredentialSchemaBuilder, IndyCryptoError>

CredentialSchemaBuilder::finalize(self) -> Result<CredentialSchema, IndyCryptoError>

CredentialValuesBuilder::new() -> Result<CredentialValuesBuilder, IndyCryptoError>

CredentialValuesBuilder::add_value(mut self, attr: &str, dec_value: &str) ->
                                 Result<CredentialValuesBuilder, IndyCryptoError>

CredentialValuesBuilder::finalize(self) -> Result<CredentialValues, IndyCryptoError>

SubProofRequestBuilder::new() -> Result<SubProofRequestBuilder, IndyCryptoError>

SubProofRequestBuilder::add_revealed_attr(mut self, attr: &str) -> 
                                      Result<SubProofRequestBuilder, IndyCryptoError>


SubProofRequestBuilder::add_predicate(mut self, predicate: &Predicate) -> 
                                      Result<SubProofRequestBuilder, IndyCryptoError>

SubProofRequestBuilder::finalize(self) -> Result<SubProofRequest, IndyCryptoError>
```

### Tails
```Rust
impl Iterator<Tail> for RevocationTailsGenerator

RevocationTailsGenerator::next() -> Option<Tail>

Tail::from_bytes(bytes: &[u8]) -> Result<Tail, IndyCryptoError>
Tail::to_bytes(&self) -> Vec<u8>

trait RevocationTailsAccessor {
    fn access_tail(&self, tail_id: u32, accessor: &mut FnMut(&Tail)) -> Result<(), IndyCryptoError)>
}
```

### Witness
```Rust
Witness::new<RTA>(rev_idx: u32,
                  max_cred_num: u32,
                  r_reg_delta: &RevocationRegisterDelta /* from initial moment to current */,
                  r_tails_accessor: RTA) -> Result<Witness, IndyCryptoError>
                    where RTA: RevocationTailsAccessor

Witness::update<RTA>(&mut self, delta: &RevocationRegisterDelta, rev_idx: u32, max_cred_num: u32, r_tails_accessor: RTA) ->
                     Result<(), IndyCryptoError>
                        where RTA: RevocationTailsAccessor
```

### RevocationRegistry
```Rust
struct RevocationRegistry {
    acc: PointG2,
}

RevocationRegistry::apply_delta(&mut self, delta: &RevocationRegistryDelta) -> ()
RevocationRegistry::revert_delta(&mut self, delta: &RevocationRegistryDelta) -> ()

RevocationRegistry::from_json(&str)
```

### RevocationRegistryDelta
```Rust
struct RevocationRegistryDelta {
    start_acc: PointG2,
    issued: HashSet<u32>,
    revoked: HashSet<u32>,
    acc: PointG2,
}

RevocationRegistryDelta::join(&mut self, other: &RevocationRegistryDelta) -> ()
RevocationRegistryDelta::revert(&mut self, other: &RevocationRegistryDelta) -> ()
```

### Issuer
```Rust
Issuer::new_cred_def(attrs: &CredentialSchema, support_revocation: bool) ->
                          Result<(CredentialPublicKey, CredentialPrivateKey, CredentialKeyCorrectnessProof), IndyCryptoError>

Issuer::new_revocation_registry_def(issuer_pub_key: &CredentialPublicKey,
                                    max_cred_num: u32,
                                    issuence_by_default: bool) -> Result<(RevocationKeyPublic,
                                                                          RevocationKeyPrivate,
                                                                          RevocationRegistry,
                                                                          RevocationTailsGenerator),
                                                                         IndyCryptoError>

Issuer::sign_credential<RTA>(prover_id: &str,
                             blinded_ms: &BlindedMasterSecret,
                             blinded_master_secret_correctness_proof: &BlindedMasterSecretProofCorrectness,
                             master_secret_blinding_nonce: &Nonce,
                             credential_issuance_nonce: &Nonce,
                             credential_values: &CredentialValues,
                             issuer_pub_key: &CredentialPublicKey,
                             issuer_priv_key: &CredentialPrivateKey,
                             rev_idx: Option<u32>,
                             max_cred_num: Option<u32>,
                             r_reg: Option<&mut RevocationRegistry>,
                             r_key_priv: Option<&RevocationKeyPrivate>,
                             rev_tails_accessor: RTA) ->
                                        Result<(CredentialSignature, SignatureCorrectnessProof, Optional<RevocationRegistryDelta>), IndyCryptoError>
                                            where RTA: RevocationTailsAccessor

Issuer::revoke_credential<RTA>(r_reg: &mut RevocationRegistry,
                               max_cred_num: u32,
                               rev_idx: u32,
                               r_tails_accessor: RTA) -> Result<RevocationRegistryDelta, IndyCryptoError>
                                where RTA: RevocationTailsAccessor
```

### Prover
```Rust
Prover::new_master_secret() -> Result<MasterSecret, IndyCryptoError>

Prover::blind_master_secret(credential_pub_key: &CredentialPublicKey,
                            credential_key_correctness_proof: &CredentialKeyCorrectnessProof,
                            master_secret: &MasterSecret,
                            master_secret_blinding_nonce: &Nonce) -> Result<(BlindedMasterSecret,
                                                                             MasterSecretBlindingData,
                                                                             BlindedMasterSecretProofCorrectness),
                                                                            IndyCryptoError>

Prover::process_credential_signature(credential_signature: &mut CredentialSignature,
                                     blinded_master_secret_data: &BlindedMasterSecretData,
                                     p_pub_key: &CredentialPublicKey,
                                     r_pub_key: Option<&RevocationKeyPublic>) -> Result<(), IndyCryptoError>
Prover::new_proof_builder() -> Result<ProofBuilder, IndyCryptoError>

ProofBuilder::add_sub_proof_request(&mut self,
                                    key_id: &str,
                                    sub_proof_req: &SubProofRequest,
                                    schema: &CredentialSchema,
                                    credential_signature: &CredentialSignature,
                                    credential_values: &CredentialValues,
                                    pub_key: &CredentialPublicKey,
                                    r_reg: Option<&RevocationRegistry>
                                    witness: Option<&Witness>)
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
                                     sub_proof_req: &SubProofRequest,
                                     schema: &CredentialSchema,
                                     p_pub_key: &CredentialPublicKey,
                                     r_pub_key: Option<&RevocationKeyPublic>,
                                     rev_reg: Option<&RevocationRegistry>)
                                            -> Result<(), IndyCryptoError>


ProofVerifier::verify(self,
                      proof: &Proof,
                      nonce: &Nonce) -> Result<bool, IndyCryptoError>
```
