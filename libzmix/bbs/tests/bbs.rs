#[macro_use]
extern crate bbs;

use bbs::prelude::*;
use std::collections::BTreeMap;

#[test]
fn keygen() {
    let res = Issuer::new_keys(5);

    assert!(res.is_ok());

    let (dpk, _) = Issuer::new_short_keys(None);
    let _ = dpk.to_public_key(5);
    let _ = dpk.to_public_key(7);
}

#[test]
fn sign() {
    let (pk, sk) = Issuer::new_keys(5).unwrap();
    let messages = vec![
        SignatureMessage::hash(b"message 1"),
        SignatureMessage::hash(b"message 2"),
        SignatureMessage::hash(b"message 3"),
        SignatureMessage::hash(b"message 4"),
        SignatureMessage::hash(b"message 5"),
    ];

    let signature = Signature::new(messages.as_slice(), &sk, &pk).unwrap();

    assert!(signature.verify(messages.as_slice(), &pk).unwrap());
}

#[test]
fn blind_sign() {
    let (pk, sk) = Issuer::new_keys(5).unwrap();
    let message = SignatureMessage::hash(b"message_0");

    let signature_blinding = Signature::generate_blinding();

    let mut builder = CommitmentBuilder::new();
    builder.add(&pk.h0, &signature_blinding);
    builder.add(&pk.h[0], &message);

    let commitment = builder.finalize();

    // Completed by the signer
    // `commitment` is received from the recipient
    let messages = sm_map![
        1 => b"message_1",
        2 => b"message_2",
        3 => b"message_3",
        4 => b"message_4"
    ];

    let blind_signature = BlindSignature::new(&commitment, &messages, &sk, &pk).unwrap();

    // Completed by the recipient
    // receives `blind_signature` from signer
    // Recipient knows all `messages` that are signed

    let signature = blind_signature.to_unblinded(&signature_blinding);

    let mut msgs = messages
        .iter()
        .map(|(_, m)| m.clone())
        .collect::<Vec<SignatureMessage>>();
    msgs.insert(0, message.clone());

    let res = signature.verify(msgs.as_slice(), &pk);
    assert!(res.is_ok());
    assert!(res.unwrap());
}

#[test]
fn blind_sign_simple() {
    let (pk, sk) = Issuer::new_keys(5).unwrap();
    let signing_nonce = Issuer::generate_signing_nonce();

    // Send `signing_nonce` to holder

    // Recipient wants to hide a message in each signature to be able to link
    // them together
    let link_secret = Prover::new_link_secret();
    let mut messages = BTreeMap::new();
    messages.insert(0, link_secret.clone());
    let (ctx, signature_blinding) =
        Prover::new_blind_signature_context(&pk, &messages, &signing_nonce).unwrap();

    // Send `ctx` to signer
    let messages = sm_map![
        1 => b"message_1",
        2 => b"message_2",
        3 => b"message_3",
        4 => b"message_4"
    ];

    // Will fail if `ctx` is invalid
    let blind_signature = Issuer::blind_sign(&ctx, &messages, &sk, &pk, &signing_nonce).unwrap();

    // Send `blind_signature` to recipient
    // Recipient knows all `messages` that are signed
    let mut msgs = messages
        .iter()
        .map(|(_, m)| m.clone())
        .collect::<Vec<SignatureMessage>>();
    msgs.insert(0, link_secret.clone());

    let res =
        Prover::complete_signature(&pk, msgs.as_slice(), &blind_signature, &signature_blinding);
    assert!(res.is_ok());
}

#[test]
fn pok_sig() {
    let (pk, sk) = Issuer::new_keys(5).unwrap();
    let messages = vec![
        SignatureMessage::hash(b"message_1"),
        SignatureMessage::hash(b"message_2"),
        SignatureMessage::hash(b"message_3"),
        SignatureMessage::hash(b"message_4"),
        SignatureMessage::hash(b"message_5"),
    ];

    let signature = Signature::new(messages.as_slice(), &sk, &pk).unwrap();

    let nonce = Verifier::generate_proof_nonce();
    let proof_request = Verifier::new_proof_request(&[1, 3], &pk).unwrap();

    // Sends `proof_request` and `nonce` to the prover
    let proof_messages = vec![
        pm_hidden!(b"message_1"),
        pm_revealed!(b"message_2"),
        pm_hidden!(b"message_3"),
        pm_revealed!(b"message_4"),
        pm_hidden!(b"message_5"),
    ];

    let pok = Prover::commit_signature_pok(&proof_request, proof_messages.as_slice(), &signature)
        .unwrap();

    // complete other zkps as desired and compute `challenge_hash`
    let challenge = Prover::create_challenge_hash(vec![pok.clone()], vec![], &nonce).unwrap();

    let proof = Prover::generate_signature_pok(pok, &challenge).unwrap();

    // Send `proof` and `challenge` to Verifier

    match Verifier::verify_signature_pok(&proof_request, &proof, &nonce) {
        Ok(_) => assert!(true),   // check revealed messages
        Err(_) => assert!(false), // Why did the proof failed
    };
}

#[test]
fn pok_sig_extra_message() {
    let (pk, sk) = Issuer::new_keys(5).unwrap();
    let messages = vec![
        SignatureMessage::hash(b"message_1"),
        SignatureMessage::hash(b"message_2"),
        SignatureMessage::hash(b"message_3"),
        SignatureMessage::hash(b"message_4"),
        SignatureMessage::hash(b"message_5"),
    ];

    let signature = Signature::new(messages.as_slice(), &sk, &pk).unwrap();

    let nonce = Verifier::generate_proof_nonce();
    let mut proof_request = Verifier::new_proof_request(&[1, 3], &pk).unwrap();

    // Sends `proof_request` and `nonce` to the prover
    let proof_messages = vec![
        pm_hidden!(b"message_1"),
        pm_revealed!(b"message_2"),
        pm_hidden!(b"message_3"),
        pm_revealed!(b"message_4"),
        pm_hidden!(b"message_5"),
    ];

    let pok = Prover::commit_signature_pok(&proof_request, proof_messages.as_slice(), &signature)
        .unwrap();

    // complete other zkps as desired and compute `challenge_hash`
    let challenge = Prover::create_challenge_hash(vec![pok.clone()], vec![], &nonce).unwrap();

    let mut proof = Prover::generate_signature_pok(pok, &challenge).unwrap();

    // Reveal a message that was hidden, should fail
    proof_request.revealed_messages.insert(4);

    // Send `proof` and `challenge` to Verifier

    match Verifier::verify_signature_pok(&proof_request, &proof, &nonce) {
        Ok(_) => assert!(false),
        Err(_) => assert!(true),
    };

    proof_request.revealed_messages.remove(&4);
    proof
        .revealed_messages
        .insert(4, SignatureMessage::hash(b"message_4"));

    match Verifier::verify_signature_pok(&proof_request, &proof, &nonce) {
        Ok(_) => assert!(false),
        Err(_) => assert!(true),
    };

    proof.revealed_messages.remove(&4);
    proof
        .revealed_messages
        .insert(3, SignatureMessage::random());
    match Verifier::verify_signature_pok(&proof_request, &proof, &nonce) {
        Ok(_) => assert!(false),
        Err(_) => assert!(true),
    };
}

#[test]
fn pok_sig_bad_message() {
    let (pk, sk) = Issuer::new_keys(5).unwrap();
    let messages = vec![
        SignatureMessage::hash(b"message_1"),
        SignatureMessage::hash(b"message_2"),
        SignatureMessage::hash(b"message_3"),
        SignatureMessage::hash(b"message_4"),
        SignatureMessage::hash(b"message_5"),
    ];

    let signature = Signature::new(messages.as_slice(), &sk, &pk).unwrap();

    let nonce = Verifier::generate_proof_nonce();
    let mut proof_request = Verifier::new_proof_request(&[1, 3], &pk).unwrap();

    // Sends `proof_request` and `nonce` to the prover
    let mut proof_messages = vec![
        pm_hidden!(b"message_0"), //message that wasn't signed
        pm_revealed!(b"message_2"),
        pm_hidden!(b"message_3"),
        pm_revealed!(b"message_4"),
        pm_hidden!(b"message_5"),
    ];

    let res = Prover::commit_signature_pok(&proof_request, proof_messages.as_slice(), &signature);
    assert!(res.is_err());
    proof_messages[0] = pm_hidden!(b"message_1");
    let pok = Prover::commit_signature_pok(&proof_request, proof_messages.as_slice(), &signature)
        .unwrap();

    let challenge = Prover::create_challenge_hash(vec![pok.clone()], vec![], &nonce).unwrap();

    let proof = Prover::generate_signature_pok(pok, &challenge).unwrap();
    proof_request.revealed_messages.insert(0);

    match Verifier::verify_signature_pok(&proof_request, &proof, &nonce) {
        Ok(_) => assert!(false),
        Err(_) => assert!(true),
    };

    let proof_request = Verifier::new_proof_request(&[0, 1, 2, 3], &pk).unwrap();
    let pok = Prover::commit_signature_pok(&proof_request, proof_messages.as_slice(), &signature)
        .unwrap();

    let challenge = Prover::create_challenge_hash(vec![pok.clone()], vec![], &nonce).unwrap();

    let mut proof = Prover::generate_signature_pok(pok, &challenge).unwrap();
    proof
        .revealed_messages
        .insert(0, SignatureMessage::hash(b"message_1"));

    //The proof is not what the verifier asked for
    match Verifier::verify_signature_pok(&proof_request, &proof, &nonce) {
        Ok(_) => assert!(false),
        Err(_) => assert!(true),
    };
}

#[test]
fn test_challenge_hash_with_prover_claims() {
    //issue credential
    let (pk, sk) = Issuer::new_keys(5).unwrap();
    let messages = vec![
        SignatureMessage::hash(b"message_1"),
        SignatureMessage::hash(b"message_2"),
        SignatureMessage::hash(b"message_3"),
        SignatureMessage::hash(b"message_4"),
        SignatureMessage::hash(b"message_5"),
    ];

    let signature = Signature::new(messages.as_slice(), &sk, &pk).unwrap();

    //verifier requests credential
    let nonce = Verifier::generate_proof_nonce();
    let proof_request = Verifier::new_proof_request(&[1, 3], &pk).unwrap();

    // Sends `proof_request` and `nonce` to the prover
    let proof_messages = vec![
        pm_hidden!(b"message_1"),
        pm_revealed!(b"message_2"),
        pm_hidden!(b"message_3"),
        pm_revealed!(b"message_4"),
        pm_hidden!(b"message_5"),
    ];

    // prover creates pok for proof request
    let pok = Prover::commit_signature_pok(&proof_request, proof_messages.as_slice(), &signature)
        .unwrap();

    let claims = vec!["self-attested claim1", "self-attested claim2"];

    // complete other zkps as desired and compute `challenge_hash`
    let challenge =
        Prover::create_challenge_hash(vec![pok.clone()], claims.clone(), &nonce).unwrap();

    let proof = Prover::generate_signature_pok(pok, &challenge).unwrap();

    // Send `proof`, `claims`, and `challenge` to Verifier

    // Verifier creates their own challenge bytes
    // and adds proof and claims to it
    let mut ver_chal_bytes = proof.proof.get_bytes_for_challenge(
        proof_request.revealed_messages.clone(),
        &proof_request.verification_key,
    );
    for c in claims {
        ver_chal_bytes.extend_from_slice(c.as_bytes());
    }

    // Verifier completes ver_challenge_bytes by adding verifier_nonce,
    // then constructs the challenge
    ver_chal_bytes.extend_from_slice(&nonce.to_bytes_uncompressed_form()[..]);
    let ver_challenge = ProofChallenge::hash(&ver_chal_bytes);

    // Verifier checks proof1
    let res = proof.proof.verify(
        &proof_request.verification_key,
        &proof.revealed_messages,
        &ver_challenge,
    );
    match res {
        Ok(_) => assert!(true),   // check revealed messages
        Err(_) => assert!(false), // Why did the proof fail?
    };
}

#[test]
fn bbs_demo() {
    // Prover generates link secret
    let link_secret = Prover::new_link_secret();

    // Issuer1 creates keys to sign a credential with 5 claims
    // (one of which is the blinded link secret)
    let (pk1, sk1) = Issuer::new_keys(5).unwrap();

    let same_claim = SignatureMessage::hash(b"same_claim");

    // Prover desires a credential from Issuer1,
    // Issuer1 constructs the credential
    let mut credential1 = sm_map![
        1 => b"claim1_first_name",
        3 => b"claim3_email",
        4 => b"claim4_address"
    ];
    credential1.insert(2, same_claim.clone());

    // Issuer1 generates a signing nonce and sends it to the Prover
    let signing_nonce1 = Issuer::generate_signing_nonce();

    // Prover creates set of blind claims (link secret) which will be included in the credential
    let mut blind_claims1 = BTreeMap::new();
    blind_claims1.insert(0, link_secret.clone());

    // Prover generates blind signature context and sends it to Issuer1
    // Prover stores signature blinding
    let (ctx1, signature_blinding1) =
        Prover::new_blind_signature_context(&pk1, &blind_claims1, &signing_nonce1).unwrap();

    // Issuer1 signs the credential and sends it to the Prover
    let blind_signature1 =
        Issuer::blind_sign(&ctx1, &credential1, &sk1, &pk1, &signing_nonce1).unwrap();

    // Prover adds link secret to the credential from Issuer1
    let mut full_credential1 = credential1
        .iter()
        .map(|(_, m)| m.clone())
        .collect::<Vec<SignatureMessage>>();
    full_credential1.insert(0, link_secret.clone());

    // Prover completes the signature from Issuer1
    let complete_signature1 = Prover::complete_signature(
        &pk1,
        full_credential1.as_slice(),
        &blind_signature1,
        &signature_blinding1,
    );

    // Prover verifies the signature from Issuer1
    assert!(complete_signature1.is_ok());
    let complete_sig1 = complete_signature1.unwrap();
    assert!(complete_sig1
        .verify(full_credential1.as_slice(), &pk1)
        .unwrap());

    // Issuer2 creates keys to sign a credential with 4 claims
    // (one of which is the blinded link secret)
    let (pk2, sk2) = Issuer::new_keys(4).unwrap();

    // Prover desires a credential from Issuer2,
    // Issuer2 constructs the credential
    let mut credential2 = sm_map![
        1 => b"claim1_loyalty_program_id",
        2 => b"claim2_customer_id"
    ];
    credential2.insert(3, same_claim.clone());

    assert_eq!(credential1[&2], credential2[&3]);

    // Issuer2 generates a signing nonce and sends it to the Prover
    let signing_nonce2 = Issuer::generate_signing_nonce();

    // Prover creates set of blind claims (link secret) which will be included in the credential
    let mut blind_claims2 = BTreeMap::new();
    blind_claims2.insert(0, link_secret.clone());

    // Prover generates blind signature context and sends it to Issuer2
    // Prover stores signature blinding
    let (ctx2, signature_blinding2) =
        Prover::new_blind_signature_context(&pk2, &blind_claims2, &signing_nonce2).unwrap();

    // Issuer2 signs the credential and sends it to the Prover
    let blind_signature2 =
        Issuer::blind_sign(&ctx2, &credential2, &sk2, &pk2, &signing_nonce2).unwrap();

    // Prover adds link secret to the credential from Issuer2
    let mut full_credential2 = credential2
        .iter()
        .map(|(_, m)| m.clone())
        .collect::<Vec<SignatureMessage>>();
    full_credential2.insert(0, link_secret.clone());

    assert_eq!(full_credential1[0], full_credential2[0]);
    assert_eq!(full_credential1[2], full_credential2[3]);

    // Prover completes the signature from Issuer2
    let complete_signature2 = Prover::complete_signature(
        &pk2,
        full_credential2.as_slice(),
        &blind_signature2,
        &signature_blinding2,
    );

    // Prover verifies the signature from Issuer1
    assert!(complete_signature2.is_ok());
    let complete_sig2 = complete_signature2.unwrap();
    assert!(complete_sig2
        .verify(full_credential2.as_slice(), &pk2)
        .unwrap());

    // Verifier wants the Prover to reveal claim1 from Issuer1,
    // plus a proof that claim2 from Issuer1 and claim3 from Issuer2 are identical
    // Verifier creates a nonce
    let verifier_nonce = Verifier::generate_proof_nonce();

    // Verifier creates proof request for the reveal of claim1 from credential1 from Issuer1
    let proof_request1 = Verifier::new_proof_request(&[1], &pk1).unwrap();

    // Verifier creates proof request for credential2 from Issuer2
    let proof_request2 = Verifier::new_proof_request(&[], &pk2).unwrap();

    // and additionally communicates the request for a ZK equality proof of
    // claim2 from credential1 and claim3 from credential2.

    // Prover creates a blinding factor to use for his link secrets.
    let link_secret_blinding = ProofNonce::random();

    // Prover creates a blinding factor to use for the ZK equality proof of
    // claim2 from credential1 and claim3 from credential2.
    let same_blinding = ProofNonce::random();

    // Prover constructs proof messages from credential1
    // for selective disclosure of claim1 and ZK equality proof of claim2
    let proof_messages1 = vec![
        pm_hidden_raw!(link_secret.clone(), link_secret_blinding.clone()),
        pm_revealed!(b"claim1_first_name"),
        pm_hidden_raw!(same_claim.clone(), same_blinding.clone()),
        pm_hidden!(b"claim3_email"),
        pm_hidden!(b"claim4_address"),
    ];

    // Prover constructs signature proof of knowledge for credential1
    let pok1 =
        Prover::commit_signature_pok(&proof_request1, proof_messages1.as_slice(), &complete_sig1)
            .unwrap();

    // Prover constructs proof messages from credential2
    // for ZK equality proof of claim3
    let proof_messages2 = vec![
        pm_hidden_raw!(link_secret.clone(), link_secret_blinding.clone()),
        pm_hidden!(b"claim1_loyalty_program_id"),
        pm_hidden!(b"claim2_customer_id"),
        pm_hidden_raw!(same_claim.clone(), same_blinding.clone()),
    ];

    // Prover constructs signature proof of knowledge for credential2
    let pok2 =
        Prover::commit_signature_pok(&proof_request2, proof_messages2.as_slice(), &complete_sig2)
            .unwrap();

    // Prover creates challenge_bytes and adds pok1 and pok2 to it.
    let mut chal_bytes = Vec::new();
    chal_bytes.extend_from_slice(pok1.to_bytes().as_slice());
    chal_bytes.extend_from_slice(pok2.to_bytes().as_slice());

    // Prover completes challenge_bytes by adding verifier_nonce,
    // then constructs the challenge
    chal_bytes.extend_from_slice(&verifier_nonce.to_bytes_uncompressed_form()[..]);
    let challenge = ProofChallenge::hash(&chal_bytes);

    // Prover constructs the proofs and sends them to the Verifier
    let proof1 = Prover::generate_signature_pok(pok1, &challenge).unwrap();
    let proof2 = Prover::generate_signature_pok(pok2, &challenge).unwrap();

    // Verifier creates their own challenge bytes
    // and adds proof1 and proof2 to it
    let mut ver_chal_bytes = proof1.proof.get_bytes_for_challenge(
        proof_request1.revealed_messages.clone(),
        &proof_request1.verification_key,
    );
    ver_chal_bytes.extend_from_slice(
        proof2
            .proof
            .get_bytes_for_challenge(
                proof_request2.revealed_messages.clone(),
                &proof_request2.verification_key,
            )
            .as_slice(),
    );

    // Verifier completes ver_challenge_bytes by adding verifier_nonce,
    // then constructs the challenge
    ver_chal_bytes.extend_from_slice(&verifier_nonce.to_bytes_uncompressed_form()[..]);
    let ver_challenge = ProofChallenge::hash(&ver_chal_bytes);

    // Verifier checks proof1
    let res1 = proof1.proof.verify(
        &proof_request1.verification_key,
        &proof1.revealed_messages,
        &ver_challenge,
    );
    match res1 {
        Ok(_) => assert!(true),   // check revealed messages
        Err(_) => assert!(false), // Why did the proof fail?
    };

    // Verifier checks proof1
    let res2 = proof2.proof.verify(
        &proof_request2.verification_key,
        &proof2.revealed_messages,
        &ver_challenge,
    );
    match res2 {
        Ok(_) => assert!(true),   // check revealed messages
        Err(_) => assert!(false), // Why did the proof fail?
    };

    // Verifier checks equality of link secrets
    assert_eq!(
        proof1.proof.get_resp_for_message(0).unwrap(),
        proof2.proof.get_resp_for_message(0).unwrap()
    );

    // Verifier checks validity of ZK equality proof of
    // claim2 from credential1 (which is index 1 of the hidden values in proof1)
    // and claim3 from credential2 (which is index 3 of the hidden values in proof2)
    assert_eq!(
        proof1.proof.get_resp_for_message(1).unwrap(),
        proof2.proof.get_resp_for_message(3).unwrap()
    );
}
