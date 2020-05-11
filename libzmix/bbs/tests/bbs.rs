#[macro_use]
extern crate bbs;

use bbs::prelude::*;
use std::collections::BTreeMap;

#[test]
fn keygen() {
    let res = Issuer::new_keys(5);

    assert!(res.is_ok());

    let (dpk, _) = Issuer::new_short_keys(None);
    let dst = DomainSeparationTag::new(b"testgen", None, None, None).unwrap();
    let _ = dpk.to_public_key(5, dst.clone());
    let _ = dpk.to_public_key(7, dst);
}

#[test]
fn sign() {
    let (pk, sk) = Issuer::new_keys(5).unwrap();
    let messages = vec![
        SignatureMessage::from_msg_hash(b"message 1"),
        SignatureMessage::from_msg_hash(b"message 2"),
        SignatureMessage::from_msg_hash(b"message 3"),
        SignatureMessage::from_msg_hash(b"message 4"),
        SignatureMessage::from_msg_hash(b"message 5"),
    ];

    let signature = Signature::new(messages.as_slice(), &sk, &pk).unwrap();

    assert!(signature.verify(messages.as_slice(), &pk).unwrap());
}

#[test]
fn blind_sign() {
    let (pk, sk) = Issuer::new_keys(5).unwrap();
    let message = SignatureMessage::from_msg_hash(b"message_0");

    let signature_blinding = Signature::generate_blinding();

    let commitment = &pk.h[0] * &message + &pk.h0 * &signature_blinding;

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
        SignatureMessage::from_msg_hash(b"message_1"),
        SignatureMessage::from_msg_hash(b"message_2"),
        SignatureMessage::from_msg_hash(b"message_3"),
        SignatureMessage::from_msg_hash(b"message_4"),
        SignatureMessage::from_msg_hash(b"message_5"),
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
        SignatureMessage::from_msg_hash(b"message_1"),
        SignatureMessage::from_msg_hash(b"message_2"),
        SignatureMessage::from_msg_hash(b"message_3"),
        SignatureMessage::from_msg_hash(b"message_4"),
        SignatureMessage::from_msg_hash(b"message_5"),
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
        .insert(4, SignatureMessage::from_msg_hash(b"message_4"));

    match Verifier::verify_signature_pok(&proof_request, &proof, &nonce) {
        Ok(_) => assert!(false),
        Err(_) => assert!(true),
    };

    proof.revealed_messages.remove(&4);
    proof.revealed_messages.insert(3, SignatureMessage::new());
    match Verifier::verify_signature_pok(&proof_request, &proof, &nonce) {
        Ok(_) => assert!(false),
        Err(_) => assert!(true),
    };
}

#[test]
fn pok_sig_bad_message() {
    let (pk, sk) = Issuer::new_keys(5).unwrap();
    let messages = vec![
        SignatureMessage::from_msg_hash(b"message_1"),
        SignatureMessage::from_msg_hash(b"message_2"),
        SignatureMessage::from_msg_hash(b"message_3"),
        SignatureMessage::from_msg_hash(b"message_4"),
        SignatureMessage::from_msg_hash(b"message_5"),
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

    let challenge = Prover::create_challenge_hash(vec![pok.clone()], vec![],&nonce).unwrap();

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
        .insert(0, SignatureMessage::from_msg_hash(b"message_1"));

    //The proof is not what the verifier asked for
    match Verifier::verify_signature_pok(&proof_request, &proof, &nonce) {
        Ok(_) => assert!(false),
        Err(_) => assert!(true),
    };
}

#[test]
fn test_challenge_hash_with_prover_claims(){
    //issue credential
    let (pk, sk) = Issuer::new_keys(5).unwrap();
    let messages = vec![
        SignatureMessage::from_msg_hash(b"message_1"),
        SignatureMessage::from_msg_hash(b"message_2"),
        SignatureMessage::from_msg_hash(b"message_3"),
        SignatureMessage::from_msg_hash(b"message_4"),
        SignatureMessage::from_msg_hash(b"message_5"),
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
    for c in claims{
        ver_chal_bytes.extend_from_slice(c.as_bytes());
    }

    // Verifier completes ver_challenge_bytes by adding verifier_nonce,
    // then constructs the challenge
    ver_chal_bytes.extend_from_slice(&nonce.to_bytes()[..]);
    let ver_challenge = SignatureNonce::from_msg_hash(&ver_chal_bytes);

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
