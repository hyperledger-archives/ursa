extern crate amcl_wrapper;
extern crate zmix;

use amcl_wrapper::group_elem::GroupElement;
use std::collections::{HashMap, HashSet};
use zmix::signatures::prelude::*;
use zmix::signatures::ps::prelude::*;

#[test]
fn test_scenario_1() {
    // User request signer to sign 10 messages where signer knows only 8 messages, the other 2 are given in a form of commitment.
    // Once user receives the signature, it engages in a proof of knowledge of signature with a verifier.
    // The user also reveals to the verifier some of the messages.
    let count_msgs = 10;
    let committed_msgs = 2;
    let (vk, sk) = generate(count_msgs, "test".as_bytes());
    let msgs = SignatureMessageVector::random(count_msgs);
    let blinding = SignatureMessage::random();

    // User commits to some messages
    let mut comm = SignatureGroup::new();
    for i in 0..committed_msgs {
        comm += &vk.Y[i] * &msgs[i];
    }
    comm += &vk.g * &blinding;

    {
        // User and signer engage in a proof of knowledge for the above commitment `comm`
        let mut bases = Vec::<SignatureGroup>::new();
        let mut hidden_msgs = Vec::<SignatureMessage>::new();
        for i in 0..committed_msgs {
            bases.push(vk.Y[i].clone());
            hidden_msgs.push(msgs[i].clone());
        }
        bases.push(vk.g.clone());
        hidden_msgs.push(blinding.clone());

        // User creates a random commitment, computes challenge and response. The proof of knowledge consists of commitment and responses
        let mut committing = ProverCommittingSignatureGroup::new();
        for b in &bases {
            committing.commit(b, None);
        }
        let committed = committing.finish();

        // Note: The challenge may come from the main protocol
        let chal = committed.gen_challenge(comm.to_bytes());

        let proof = committed.gen_proof(&chal, hidden_msgs.as_slice()).unwrap();

        // Signer verifies the proof of knowledge.
        assert!(proof.verify(bases.as_slice(), &comm, &chal).unwrap());
    }

    // Get signature, unblind it and then verify.
    let sig_blinded = Signature::new_with_committed_messages(
        &comm,
        &msgs.as_slice()[committed_msgs..count_msgs],
        &sk,
        &vk,
    )
    .unwrap();
    let sig_unblinded = sig_blinded.get_unblinded_signature(&blinding);
    assert!(sig_unblinded.verify(msgs.as_slice(), &vk).unwrap());

    // Do a proof of knowledge of the signature and also reveal some of the messages.
    let mut revealed_msg_indices = HashSet::new();
    revealed_msg_indices.insert(4);
    revealed_msg_indices.insert(6);
    revealed_msg_indices.insert(9);

    let pok = PoKOfSignature::init(
        &sig_unblinded,
        &vk,
        msgs.as_slice(),
        None,
        revealed_msg_indices.clone(),
    )
    .unwrap();

    let chal = SignatureMessage::from_msg_hash(&pok.to_bytes());

    let proof = pok.gen_proof(&chal).unwrap();

    let mut revealed_msgs = HashMap::new();
    for i in &revealed_msg_indices {
        revealed_msgs.insert(i.clone(), msgs[*i].clone());
    }
    assert!(proof.verify(&vk, revealed_msgs.clone(), &chal).unwrap());
}
