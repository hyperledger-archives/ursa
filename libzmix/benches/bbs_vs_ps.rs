extern crate amcl_wrapper;
#[macro_use]
extern crate criterion;
#[macro_use]
extern crate bbs;
extern crate zmix;

use amcl_wrapper::field_elem::FieldElement;

use criterion::Criterion;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use bbs::keys::generate as bbs_keys_generate;
use bbs::messages::{HiddenMessage, ProofMessage};
use bbs::pok_sig::PoKOfSignature as BBSPoKOfSignature;
use bbs::signature::Signature as BBSSignature;
use zmix::signatures::ps::keys::{keygen as ps_keys_generate, Params};
use zmix::signatures::ps::pok_sig::PoKOfSignature as PSPoKOfSignature;
use zmix::signatures::ps::signature::Signature as PSSignature;
use zmix::signatures::SignatureMessageVector;

fn keypair_benchmark(c: &mut Criterion) {
    for atts in vec![1, 2, 5, 10, 20, 50, 100, 200] {
        c.bench_function(format!("create bbs+ key for {}", atts).as_str(), move |b| {
            b.iter(|| bbs_keys_generate(atts))
        });
        c.bench_function(format!("create ps key for {}", atts).as_str(), move |b| {
            let params = Params::new(format!("create ps key for {}", atts).as_bytes());
            b.iter(|| ps_keys_generate(atts, &params))
        });
    }
}

fn sign_messages_benchmark(c: &mut Criterion) {
    for atts in vec![1, 2, 5, 10, 20, 50, 100, 200] {
        let (pk, sk) = bbs_keys_generate(atts).unwrap();
        let attributes = SignatureMessageVector::random(atts);
        c.bench_function(format!("bbs+ sign {} atts", atts).as_str(), |b| {
            b.iter(|| BBSSignature::new(attributes.as_slice(), &sk, &pk))
        });
        let label = format!("ps sign {} atts", atts);
        let params = Params::new(label.as_bytes());
        let (_, sk) = ps_keys_generate(atts, &params);
        c.bench_function(label.as_str(), |b| {
            b.iter(|| PSSignature::new(attributes.as_slice(), &sk, &params))
        });
    }
}

fn bbs_sign_committed_messages_benchmark(c: &mut Criterion) {}

fn bbs_prove_benchmark(c: &mut Criterion) {
    for atts in vec![1, 2, 5, 10, 20, 50, 100, 200] {
        ////////////////////////// BBS+ Signatures
        let (pk, sk) = bbs_keys_generate(atts).unwrap();
        let attributes = SignatureMessageVector::random(atts);
        let sig_atts = attributes
            .iter()
            .map(|m| pm_hidden_raw!(m.clone()))
            .collect::<Vec<ProofMessage>>();
        let sig = BBSSignature::new(attributes.as_slice(), &sk, &pk).unwrap();

        c.bench_function(format!("bbs+ generate proof {} atts", atts).as_str(), |b| {
            b.iter(|| {
                let pok = BBSPoKOfSignature::init(&sig, &pk, &sig_atts).unwrap();
                let challenge = FieldElement::from_msg_hash(&pok.to_bytes());
                pok.gen_proof(&challenge).unwrap()
            })
        });
        let poks = BBSPoKOfSignature::init(&sig, &pk, &sig_atts).unwrap();
        let challenge = FieldElement::from_msg_hash(&poks.to_bytes());
        let proof = poks.gen_proof(&challenge).unwrap();
        c.bench_function(format!("bbs+ verify proof {} atts", atts).as_str(), |b| {
            b.iter(|| proof.verify(&pk, &BTreeMap::new(), &challenge).unwrap())
        });

        ////////////////////////// PS Signatures
        let label = format!("ps verify proof {} atts", atts);
        let params = Params::new(label.as_bytes());
        let (pk, sk) = ps_keys_generate(atts, &params);
        let sig = PSSignature::new(attributes.as_slice(), &sk, &params).unwrap();

        c.bench_function(format!("ps generate proof {} atts", atts).as_str(), |b| {
            b.iter(|| {
                let pok = PSPoKOfSignature::init(
                    &sig,
                    &pk,
                    &params,
                    attributes.as_slice(),
                    None,
                    HashSet::new(),
                )
                .unwrap();
                let chal = FieldElement::from_msg_hash(&pok.to_bytes());
                pok.gen_proof(&chal).unwrap()
            })
        });

        let pok = PSPoKOfSignature::init(
            &sig,
            &pk,
            &params,
            attributes.as_slice(),
            None,
            HashSet::new(),
        )
        .unwrap();
        let chal = FieldElement::from_msg_hash(&pok.to_bytes());
        let proof = pok.gen_proof(&chal).unwrap();

        c.bench_function(label.as_str(), |b| {
            b.iter(|| proof.verify(&pk, &params, HashMap::new(), &chal).unwrap())
        });
    }
}

criterion_group!(
    name = bench_bbs;
    config = Criterion::default();
    targets = keypair_benchmark, sign_messages_benchmark, bbs_sign_committed_messages_benchmark, bbs_prove_benchmark
);

criterion_main!(bench_bbs);
