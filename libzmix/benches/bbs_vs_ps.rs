#[macro_use]
extern crate criterion;
extern crate zmix;

use criterion::Criterion;

use zmix::signatures::bbs::prelude::*;

fn bbs_keypair_benchmark(c: &mut Criterion) {
    for i in vec![1, 2, 5, 10, 20, 50, 100] {
        let atts = i;
        c.bench_function(format!("create key for {}", i).as_str(), move |b| {
            b.iter(|| generate(atts))
        });
    }
}

fn bbs_sign_messages_benchmark(c: &mut Criterion) {
    for i in vec![1, 2, 5, 10, 20, 50, 100] {
        let atts = i;
        let (pk, sk) = generate(atts).unwrap();
        let mut attributes = Vec::new();
        for _ in 0..i {
            attributes.push(BBSMessage::random());
        }
        c.bench_function(format!("sign {} atts", i).as_str(), move |b| {
            b.iter(|| Signature::new(attributes.as_slice(), &sk, &pk))
        });
    }
}

fn bbs_sign_committed_messages_benchmark(c: &mut Criterion) {
    for i in vec![1, 2, 5, 10, 20, 50, 100] {
        let atts = i;
        let keypair = generate(atts).unwrap();
        let mut attributes = Vec::new();
        for _ in 0..i {
            attributes.push(BBSMessage::random());
        }
        c.bench_function(format!("2 party sign {} atts", i).as_str(), move |b| {
            b.iter(|| {
                let mut protocol = bbs::SignatureProtocol::new(&format!("{}", i));
                let s = protocol
                    .blind_attributes(&keypair.public_key, &attributes[0..1])
                    .unwrap();
                protocol
                    .issue_signature(&keypair, &attributes[1..])
                    .unwrap();
                let _signature = protocol
                    .complete_signature(&keypair.public_key, &s, &attributes[1..])
                    .unwrap();
            })
        });
    }
}

fn bbs_prove_benchmark(c: &mut Criterion) {}

criterion_group!(
    name = bench_bbs;
    config = Criterion::default();
    targets = bbs_keypair_benchmark, bbs_sign_messages_benchmark, bbs_sign_committed_messages_benchmark, bbs_prove_benchmark
);

criterion_main!(bench_bbs);
