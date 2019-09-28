#[macro_use]
extern crate criterion;
extern crate zmix;

use criterion::Criterion;

use zmix::signatures::bbs::keys::generate as bbs_keys_generate;
use zmix::signatures::bbs::signature::Signature as BBSSignature;
use zmix::signatures::ps::keys::keygen as ps_keys_generate;
use zmix::signatures::ps::signature::Signature as PSSignature;
use zmix::signatures::SignatureMessageVector;

fn keypair_benchmark(c: &mut Criterion) {
    for atts in vec![1, 2, 5, 10, 20, 50, 100] {
        c.bench_function(format!("create bbs+ key for {}", atts).as_str(), move |b| {
            b.iter(|| bbs_keys_generate(atts))
        });
        c.bench_function(format!("create ps key for {}", atts).as_str(), move |b| {
            b.iter(|| ps_keys_generate(atts, format!("create ps key for {}", atts).as_bytes()))
        });
    }
}

fn sign_messages_benchmark(c: &mut Criterion) {
    for atts in vec![1, 2, 5, 10, 20, 50, 100] {
        let (pk, sk) = bbs_keys_generate(atts).unwrap();
        let attributes = SignatureMessageVector::random(atts);
        c.bench_function(format!("bbs+ sign {} atts", atts).as_str(), |b| {
            b.iter(|| BBSSignature::new(attributes.as_slice(), &sk, &pk))
        });
        let label = format!("ps sign {} atts", atts);
        let (pk, sk) = ps_keys_generate(atts, label.as_bytes());
        c.bench_function(label.as_str(), |b| {
            b.iter(|| PSSignature::new(attributes.as_slice(), &sk, &pk))
        });
    }
}

fn bbs_sign_committed_messages_benchmark(c: &mut Criterion) {}

fn bbs_prove_benchmark(c: &mut Criterion) {}

criterion_group!(
    name = bench_bbs;
    config = Criterion::default();
    targets = keypair_benchmark, sign_messages_benchmark, bbs_sign_committed_messages_benchmark, bbs_prove_benchmark
);

criterion_main!(bench_bbs);
