#[macro_use]
extern crate criterion;
extern crate amcl_wrapper;
extern crate ursa;

use amcl_wrapper::field_elem::FieldElement;
use criterion::Criterion;

use ursa::signatures::bls::{
    normal::{
        generate as usual_generate, AggregatedPublicKey as UsualAggregatedPublicKey,
        AggregatedSignature as UsualAggregatedSignature, PublicKey as UsualPublicKey,
        Signature as UsualSignature,
    },
    small::{
        generate as small_generate, AggregatedPublicKey as SmallAggregatedPublicKey,
        AggregatedSignature as SmallAggregatedSignature, PublicKey as SmallPublicKey,
        Signature as SmallSignature,
    },
};

fn keypair_benchmark(c: &mut Criterion) {
    c.bench_function(format!("Create usual bls key pair").as_str(), move |b| {
        b.iter(|| usual_generate());
    });
    c.bench_function(format!("Create small bls key pair").as_str(), move |b| {
        b.iter(|| small_generate());
    });
}

fn sign_benchmark(c: &mut Criterion) {
    let msg = b"This is a test message";
    let (_, usk) = usual_generate();
    c.bench_function(format!("Sign usual bls").as_str(), move |b| {
        b.iter(|| UsualSignature::new(&msg[..], &usk));
    });

    let (_, ssk) = small_generate();
    c.bench_function(format!("Sign small bls").as_str(), move |b| {
        b.iter(|| SmallSignature::new(&msg[..], &ssk));
    });
}

fn verify_benchmark(c: &mut Criterion) {
    let msg = b"This is a test message to verify";
    let (upk, usk) = usual_generate();
    let usg = UsualSignature::new(&msg[..], &usk);
    c.bench_function(format!("Verify usual bls").as_str(), move |b| {
        b.iter(|| assert!(usg.verify(&msg[..], &upk)));
    });

    let (spk, ssk) = small_generate();
    let ssg = SmallSignature::new(&msg[..], &ssk);
    c.bench_function(format!("Verify small bls").as_str(), move |b| {
        b.iter(|| assert!(ssg.verify(&msg[..], &spk)));
    });
}

fn verify_aggregate_no_rk_benchmark(c: &mut Criterion) {
    const MSG_COUNT: usize = 10;
    let msg = b"This is a test message for aggregate signatures";
    let mut upks = Vec::new();
    let mut usig = Vec::new();
    for _ in 0..MSG_COUNT {
        let (pk, sk) = usual_generate();
        let sig = UsualSignature::new(&msg[..], &sk);
        upks.push(pk);
        usig.push(sig);
    }

    let uasg = UsualAggregatedSignature::new(usig.as_slice());

    c.bench_function(
        format!("Usual bls aggregate signatures no rogue key protection").as_str(),
        move |b| {
            b.iter(|| UsualAggregatedSignature::new(usig.as_slice()));
        },
    );

    c.bench_function(
        format!("Usual bls aggregate signatures no rogue key protection verify").as_str(),
        move |b| {
            b.iter(|| assert!(uasg.verify_no_rk(&msg[..], upks.as_slice())));
        },
    );

    let mut spks = Vec::new();
    let mut ssig = Vec::new();
    for _ in 0..MSG_COUNT {
        let (pk, sk) = small_generate();
        let sig = SmallSignature::new(&msg[..], &sk);
        spks.push(pk);
        ssig.push(sig);
    }
    let sasg = SmallAggregatedSignature::new(ssig.as_slice());

    c.bench_function(
        format!("Small bls aggregate signatures no rogue key protection").as_str(),
        move |b| {
            b.iter(|| SmallAggregatedSignature::new(ssig.as_slice()));
        },
    );

    c.bench_function(
        format!("Small bls aggregate signatures no rogue key protection verify").as_str(),
        move |b| {
            b.iter(|| assert!(sasg.verify_no_rk(&msg[..], spks.as_slice())));
        },
    );
}

fn verify_aggregate_rk_benchmark(c: &mut Criterion) {
    const MSG_COUNT: usize = 10;
    let msg = b"This is a test message for aggregate signatures with rogue key protection";
    let mut upks = Vec::new();
    let mut usks = Vec::new();
    for _ in 0..MSG_COUNT {
        let (pk, sk) = usual_generate();
        upks.push(pk);
        usks.push(sk);
    }
    let uapk = UsualAggregatedPublicKey::new(upks.as_slice());

    let mut usig = Vec::new();
    for i in 0..MSG_COUNT {
        let sig = UsualSignature::new_with_rk_mitigation(&msg[..], &usks[i], i, upks.as_slice());
        usig.push(sig);
    }

    c.bench_function(
        format!("Usual bls sign with rogue key protection").as_str(),
        move |b| {
            b.iter(|| {
                UsualSignature::new_with_rk_mitigation(&msg[..], &usks[0], 0, upks.as_slice())
            });
        },
    );

    let uasg = UsualAggregatedSignature::new(usig.as_slice());

    c.bench_function(
        format!("Usual bls aggregate signatures rogue key protection verify").as_str(),
        move |b| {
            b.iter(|| assert!(uasg.verify(&msg[..], &uapk)));
        },
    );

    let mut spks = Vec::new();
    let mut ssks = Vec::new();
    for _ in 0..MSG_COUNT {
        let (pk, sk) = small_generate();
        spks.push(pk);
        ssks.push(sk);
    }

    let sapk = SmallAggregatedPublicKey::new(spks.as_slice());

    let mut ssig = Vec::new();
    for i in 0..MSG_COUNT {
        let sig = SmallSignature::new_with_rk_mitigation(&msg[..], &ssks[i], i, spks.as_slice());
        ssig.push(sig);
    }

    c.bench_function(
        format!("Small bls sign with rogue key protection").as_str(),
        move |b| {
            b.iter(|| {
                SmallSignature::new_with_rk_mitigation(&msg[..], &ssks[0], 0, spks.as_slice())
            });
        },
    );

    let sasg = SmallAggregatedSignature::new(ssig.as_slice());

    c.bench_function(
        format!("Small bls aggregate signatures rogue key protection verify").as_str(),
        move |b| {
            b.iter(|| assert!(sasg.verify(&msg[..], &sapk)));
        },
    );
}

fn verify_multisig(c: &mut Criterion) {
    const MSG_COUNT: usize = 10;

    let mut usgs = Vec::new();
    let mut msgs = Vec::new();

    for _ in 0..MSG_COUNT {
        let (pk, sk) = usual_generate();
        let msg = FieldElement::random();
        let sig = UsualSignature::new(msg.to_bytes().as_slice(), &sk);
        usgs.push(sig);
        msgs.push((msg.to_bytes(), pk));
    }

    let mut usig = usgs[0].clone();
    usig.aggregate(&usgs[1..]);

    c.bench_function(
        format!("Usual bls multisignature verify").as_str(),
        move |b| {
            let refs = msgs
                .iter()
                .map(|(m, p)| (m.as_slice(), p))
                .collect::<Vec<(&[u8], &UsualPublicKey)>>();
            b.iter(|| assert!(usig.verify_multi(refs.as_slice())));
        },
    );

    let mut ssgs = Vec::new();
    let mut msgs = Vec::new();

    for _ in 0..MSG_COUNT {
        let (pk, sk) = small_generate();
        let msg = FieldElement::random();
        let sig = SmallSignature::new(msg.to_bytes().as_slice(), &sk);
        ssgs.push(sig);
        msgs.push((msg.to_bytes(), pk));
    }

    let mut ssig = ssgs[0].clone();
    ssig.aggregate(&ssgs[1..]);

    c.bench_function(
        format!("Small bls multisignature verify").as_str(),
        move |b| {
            let refs = msgs
                .iter()
                .map(|(m, p)| (m.as_slice(), p))
                .collect::<Vec<(&[u8], &SmallPublicKey)>>();
            b.iter(|| assert!(ssig.verify_multi(refs.as_slice())));
        },
    );
}

criterion_group!(
    name = bench_bls;
    config = Criterion::default();
    targets = keypair_benchmark, sign_benchmark, verify_benchmark, verify_aggregate_no_rk_benchmark, verify_aggregate_rk_benchmark, verify_multisig
);

criterion_main!(bench_bls);
