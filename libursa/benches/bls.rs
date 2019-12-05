#[macro_use]
extern crate criterion;
extern crate amcl_wrapper;
extern crate ursa;

use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use criterion::Criterion;

use ursa::signatures::bls::{
    normal::{
        generate as usual_generate, AggregatedPublicKey as UsualAggregatedPublicKey,
        AggregatedSignature as UsualAggregatedSignature, Generator as UsualGenerator,
        PublicKey as UsualPublicKey, Signature as UsualSignature,
    },
    small::{
        generate as small_generate, AggregatedPublicKey as SmallAggregatedPublicKey,
        AggregatedSignature as SmallAggregatedSignature, Generator as SmallGenerator,
        PublicKey as SmallPublicKey, Signature as SmallSignature,
    },
};

fn keypair_benchmark(c: &mut Criterion) {
    let g = UsualGenerator::generator();
    c.bench_function(format!("Create usual bls key pair").as_str(), move |b| {
        b.iter(|| usual_generate(&g));
    });
    let g = SmallGenerator::generator();
    c.bench_function(format!("Create small bls key pair").as_str(), move |b| {
        b.iter(|| small_generate(&g));
    });
}

fn sign_benchmark(c: &mut Criterion) {
    let msg = b"This is a test message";
    let g = UsualGenerator::generator();
    let (_, usk) = usual_generate(&g);
    c.bench_function(format!("Sign usual bls").as_str(), move |b| {
        b.iter(|| UsualSignature::new(&msg[..], None, &usk));
    });

    let g = SmallGenerator::generator();
    let (_, ssk) = small_generate(&g);
    c.bench_function(format!("Sign small bls").as_str(), move |b| {
        b.iter(|| SmallSignature::new(&msg[..], None, &ssk));
    });
}

fn verify_benchmark(c: &mut Criterion) {
    let msg = b"This is a test message to verify";
    let g = UsualGenerator::generator();
    let (upk, usk) = usual_generate(&g);
    let usg = UsualSignature::new(&msg[..], None, &usk);
    c.bench_function(format!("Verify usual bls").as_str(), move |b| {
        b.iter(|| assert!(usg.verify(&msg[..], None, &upk, &g)));
    });

    let g = SmallGenerator::generator();
    let (spk, ssk) = small_generate(&g);
    let ssg = SmallSignature::new(&msg[..], None, &ssk);
    c.bench_function(format!("Verify small bls").as_str(), move |b| {
        b.iter(|| assert!(ssg.verify(&msg[..], None, &spk, &g)));
    });
}

fn verify_aggregate_no_rk_benchmark(c: &mut Criterion) {
    const MSG_COUNT: usize = 10;
    let msg = b"This is a test message for aggregate signatures";
    let mut upks = Vec::new();
    let mut usig = Vec::new();
    let g = UsualGenerator::generator();
    for _ in 0..MSG_COUNT {
        let (pk, sk) = usual_generate(&g);
        let sig = UsualSignature::new(&msg[..], None, &sk);
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
            b.iter(|| assert!(uasg.verify_no_rk(&msg[..], None, upks.as_slice(), &g)));
        },
    );

    let g = SmallGenerator::generator();
    let mut spks = Vec::new();
    let mut ssig = Vec::new();
    for _ in 0..MSG_COUNT {
        let (pk, sk) = small_generate(&g);
        let sig = SmallSignature::new(&msg[..], None, &sk);
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
            b.iter(|| assert!(sasg.verify_no_rk(&msg[..], None, spks.as_slice(), &g)));
        },
    );
}

fn verify_aggregate_rk_benchmark(c: &mut Criterion) {
    const MSG_COUNT: usize = 10;
    let g = UsualGenerator::generator();
    let msg = b"This is a test message for aggregate signatures with rogue key protection";
    let mut upks = Vec::new();
    let mut usks = Vec::new();
    for _ in 0..MSG_COUNT {
        let (pk, sk) = usual_generate(&g);
        upks.push(pk);
        usks.push(sk);
    }
    let uapk = UsualAggregatedPublicKey::new(upks.as_slice());

    let mut usig = Vec::new();
    for i in 0..MSG_COUNT {
        let sig =
            UsualSignature::new_with_rk_mitigation(&msg[..], None, &usks[i], i, upks.as_slice());
        usig.push(sig);
    }

    c.bench_function(
        format!("Usual bls sign with rogue key protection").as_str(),
        move |b| {
            b.iter(|| {
                UsualSignature::new_with_rk_mitigation(&msg[..], None, &usks[0], 0, upks.as_slice())
            });
        },
    );

    let uasg = UsualAggregatedSignature::new(usig.as_slice());

    c.bench_function(
        format!("Usual bls aggregate signatures rogue key protection verify").as_str(),
        move |b| {
            b.iter(|| assert!(uasg.verify(&msg[..], None, &uapk, &g)));
        },
    );

    let g = SmallGenerator::generator();
    let mut spks = Vec::new();
    let mut ssks = Vec::new();
    for _ in 0..MSG_COUNT {
        let (pk, sk) = small_generate(&g);
        spks.push(pk);
        ssks.push(sk);
    }

    let sapk = SmallAggregatedPublicKey::new(spks.as_slice());

    let mut ssig = Vec::new();
    for i in 0..MSG_COUNT {
        let sig =
            SmallSignature::new_with_rk_mitigation(&msg[..], None, &ssks[i], i, spks.as_slice());
        ssig.push(sig);
    }

    c.bench_function(
        format!("Small bls sign with rogue key protection").as_str(),
        move |b| {
            b.iter(|| {
                SmallSignature::new_with_rk_mitigation(&msg[..], None, &ssks[0], 0, spks.as_slice())
            });
        },
    );

    let sasg = SmallAggregatedSignature::new(ssig.as_slice());

    c.bench_function(
        format!("Small bls aggregate signatures rogue key protection verify").as_str(),
        move |b| {
            b.iter(|| assert!(sasg.verify(&msg[..], None, &sapk, &g)));
        },
    );
}

fn verify_multisig(c: &mut Criterion) {
    const MSG_COUNT: usize = 10;

    let g = UsualGenerator::generator();
    let mut usgs = Vec::new();
    let mut msgs = Vec::new();

    for _ in 0..MSG_COUNT {
        let (pk, sk) = usual_generate(&g);
        let msg = FieldElement::random();
        let sig = UsualSignature::new(msg.to_bytes().as_slice(), None, &sk);
        usgs.push(sig);
        msgs.push((msg.to_bytes(), pk));
    }

    let mut usig = usgs[0].clone();
    usig.combine(&usgs[1..]);

    c.bench_function(
        format!("Usual bls multisignature verify").as_str(),
        move |b| {
            let refs = msgs
                .iter()
                .map(|(m, p)| (m.as_slice(), p))
                .collect::<Vec<(&[u8], &UsualPublicKey)>>();
            b.iter(|| assert!(usig.verify_multi(refs.as_slice(), None, &g)));
        },
    );

    let g = SmallGenerator::generator();
    let mut ssgs = Vec::new();
    let mut msgs = Vec::new();

    for _ in 0..MSG_COUNT {
        let (pk, sk) = small_generate(&g);
        let msg = FieldElement::random();
        let sig = SmallSignature::new(msg.to_bytes().as_slice(), None, &sk);
        ssgs.push(sig);
        msgs.push((msg.to_bytes(), pk));
    }

    let mut ssig = ssgs[0].clone();
    ssig.combine(&ssgs[1..]);

    c.bench_function(
        format!("Small bls multisignature verify").as_str(),
        move |b| {
            let refs = msgs
                .iter()
                .map(|(m, p)| (m.as_slice(), p))
                .collect::<Vec<(&[u8], &SmallPublicKey)>>();
            b.iter(|| assert!(ssig.verify_multi(refs.as_slice(), None, &g)));
        },
    );
}

criterion_group!(
    name = bench_bls;
    config = Criterion::default();
    targets = keypair_benchmark, sign_benchmark, verify_benchmark, verify_aggregate_no_rk_benchmark, verify_aggregate_rk_benchmark, verify_multisig
);

criterion_main!(bench_bls);
