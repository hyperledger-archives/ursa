use ff::{Field, PrimeField, PrimeFieldRepr, SqrtField};
use pairing::bls12_381::*;
use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;

#[bench]
fn bench_fq_repr_add_nocarry(b: &mut ::test::Bencher) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let v: Vec<(FqRepr, FqRepr)> = (0..SAMPLES)
        .map(|_| {
            let mut tmp1 = Fq::random(&mut rng).into_repr();
            let mut tmp2 = Fq::random(&mut rng).into_repr();
            // Shave a few bits off to avoid overflow.
            for _ in 0..3 {
                tmp1.div2();
                tmp2.div2();
            }
            (tmp1, tmp2)
        })
        .collect();

    let mut count = 0;
    b.iter(|| {
        let mut tmp = v[count].0;
        tmp.add_nocarry(&v[count].1);
        count = (count + 1) % SAMPLES;
        tmp
    });
}

#[bench]
fn bench_fq_repr_sub_noborrow(b: &mut ::test::Bencher) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let v: Vec<(FqRepr, FqRepr)> = (0..SAMPLES)
        .map(|_| {
            let tmp1 = Fq::random(&mut rng).into_repr();
            let mut tmp2 = tmp1;
            // Ensure tmp2 is smaller than tmp1.
            for _ in 0..10 {
                tmp2.div2();
            }
            (tmp1, tmp2)
        })
        .collect();

    let mut count = 0;
    b.iter(|| {
        let mut tmp = v[count].0;
        tmp.sub_noborrow(&v[count].1);
        count = (count + 1) % SAMPLES;
        tmp
    });
}

#[bench]
fn bench_fq_repr_num_bits(b: &mut ::test::Bencher) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let v: Vec<FqRepr> = (0..SAMPLES)
        .map(|_| Fq::random(&mut rng).into_repr())
        .collect();

    let mut count = 0;
    b.iter(|| {
        let tmp = v[count].num_bits();
        count = (count + 1) % SAMPLES;
        tmp
    });
}

#[bench]
fn bench_fq_repr_mul2(b: &mut ::test::Bencher) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let v: Vec<FqRepr> = (0..SAMPLES)
        .map(|_| Fq::random(&mut rng).into_repr())
        .collect();

    let mut count = 0;
    b.iter(|| {
        let mut tmp = v[count];
        tmp.mul2();
        count = (count + 1) % SAMPLES;
        tmp
    });
}

#[bench]
fn bench_fq_repr_div2(b: &mut ::test::Bencher) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let v: Vec<FqRepr> = (0..SAMPLES)
        .map(|_| Fq::random(&mut rng).into_repr())
        .collect();

    let mut count = 0;
    b.iter(|| {
        let mut tmp = v[count];
        tmp.div2();
        count = (count + 1) % SAMPLES;
        tmp
    });
}

#[bench]
fn bench_fq_add_assign(b: &mut ::test::Bencher) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let v: Vec<(Fq, Fq)> = (0..SAMPLES)
        .map(|_| (Fq::random(&mut rng), Fq::random(&mut rng)))
        .collect();

    let mut count = 0;
    b.iter(|| {
        let mut tmp = v[count].0;
        tmp.add_assign(&v[count].1);
        count = (count + 1) % SAMPLES;
        tmp
    });
}

#[bench]
fn bench_fq_sub_assign(b: &mut ::test::Bencher) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let v: Vec<(Fq, Fq)> = (0..SAMPLES)
        .map(|_| (Fq::random(&mut rng), Fq::random(&mut rng)))
        .collect();

    let mut count = 0;
    b.iter(|| {
        let mut tmp = v[count].0;
        tmp.sub_assign(&v[count].1);
        count = (count + 1) % SAMPLES;
        tmp
    });
}

#[bench]
fn bench_fq_mul_assign(b: &mut ::test::Bencher) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let v: Vec<(Fq, Fq)> = (0..SAMPLES)
        .map(|_| (Fq::random(&mut rng), Fq::random(&mut rng)))
        .collect();

    let mut count = 0;
    b.iter(|| {
        let mut tmp = v[count].0;
        tmp.mul_assign(&v[count].1);
        count = (count + 1) % SAMPLES;
        tmp
    });
}

#[bench]
fn bench_fq_square(b: &mut ::test::Bencher) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let v: Vec<Fq> = (0..SAMPLES).map(|_| Fq::random(&mut rng)).collect();

    let mut count = 0;
    b.iter(|| {
        let mut tmp = v[count];
        tmp.square();
        count = (count + 1) % SAMPLES;
        tmp
    });
}

#[bench]
fn bench_fq_inverse(b: &mut ::test::Bencher) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let v: Vec<Fq> = (0..SAMPLES).map(|_| Fq::random(&mut rng)).collect();

    let mut count = 0;
    b.iter(|| {
        count = (count + 1) % SAMPLES;
        v[count].inverse()
    });
}

#[bench]
fn bench_fq_negate(b: &mut ::test::Bencher) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let v: Vec<Fq> = (0..SAMPLES).map(|_| Fq::random(&mut rng)).collect();

    let mut count = 0;
    b.iter(|| {
        let mut tmp = v[count];
        tmp.negate();
        count = (count + 1) % SAMPLES;
        tmp
    });
}

#[bench]
fn bench_fq_sqrt(b: &mut ::test::Bencher) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let v: Vec<Fq> = (0..SAMPLES)
        .map(|_| {
            let mut tmp = Fq::random(&mut rng);
            tmp.square();
            tmp
        })
        .collect();

    let mut count = 0;
    b.iter(|| {
        count = (count + 1) % SAMPLES;
        v[count].sqrt()
    });
}

#[bench]
fn bench_fq_into_repr(b: &mut ::test::Bencher) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let v: Vec<Fq> = (0..SAMPLES).map(|_| Fq::random(&mut rng)).collect();

    let mut count = 0;
    b.iter(|| {
        count = (count + 1) % SAMPLES;
        v[count].into_repr()
    });
}

#[bench]
fn bench_fq_from_repr(b: &mut ::test::Bencher) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let v: Vec<FqRepr> = (0..SAMPLES)
        .map(|_| Fq::random(&mut rng).into_repr())
        .collect();

    let mut count = 0;
    b.iter(|| {
        count = (count + 1) % SAMPLES;
        Fq::from_repr(v[count])
    });
}
