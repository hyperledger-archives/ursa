#[macro_use]
extern crate criterion;
extern crate bulletproofs_amcl;

use criterion::Criterion;

use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use bulletproofs_amcl::utils::vector_poly::VecPoly3;

/// Benchmark evaluation of vector polynomial
fn eval_benchmark(c: &mut Criterion) {
    for n in vec![10, 50, 100, 500, 1000] {
        let p1_0 = FieldElementVector::random(n);
        let p1_1 = FieldElementVector::random(n);
        let p1_2 = FieldElementVector::random(n);
        let p1_3 = FieldElementVector::random(n);
        let p1 = VecPoly3(p1_0, p1_1, p1_2, p1_3);
        let x = FieldElement::random();

        c.bench_function(format!("eval for {} elements", n).as_str(), |b| {
            b.iter(|| p1.eval(&x))
        });

        c.bench_function(format!("eval_alt for {} elements", n).as_str(), |b| {
            b.iter(|| p1.eval_alt(&x))
        });
    }
}

criterion_group!(
    name = bench_eval;
    config = Criterion::default();
    targets = eval_benchmark
);

criterion_main!(bench_eval);
