extern crate rand;

pub mod hash_db;
pub mod vector_poly;

use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;

pub fn get_generators(prefix: &str, n: usize) -> Vec<G1> {
    let mut gens: Vec<G1> = Vec::with_capacity(n);
    for i in 1..n + 1 {
        let s: String = prefix.to_string() + &i.to_string();
        gens.push(G1::from_msg_hash(s.as_bytes()));
    }
    gens
}

pub fn gen_challenges(input: &[&G1], state: &mut Vec<u8>, n: usize) -> Vec<FieldElement> {
    let mut r = Vec::<FieldElement>::with_capacity(n);
    for i in 0..input.len() {
        state.extend_from_slice(&input[i].to_bytes());
    }
    r.push(FieldElement::from_msg_hash(&state));

    let gen = G1::generator();
    for _ in 1..n {
        let _p = &gen * r.last().unwrap();
        state.extend_from_slice(&_p.to_bytes());
        r.push(FieldElement::from_msg_hash(&state));
    }
    r
}
