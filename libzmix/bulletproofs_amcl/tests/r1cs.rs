extern crate merlin;
use bulletproofs_amcl as bulletproofs;

use bulletproofs::errors::R1CSError;
use bulletproofs::r1cs::{
    ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier,
};

#[cfg(test)]
mod tests {
    use super::*;
    use amcl_wrapper::field_elem::FieldElement;
    use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
    use amcl_wrapper::group_elem_g1::{G1Vector, G1};
    use bulletproofs::utils::get_generators;
    use merlin::Transcript;

    #[test]
    fn test_2_factors_r1cs() {
        // Prove knowledge of `p` and `q` such that given an `r`, `p * q = r`
        let G: G1Vector = get_generators("G", 8).into();
        let H: G1Vector = get_generators("H", 8).into();
        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        let factors = vec![
            (
                FieldElement::from(17u32),
                FieldElement::from(19u32),
                FieldElement::from(323u32),
            ),
            (
                FieldElement::from(7u32),
                FieldElement::from(5u32),
                FieldElement::from(35u32),
            ),
        ];

        let (proof, commitments) = {
            let mut comms = vec![];
            let mut prover_transcript = Transcript::new(b"Factors");
            let mut prover = Prover::new(&g, &h, &mut prover_transcript);

            for (p, q, r) in &factors {
                let (com_p, var_p) = prover.commit(*p, FieldElement::random());
                let (com_q, var_q) = prover.commit(*q, FieldElement::random());
                let (_, _, o) = prover.multiply(var_p.into(), var_q.into());
                let lc: LinearCombination = vec![(Variable::One(), *r)].iter().collect();
                prover.constrain(o - lc);
                comms.push(com_p);
                comms.push(com_q);
            }

            let proof = prover.prove(&G, &H).unwrap();

            (proof, comms)
        };

        println!("Proving done");

        let mut verifier_transcript = Transcript::new(b"Factors");
        let mut verifier = Verifier::new(&mut verifier_transcript);
        let mut i = 0;
        while i < factors.len() {
            let var_p = verifier.commit(commitments[2 * i]);
            let var_q = verifier.commit(commitments[2 * i + 1]);
            let (_, _, o) = verifier.multiply(var_p.into(), var_q.into());
            let lc: LinearCombination = vec![(Variable::One(), factors[i].2)].iter().collect();
            verifier.constrain(o - lc);

            i += 1;
        }

        assert!(verifier.verify(&proof, &g, &h, &G, &H).is_ok());
    }

    #[test]
    fn test_factor_r1cs() {
        // Prove knowledge of `p` and `q` such that given an `r`, `p * q = r`
        let G: G1Vector = get_generators("G", 8).into();
        let H: G1Vector = get_generators("H", 8).into();
        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        let factors = vec![
            (
                FieldElement::from(2u32),
                FieldElement::from(4u32),
                FieldElement::from(6u32),
                FieldElement::from(48u32),
            ),
            (
                FieldElement::from(7u32),
                FieldElement::from(5u32),
                FieldElement::from(35u32),
                FieldElement::from(1225u32),
            ),
        ];

        let (proof, commitments) = {
            let mut comms = vec![];
            let mut prover_transcript = Transcript::new(b"Factors");
            let mut prover = Prover::new(&g, &h, &mut prover_transcript);

            for (p, q, r, s) in &factors {
                let (com_p, var_p) = prover.commit(*p, FieldElement::random());
                let (com_q, var_q) = prover.commit(*q, FieldElement::random());
                let (com_r, var_r) = prover.commit(*r, FieldElement::random());
                let (_, _, o1) = prover.multiply(var_p.into(), var_q.into());
                let (_, _, o2) = prover.multiply(o1.into(), var_r.into());
                let lc: LinearCombination = vec![(Variable::One(), *s)].iter().collect();
                prover.constrain(o2 - lc);
                comms.push(com_p);
                comms.push(com_q);
                comms.push(com_r);
            }

            let proof = prover.prove(&G, &H).unwrap();

            (proof, comms)
        };

        println!("Proving done");

        let mut verifier_transcript = Transcript::new(b"Factors");
        let mut verifier = Verifier::new(&mut verifier_transcript);
        let mut i = 0;
        while i < factors.len() {
            let var_p = verifier.commit(commitments[3 * i]);
            let var_q = verifier.commit(commitments[3 * i + 1]);
            let var_r = verifier.commit(commitments[3 * i + 2]);
            let (_, _, o1) = verifier.multiply(var_p.into(), var_q.into());
            let (_, _, o2) = verifier.multiply(o1.into(), var_r.into());
            let lc: LinearCombination = vec![(Variable::One(), factors[i].3)].iter().collect();
            verifier.constrain(o2 - lc);

            i += 1;
        }

        assert!(verifier.verify(&proof, &g, &h, &G, &H).is_ok());
    }
}
