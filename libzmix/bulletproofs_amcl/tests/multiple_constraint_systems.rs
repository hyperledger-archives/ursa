#[cfg(test)]
mod tests {
    extern crate merlin;
    use bulletproofs_amcl as bulletproofs;

    use bulletproofs::r1cs::{Prover, Verifier};

    use bulletproofs::r1cs::gadgets::bound_check::{prove_bounded_num, verify_bounded_num};

    use amcl_wrapper::field_elem::FieldElement;
    use amcl_wrapper::group_elem::GroupElement;
    use amcl_wrapper::group_elem_g1::{G1Vector, G1};
    use bulletproofs::utils::get_generators;
    use bulletproofs_amcl::r1cs::gadgets::set_membership::{
        prove_set_membership, verify_set_membership,
    };
    use bulletproofs_amcl::r1cs::gadgets::set_non_membership::{
        prove_set_non_membership, verify_set_non_membership,
    };
    use merlin::Transcript;
    use rand::Rng;

    #[test]
    fn test_3_bound_checks() {
        // Do 3 bound check in one proof
        let mut rng = rand::thread_rng();

        let max_bits_in_val = 32;

        let min_1 = 10;
        let max_1 = 100;
        let v_1 = rng.gen_range(min_1, max_1);

        let min_2 = 1;
        let max_2 = 18;
        let v_2 = rng.gen_range(min_2, max_2);

        let min_3 = 906;
        let max_3 = 1090;
        let v_3 = rng.gen_range(min_3, max_3);

        let big_g: G1Vector = get_generators("G", 512).into();
        let big_h: G1Vector = get_generators("H", 512).into();
        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        let transcript_label = b"MultipleBoundChecks";

        let mut prover_transcript = Transcript::new(transcript_label);
        let mut prover = Prover::new(&g, &h, &mut prover_transcript);

        let comms_1 = prove_bounded_num(
            v_1,
            None,
            min_1,
            max_1,
            max_bits_in_val,
            Some(&mut rng),
            &mut prover,
        )
        .unwrap();

        let comms_2 = prove_bounded_num(
            v_2,
            None,
            min_2,
            max_2,
            max_bits_in_val,
            Some(&mut rng),
            &mut prover,
        )
        .unwrap();

        let comms_3 = prove_bounded_num(
            v_3,
            None,
            min_3,
            max_3,
            max_bits_in_val,
            Some(&mut rng),
            &mut prover,
        )
        .unwrap();

        let proof = prover.prove(&big_g, &big_h).unwrap();

        let mut verifier_transcript = Transcript::new(transcript_label);
        let mut verifier = Verifier::new(&mut verifier_transcript);

        verify_bounded_num(min_1, max_1, max_bits_in_val, comms_1, &mut verifier).unwrap();
        verify_bounded_num(min_2, max_2, max_bits_in_val, comms_2, &mut verifier).unwrap();
        verify_bounded_num(min_3, max_3, max_bits_in_val, comms_3, &mut verifier).unwrap();

        assert!(verifier.verify(&proof, &g, &h, &big_g, &big_h).is_ok())
    }

    #[test]
    fn test_combination_of_bound_check_and_set_membership() {
        // Do a bound check, 1 set membership and 1 set non-membership in one proof
        let mut rng = rand::thread_rng();

        let max_bits_in_val = 32;

        let min = 39;
        let max = 545;
        let v = rng.gen_range(min, max);

        let set = vec![
            FieldElement::from(2),
            FieldElement::from(97),
            FieldElement::from(125),
            FieldElement::from(307),
            FieldElement::from(500),
            FieldElement::from(950),
            FieldElement::from(2099),
        ];

        let present_value = FieldElement::from(125);
        let absent_value = FieldElement::from(10);

        let big_g: G1Vector = get_generators("G", 256).into();
        let big_h: G1Vector = get_generators("H", 256).into();
        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        let transcript_label = b"Combination";

        let mut prover_transcript = Transcript::new(transcript_label);
        let mut prover = Prover::new(&g, &h, &mut prover_transcript);

        let comms_1 = prove_bounded_num(
            v,
            None,
            min,
            max,
            max_bits_in_val,
            Some(&mut rng),
            &mut prover,
        )
        .unwrap();

        let comms_2 = prove_set_membership(
            present_value,
            None,
            set.as_slice(),
            Some(&mut rng),
            &mut prover,
        )
        .unwrap();

        let comms_3 = prove_set_non_membership(
            absent_value,
            None,
            set.as_slice(),
            Some(&mut rng),
            &mut prover,
        )
        .unwrap();

        let proof = prover.prove(&big_g, &big_h).unwrap();

        let mut verifier_transcript = Transcript::new(transcript_label);
        let mut verifier = Verifier::new(&mut verifier_transcript);

        verify_bounded_num(min, max, max_bits_in_val, comms_1, &mut verifier).unwrap();

        verify_set_membership(set.as_slice(), comms_2, &mut verifier).unwrap();

        verify_set_non_membership(set.as_slice(), comms_3, &mut verifier).unwrap();

        assert!(verifier.verify(&proof, &g, &h, &big_g, &big_h).is_ok())
    }
}
