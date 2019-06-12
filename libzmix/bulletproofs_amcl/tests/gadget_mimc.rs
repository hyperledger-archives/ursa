//extern crate cpuprofiler;
//extern crate flame;
extern crate merlin;
extern crate rand;

use amcl_wrapper::field_elem::FieldElement;
use bulletproofs::errors::R1CSError;
use bulletproofs::r1cs::{
    ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier,
};
use bulletproofs_amcl as bulletproofs;

use bulletproofs::r1cs::linear_combination::AllocatedQuantity;
use merlin::Transcript;

mod utils;
use utils::mimc::{enforce_mimc_2_inputs, mimc, mimc_gadget, MIMC_ROUNDS};

#[cfg(test)]
mod tests {
    use super::*;
    // For benchmarking
    use std::time::{Duration, Instant};
    //use rand_chacha::ChaChaRng;
    use amcl_wrapper::field_elem::FieldElement;
    use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
    use amcl_wrapper::group_elem_g1::{G1Vector, G1};
    use bulletproofs::utils::get_generators;
    //    use cpuprofiler::PROFILER;
    use std::fs::File;

    #[test]
    fn test_mimc() {
        // Generate the MiMC round constants
        let constants = (0..MIMC_ROUNDS)
            .map(|_| FieldElement::random())
            .collect::<Vec<_>>();
        //let constants = (0..MIMC_ROUNDS).map(|i| FieldElement::one()).collect::<Vec<_>>();

        let G: G1Vector = get_generators("G", 128).into();
        let H: G1Vector = get_generators("H", 128).into();
        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        const SAMPLES: u32 = 1;
        let mut total_proving = Duration::new(0, 0);
        let mut total_verifying = Duration::new(0, 0);

        for _ in 0..SAMPLES {
            // Generate a random preimage and compute the image
            let xl = FieldElement::random();
            let xr = FieldElement::random();
            let image = mimc(&xl, &xr, &constants);

            let (proof, commitments) = {
                let mut prover_transcript = Transcript::new(b"MiMC");
                let mut prover = Prover::new(&g, &h, &mut prover_transcript);

                let (com_l, var_l) = prover.commit(xl, FieldElement::random());
                let (com_r, var_r) = prover.commit(xr, FieldElement::random());

                let left_alloc_scalar = AllocatedQuantity {
                    variable: var_l,
                    assignment: Some(xl),
                };

                let right_alloc_scalar = AllocatedQuantity {
                    variable: var_r,
                    assignment: Some(xr),
                };

                //flame::start("proving");
                //PROFILER.lock().unwrap().start("./proving.profile").unwrap();
                let start = Instant::now();
                assert!(mimc_gadget(
                    &mut prover,
                    left_alloc_scalar,
                    right_alloc_scalar,
                    MIMC_ROUNDS,
                    &constants,
                    &image
                )
                .is_ok());

                //println!("For MiMC rounds {}, no of constraints is {}", &MIMC_ROUNDS, &prover.num_constraints());
                let proof = prover.prove(&G, &H).unwrap();
                total_proving += start.elapsed();
                //flame::end("proving");
                //PROFILER.lock().unwrap().stop().unwrap();

                (proof, (com_l, com_r))
            };

            let mut verifier_transcript = Transcript::new(b"MiMC");
            let mut verifier = Verifier::new(&mut verifier_transcript);
            let var_l = verifier.commit(commitments.0);
            let var_r = verifier.commit(commitments.1);

            let left_alloc_scalar = AllocatedQuantity {
                variable: var_l,
                assignment: None,
            };

            let right_alloc_scalar = AllocatedQuantity {
                variable: var_r,
                assignment: None,
            };

            //flame::start("verifying");
            /*PROFILER
            .lock()
            .unwrap()
            .start("./verifying.profile")
            .unwrap();*/
            let start = Instant::now();
            assert!(mimc_gadget(
                &mut verifier,
                left_alloc_scalar,
                right_alloc_scalar,
                MIMC_ROUNDS,
                &constants,
                &image
            )
            .is_ok());

            assert!(verifier.verify(&proof, &g, &h, &G, &H).is_ok());
            total_verifying += start.elapsed();
            //flame::end("verifying");
            //PROFILER.lock().unwrap().stop().unwrap();
        }

        println!(
            "Total proving time for {} samples: {:?} seconds",
            SAMPLES, total_proving
        );
        println!(
            "Total verifying time for {} samples: {:?} seconds",
            SAMPLES, total_verifying
        );
        //flame::dump_html(&mut File::create("flame-graph.html").unwrap()).unwrap();
    }

}
