/*
    SPDX-License-Identifier: Apache-2.0 OR MIT
*/

use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::{G1Vector, G1};

use crate::transcript::TranscriptProtocol;
use core::mem;
use merlin::Transcript;

use crate::errors::{R1CSError, R1CSErrorKind};
use crate::ipp::IPP;
use crate::r1cs::constraint_system::ConstraintSystem;
use crate::r1cs::constraint_system::RandomizedConstraintSystem;
use crate::r1cs::linear_combination::LinearCombination;
use crate::r1cs::linear_combination::Variable;
use crate::r1cs::proof::R1CSProof;

// The following protocol is taken from Dalek's implementation. The code has inline
// comments but for a detailed documentation, check following links:
// https://doc-internal.dalek.rs/bulletproofs/r1cs/struct.Verifier.html
// https://doc-internal.dalek.rs/bulletproofs/notes/r1cs_proof/index.html
// https://doc-internal.dalek.rs/bulletproofs/r1cs/index.html

/// A [`ConstraintSystem`] implementation for use by the verifier.
///
/// The verifier adds high-level variable commitments to the transcript,
/// allocates low-level variables and creates constraints in terms of these
/// high-level variables and low-level variables.
///
/// When all constraints are added, the verifying code calls `verify`
/// which consumes the `Verifier` instance, samples random challenges
/// that instantiate the randomized constraints, and verifies the proof.
pub struct Verifier<'a> {
    transcript: &'a mut Transcript,
    constraints: Vec<LinearCombination>,

    /// Records the number of low-level variables allocated in the
    /// constraint system.
    ///
    /// Because the `Verifier` only keeps the constraints
    /// themselves, it doesn't record the assignments (they're all
    /// `Missing`), so the `num_vars` isn't kept implicitly in the
    /// variable assignments.
    num_vars: usize,
    V: Vec<G1>,

    /// This list holds closures that will be called in the second phase of the protocol,
    /// when non-randomized variables are committed.
    /// After that, the option will flip to None and additional calls to `randomize_constraints`
    /// will invoke closures immediately.
    deferred_constraints: Vec<Box<dyn Fn(&mut RandomizingVerifier<'a>) -> Result<(), R1CSError>>>,

    /// Index of a pending multiplier that's not fully assigned yet.
    pending_multiplier: Option<usize>,
}

/// Verifier in the randomizing phase.
///
/// Note: this type is exported because it is used to specify the associated type
/// in the public impl of a trait `ConstraintSystem`, which boils down to allowing compiler to
/// monomorphize the closures for the proving and verifying code.
/// However, this type cannot be instantiated by the user and therefore can only be used within
/// the callback provided to `specify_randomized_constraints`.
pub struct RandomizingVerifier<'a> {
    verifier: Verifier<'a>,
}

impl<'a> Verifier<'a> {
    /// Construct an empty constraint system with specified external
    /// input variables.
    ///
    /// # Inputs
    ///
    /// The `bp_gens` and `pc_gens` are generators for Bulletproofs
    /// and for the Pedersen commitments, respectively.  The
    /// `BulletproofGens` should have `gens_capacity` greater than
    /// the number of multiplication constraints that will eventually
    /// be added into the constraint system.
    ///
    /// The `transcript` parameter is a Merlin proof transcript.  The
    /// `Verifier` holds onto the `&mut Transcript` until it consumes
    /// itself during `Verifier::verify`, releasing its borrow of the
    /// transcript.  This ensures that the transcript cannot be
    /// altered except by the `Verifier` before proving is complete.
    ///
    /// The `commitments` parameter is a list of Pedersen commitments
    /// to the external variables for the constraint system.  All
    /// external variables must be passed up-front, so that challenges
    /// produced by `ConstraintSystem::challenge_scalar` are bound
    /// to the external variables.
    ///
    /// # Returns
    ///
    /// Returns a tuple `(cs, vars)`.
    ///
    /// The first element is the newly constructed constraint system.
    ///
    /// The second element is a list of `Variable` corresponding to
    /// the external inputs, which can be used to form constraints.
    pub fn new(transcript: &'a mut Transcript) -> Self {
        transcript.r1cs_domain_sep();

        Verifier {
            transcript,
            num_vars: 0,
            V: Vec::new(),
            constraints: Vec::new(),
            deferred_constraints: Vec::new(),
            pending_multiplier: None,
        }
    }

    /// Creates commitment to a high-level variable and adds it to the transcript.
    ///
    /// # Inputs
    ///
    /// The `commitment` parameter is a Pedersen commitment
    /// to the external variable for the constraint system.  All
    /// external variables must be passed up-front, so that challenges
    /// produced by `ConstraintSystem::challenge_scalar` are bound
    /// to the external variables.
    ///
    /// # Returns
    ///
    /// Returns a pair of a Pedersen commitment and a `Variable`,
    /// corresponding to it, which can be used to form constraints.
    pub fn commit(&mut self, commitment: G1) -> Variable {
        let i = self.V.len();

        // Add the commitment to the transcript.
        self.transcript.commit_point(b"V", &commitment);
        self.V.push(commitment);

        Variable::Committed(i)
    }

    /// Use a challenge, `z`, to flatten the constraints in the
    /// constraint system into vectors used for proving and
    /// verification.
    ///
    /// # Output
    ///
    /// Returns a tuple of
    /// ```text
    /// (wL, wR, wO, wV, wc)
    /// ```
    /// where `w{L,R,O}` is `z.z^Q.W{L,R,O}`
    ///
    /// This has the same logic as `Prover::flattened_constraints()`
    /// but also computes the constant terms (which the prover skips
    /// because they're not needed to construct the proof).
    fn flattened_constraints(
        &self,
        z: &FieldElement,
    ) -> (
        FieldElementVector,
        FieldElementVector,
        FieldElementVector,
        FieldElementVector,
        FieldElement,
    ) {
        let n = self.num_vars;
        let m = self.V.len();

        let mut wL = FieldElementVector::new(n);
        let mut wR = FieldElementVector::new(n);
        let mut wO = FieldElementVector::new(n);
        let mut wV = FieldElementVector::new(m);
        let mut wc = FieldElement::zero();

        let mut exp_z = z.clone();
        for lc in self.constraints.iter() {
            for (var, coeff) in &lc.terms {
                match var {
                    Variable::MultiplierLeft(i) => {
                        wL[*i] += &exp_z * coeff;
                    }
                    Variable::MultiplierRight(i) => {
                        wR[*i] += &exp_z * coeff;
                    }
                    Variable::MultiplierOutput(i) => {
                        wO[*i] += &exp_z * coeff;
                    }
                    Variable::Committed(i) => {
                        wV[*i] -= &exp_z * coeff;
                    }
                    Variable::One() => {
                        wc -= &exp_z * coeff;
                    }
                }
            }
            exp_z = &exp_z * z;
        }

        (wL, wR, wO, wV, wc)
    }

    // Only used for debugging purposes
    // #[cfg(test)]
    // fn get_weight_matrices(
    //     &self,
    // ) -> (
    //     Vec<FieldElementVector>,
    //     Vec<FieldElementVector>,
    //     Vec<FieldElementVector>,
    //     Vec<FieldElementVector>,
    //     FieldElement,
    // ) {
    //     let n = self.num_vars;
    //     let m = self.V.len();
    //     let q = self.constraints.len();
    //     let mut WL = vec![FieldElementVector::new(n); q];
    //     let mut WR = vec![FieldElementVector::new(n); q];
    //     let mut WO = vec![FieldElementVector::new(n); q];
    //     let mut WV = vec![FieldElementVector::new(m); q];
    //     let mut wc = FieldElement::zero();
    //
    //     for (r, lc) in self.constraints.iter().enumerate() {
    //         for (var, coeff) in &lc.terms {
    //             match var {
    //                 Variable::MultiplierLeft(i) => {
    //                     let (i, coeff) = (*i, coeff.clone());
    //                     WL[r][i] = coeff;
    //                 }
    //                 Variable::MultiplierRight(i) => {
    //                     let (i, coeff) = (*i, coeff.clone());
    //                     WR[r][i] = coeff;
    //                 }
    //                 Variable::MultiplierOutput(i) => {
    //                     let (i, coeff) = (*i, coeff.clone());
    //                     WO[r][i] = coeff;
    //                 }
    //                 Variable::Committed(i) => {
    //                     let (i, coeff) = (*i, coeff.clone());
    //                     WV[r][i] = coeff;
    //                 }
    //                 Variable::One() => {
    //                     wc -= coeff;
    //                 }
    //             }
    //         }
    //     }
    //
    //     (WL, WR, WO, WV, wc)
    // }

    /// Calls all remembered callbacks with an API that
    /// allows generating challenge scalars.
    fn create_randomized_constraints(mut self) -> Result<Self, R1CSError> {
        // Clear the pending multiplier (if any) because it was committed into A_L/A_R/S.
        self.pending_multiplier = None;

        if self.deferred_constraints.len() == 0 {
            self.transcript.r1cs_1phase_domain_sep();
            Ok(self)
        } else {
            self.transcript.r1cs_2phase_domain_sep();
            // Note: the wrapper could've used &mut instead of ownership,
            // but specifying lifetimes for boxed closures is not going to be nice,
            // so we move the self into wrapper and then move it back out afterwards.
            let mut callbacks = mem::replace(&mut self.deferred_constraints, Vec::new());
            let mut wrapped_self = RandomizingVerifier { verifier: self };
            for callback in callbacks.drain(..) {
                callback(&mut wrapped_self)?;
            }
            Ok(wrapped_self.verifier)
        }
    }

    /// Consume this `Verifier` and attempt to verify the supplied `proof`.
    pub fn verify(
        mut self,
        proof: &R1CSProof,
        g: &G1,
        h: &G1,
        G: &G1Vector,
        H: &G1Vector,
    ) -> Result<(), R1CSError> {
        // Commit a length _suffix_ for the number of high-level variables.
        // We cannot do this in advance because user can commit variables one-by-one,
        // but this suffix provides safe disambiguation because each variable
        // is prefixed with a separate label.
        self.transcript.append_u64(b"m", self.V.len() as u64);

        let n1 = self.num_vars;
        self.transcript.commit_point(b"A_I1", &proof.A_I1);
        self.transcript.commit_point(b"A_O1", &proof.A_O1);
        self.transcript.commit_point(b"S1", &proof.S1);

        // Process the remaining constraints.
        self = self.create_randomized_constraints()?;

        // If the number of multiplications is not 0 or a power of 2, then pad the circuit.
        let n = self.num_vars;
        let n2 = n - n1;
        let padded_n = self.num_vars.next_power_of_two();
        let pad = padded_n - n;

        use std::iter;

        if G.len() < padded_n {
            return Err(R1CSErrorKind::InvalidGeneratorsLength {
                length: G.len(),
                expected: padded_n,
            }
            .into());
        }

        self.transcript.commit_point(b"A_I2", &proof.A_I2);
        self.transcript.commit_point(b"A_O2", &proof.A_O2);
        self.transcript.commit_point(b"S2", &proof.S2);

        let y = self.transcript.challenge_scalar(b"y");
        let z = self.transcript.challenge_scalar(b"z");

        self.transcript.commit_point(b"T_1", &proof.T_1);
        self.transcript.commit_point(b"T_3", &proof.T_3);
        self.transcript.commit_point(b"T_4", &proof.T_4);
        self.transcript.commit_point(b"T_5", &proof.T_5);
        self.transcript.commit_point(b"T_6", &proof.T_6);

        let u = self.transcript.challenge_scalar(b"u");
        let x = self.transcript.challenge_scalar(b"x");

        self.transcript.commit_scalar(b"t_x", &proof.t_x);
        self.transcript
            .commit_scalar(b"t_x_blinding", &proof.t_x_blinding);
        self.transcript
            .commit_scalar(b"e_blinding", &proof.e_blinding);

        let w = self.transcript.challenge_scalar(b"w");

        let (wL, wR, wO, wV, wc) = self.flattened_constraints(&z);
        /*println!("{:?}", &wL);
        println!("{:?}", &wR);
        println!("{:?}", &wO);
        println!("{:?}", &wV);
        println!("{:?}", &wc);
        let (WL, WR, WO, WV, wc_) = self.get_weight_matrices();
        println!("{:?}", &WL);
        println!("{:?}", &WR);
        println!("{:?}", &WO);
        println!("{:?}", &WV);
        println!("{:?}", &wc_);*/

        let a = &proof.ipp_proof.a;
        let b = &proof.ipp_proof.b;

        let y_inv = y.inverse();
        let y_inv_vec = FieldElementVector::new_vandermonde_vector(&y_inv, padded_n);
        let y_inv_wR = wR
            .into_iter()
            .zip(y_inv_vec.iter())
            .map(|(wRi, exp_y_inv)| wRi * exp_y_inv)
            // add 0 padding, i.e. 0,0,...pad number of times
            .chain(iter::repeat(FieldElement::zero()).take(pad))
            .collect::<Vec<FieldElement>>();

        let delta = FieldElementVector::from(&y_inv_wR.as_slice()[0..n])
            .inner_product(&wL)
            .unwrap();
        // Get IPP variables
        let (u_sq, u_inv_sq, s) = IPP::verification_scalars(
            &proof.ipp_proof.L,
            &proof.ipp_proof.R,
            padded_n,
            self.transcript,
        )
        .map_err(|_| R1CSError::from(R1CSErrorKind::VerificationError))?;

        let u_for_g = iter::repeat(FieldElement::one())
            .take(n1)
            .chain(iter::repeat(u.clone()).take(n2 + pad));
        let u_for_h = u_for_g.clone();

        // define parameters for P check
        let g_scalars: Vec<FieldElement> = y_inv_wR
            .iter()
            .zip(u_for_g)
            .zip(s.iter().take(padded_n))
            .map(|((yneg_wRi, u_or_1), s_i)| u_or_1 * (&x * yneg_wRi - a * s_i))
            .collect();

        let h_scalars: Vec<FieldElement> = y_inv_vec
            .iter()
            .zip(u_for_h)
            .zip(s.iter().rev().take(padded_n))
            .zip(
                wL.into_iter()
                    .chain(iter::repeat(FieldElement::zero()).take(pad)),
            )
            .zip(
                wO.into_iter()
                    .chain(iter::repeat(FieldElement::zero()).take(pad)),
            )
            .map(|((((y_inv_i, u_or_1), s_i_inv), wLi), wOi)| {
                u_or_1 * (y_inv_i * (&x * wLi + wOi - b * s_i_inv) - FieldElement::one())
            })
            .collect();

        let r = FieldElement::random();

        let x_sqr = x.square();
        let x_cube = &x * &x_sqr;
        let r_x_sqr = &r * &x_sqr;

        // group the T_scalars and T_points together
        // T_scalars = [rx, rx^3, rx^4, rx^5, rx^6]
        let rx = &r * &x;
        let rx_cube = &r * &x_cube;
        let mut T_scalars: Vec<&FieldElement> = vec![&rx, &rx_cube];
        let rx_4 = T_scalars[T_scalars.len() - 1] * &x;
        T_scalars.push(&rx_4); // rx^4
        let rx_5 = T_scalars[T_scalars.len() - 1] * &x;
        T_scalars.push(&rx_5); // rx^5
        let rx_6 = T_scalars[T_scalars.len() - 1] * &x;
        T_scalars.push(&rx_6); // rx^6

        let T_points = [&proof.T_1, &proof.T_3, &proof.T_4, &proof.T_5, &proof.T_6];

        let ux = &u * &x;
        let ux_sqr = &u * &x_sqr;
        let ux_cube = &u * &x_cube;
        let mut arg1 = vec![&x, &x_sqr, &x_cube, &ux, &ux_sqr, &ux_cube];
        let _wV_r_x_sqr = wV.scaled_by(&r_x_sqr);
        let mut wV_r_x_sqr: Vec<&FieldElement> = _wV_r_x_sqr.iter().map(|f| f).collect();
        arg1.append(&mut wV_r_x_sqr);
        arg1.append(&mut T_scalars);

        let w = w * (&proof.t_x - a * b) + &r * (&x_sqr * (wc + delta) - &proof.t_x);
        arg1.push(&w);

        let p = (&proof.e_blinding + &r * &proof.t_x_blinding).negation();
        arg1.push(&p);
        arg1.extend(&g_scalars);
        arg1.extend(&h_scalars);
        arg1.extend(&u_sq);
        arg1.extend(&u_inv_sq);

        let mut arg2: Vec<&G1> = vec![
            &proof.A_I1,
            &proof.A_O1,
            &proof.S1,
            &proof.A_I2,
            &proof.A_O2,
            &proof.S2,
        ];

        arg2.extend(&self.V);
        arg2.extend(&T_points);
        arg2.extend(&[g, h]);
        arg2.extend(&G.as_slice()[0..padded_n]);
        arg2.extend(&H.as_slice()[0..padded_n]);
        arg2.extend(proof.ipp_proof.L.as_slice());
        arg2.extend(proof.ipp_proof.R.as_slice());

        let res = G1Vector::inner_product_var_time_with_ref_vecs(arg2, arg1).unwrap();
        if !res.is_identity() {
            return Err(R1CSErrorKind::VerificationError.into());
        }

        Ok(())
    }
}

impl<'a, 'b> ConstraintSystem for Verifier<'a> {
    type RandomizedCS = RandomizingVerifier<'a>;

    fn multiply(
        &mut self,
        mut left: LinearCombination,
        mut right: LinearCombination,
    ) -> (Variable, Variable, Variable) {
        let (l_var, r_var, o_var) = self._allocate_vars();

        // Constrain l,r,o:
        left.terms.push((l_var, FieldElement::minus_one()));
        right.terms.push((r_var, FieldElement::minus_one()));
        self.constrain(left);
        self.constrain(right);

        (l_var, r_var, o_var)
    }

    fn allocate(&mut self, _: Option<FieldElement>) -> Result<Variable, R1CSError> {
        match self.pending_multiplier {
            None => {
                let i = self.num_vars;
                self.num_vars += 1;
                self.pending_multiplier = Some(i);
                Ok(Variable::MultiplierLeft(i))
            }
            Some(i) => {
                self.pending_multiplier = None;
                Ok(Variable::MultiplierRight(i))
            }
        }
    }

    fn allocate_multiplier(
        &mut self,
        _: Option<(FieldElement, FieldElement)>,
    ) -> Result<(Variable, Variable, Variable), R1CSError> {
        Ok(self._allocate_vars())
    }

    fn constrain(&mut self, lc: LinearCombination) {
        // TODO: check that the linear combinations are valid
        // (e.g. that variables are valid, that the linear combination
        // evals to 0 for prover, etc).
        self.constraints.push(lc);
    }

    fn specify_randomized_constraints<F>(&mut self, callback: F) -> Result<(), R1CSError>
    where
        F: 'static + Fn(&mut Self::RandomizedCS) -> Result<(), R1CSError>,
    {
        self.deferred_constraints.push(Box::new(callback));
        Ok(())
    }

    fn evaluate_lc(&self, _: &LinearCombination) -> Option<FieldElement> {
        None
    }

    fn allocate_single(
        &mut self,
        _: Option<FieldElement>,
    ) -> Result<(Variable, Option<Variable>), R1CSError> {
        let var = self.allocate(None)?;
        match var {
            Variable::MultiplierLeft(i) => Ok((Variable::MultiplierLeft(i), None)),
            Variable::MultiplierRight(i) => Ok((
                Variable::MultiplierRight(i),
                Some(Variable::MultiplierOutput(i)),
            )),
            _ => Err(R1CSErrorKind::FormatError.into()),
        }
    }
}

impl<'a> Verifier<'a> {
    // Allocate variables
    fn _allocate_vars(&mut self) -> (Variable, Variable, Variable) {
        let next_var_idx = self.num_vars;
        self.num_vars += 1;

        // Create variables for l,r,o
        let l_var = Variable::MultiplierLeft(next_var_idx);
        let r_var = Variable::MultiplierRight(next_var_idx);
        let o_var = Variable::MultiplierOutput(next_var_idx);

        (l_var, r_var, o_var)
    }
}

impl<'a, 'b> ConstraintSystem for RandomizingVerifier<'a> {
    type RandomizedCS = Self;

    fn multiply(
        &mut self,
        left: LinearCombination,
        right: LinearCombination,
    ) -> (Variable, Variable, Variable) {
        self.verifier.multiply(left, right)
    }

    fn allocate(&mut self, assignment: Option<FieldElement>) -> Result<Variable, R1CSError> {
        self.verifier.allocate(assignment)
    }

    fn allocate_multiplier(
        &mut self,
        input_assignments: Option<(FieldElement, FieldElement)>,
    ) -> Result<(Variable, Variable, Variable), R1CSError> {
        self.verifier.allocate_multiplier(input_assignments)
    }

    fn constrain(&mut self, lc: LinearCombination) {
        self.verifier.constrain(lc)
    }

    fn specify_randomized_constraints<F>(&mut self, callback: F) -> Result<(), R1CSError>
    where
        F: 'static + Fn(&mut Self::RandomizedCS) -> Result<(), R1CSError>,
    {
        callback(self)
    }

    fn evaluate_lc(&self, _: &LinearCombination) -> Option<FieldElement> {
        None
    }

    fn allocate_single(
        &mut self,
        _: Option<FieldElement>,
    ) -> Result<(Variable, Option<Variable>), R1CSError> {
        self.verifier.allocate_single(None)
    }
}

impl<'a, 'b> RandomizedConstraintSystem for RandomizingVerifier<'a> {
    fn challenge_scalar(&mut self, label: &'static [u8]) -> FieldElement {
        self.verifier.transcript.challenge_scalar(label)
    }
}
