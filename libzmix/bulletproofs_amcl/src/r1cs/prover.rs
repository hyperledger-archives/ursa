/*
    SPDX-License-Identifier: Apache-2.0 OR MIT
*/

use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::{G1Vector, G1};

use crate::transcript::TranscriptProtocol;
use merlin::Transcript;

use crate::errors::{R1CSError, R1CSErrorKind};
use crate::ipp::IPP;
use crate::r1cs::constraint_system::ConstraintSystem;
use crate::r1cs::constraint_system::RandomizedConstraintSystem;
use crate::r1cs::linear_combination::LinearCombination;
use crate::r1cs::linear_combination::Variable;
use crate::r1cs::proof::R1CSProof;
use crate::utils::vector_poly::*;
use amcl_wrapper::commitment::{commit_to_field_element, commit_to_field_element_vectors};
use core::iter;
use core::mem;

// The following protocol is taken from Dalek's implementation. The code has inline
// comments but for a detailed documentation, check following links:
// https://doc-internal.dalek.rs/bulletproofs/r1cs/struct.Prover.html
// https://doc-internal.dalek.rs/bulletproofs/notes/r1cs_proof/index.html
// https://doc-internal.dalek.rs/bulletproofs/r1cs/index.html

/// A `ConstraintSystem` implementation for use by the prover.
///
/// The prover commits high-level variables and their blinding factors `(v, v_blinding)`,
/// allocates low-level variables and creates constraints in terms of these
/// high-level variables and low-level variables.
///
/// When all constraints are added, the proving code calls `prove`
/// which consumes the `Prover` instance, samples random challenges
/// that instantiate the randomized constraints, and creates a complete proof.
pub struct Prover<'a, 'b> {
    g: &'b G1,
    h: &'b G1,
    transcript: &'a mut Transcript,
    /// The constraints accumulated so far.
    constraints: Vec<LinearCombination>,
    /// Stores assignments to the "left" of multiplication gates
    a_L: FieldElementVector,
    /// Stores assignments to the "right" of multiplication gates
    a_R: FieldElementVector,
    /// Stores assignments to the "output" of multiplication gates
    a_O: FieldElementVector,
    /// High-level witness data (value openings to V commitments)
    v: FieldElementVector,
    /// High-level witness data (blinding openings to V commitments)
    v_blinding: FieldElementVector,

    /// This list holds closures that will be called in the second phase of the protocol,
    /// when non-randomized variables are committed.
    deferred_constraints: Vec<Box<dyn Fn(&mut RandomizingProver<'a, 'b>) -> Result<(), R1CSError>>>,

    /// Index of a pending multiplier that's not fully assigned yet.
    pending_multiplier: Option<usize>,
}

/// Prover in the randomizing phase.
///
/// Note: this type is exported because it is used to specify the associated type
/// in the public impl of a trait `ConstraintSystem`, which boils down to allowing compiler to
/// monomorphize the closures for the proving and verifying code.
/// However, this type cannot be instantiated by the user and therefore can only be used within
/// the callback provided to `specify_randomized_constraints`.
pub struct RandomizingProver<'a, 'b> {
    prover: Prover<'a, 'b>,
}

impl<'a, 'b> Prover<'a, 'b> {
    /// Construct an empty constraint system with specified external
    /// input variables.
    ///
    /// # Inputs
    ///
    /// The `transcript` parameter is a Merlin proof transcript.  The
    /// `Prover` holds onto the `&mut Transcript` until it consumes
    /// itself during `Prover::prove`, releasing its borrow of the
    /// transcript.  This ensures that the transcript cannot be
    /// altered except by the `Prover` before proving is complete.
    ///
    /// # Returns
    ///
    /// Returns a new `Prover` instance.
    pub fn new(g: &'b G1, h: &'b G1, transcript: &'a mut Transcript) -> Self {
        transcript.r1cs_domain_sep();

        Prover {
            g,
            h,
            transcript,
            v: FieldElementVector::new(0),
            v_blinding: FieldElementVector::new(0),
            constraints: Vec::new(),
            a_L: FieldElementVector::new(0),
            a_R: FieldElementVector::new(0),
            a_O: FieldElementVector::new(0),
            deferred_constraints: Vec::new(),
            pending_multiplier: None,
        }
    }

    /// Creates commitment to a high-level variable and adds it to the transcript.
    ///
    /// # Inputs
    ///
    /// The `v` and `v_blinding` parameters are openings to the
    /// commitment to the external variable for the constraint
    /// system.  Passing the opening (the value together with the
    /// blinding factor) makes it possible to reference pre-existing
    /// commitments in the constraint system.  All external variables
    /// must be passed up-front, so that challenges produced by
    /// `ConstraintSystem::challenge_scalar` are bound to the
    /// external variables.
    ///
    /// # Returns
    ///
    /// Returns a pair of a Pedersen commitment (as a GroupElement point),
    /// and a `Variable` corresponding to it, which can be used to form constraints.
    pub fn commit(&mut self, v: FieldElement, v_blinding: FieldElement) -> (G1, Variable) {
        let i = self.v.len();

        // Add the commitment to the transcript.
        let V = commit_to_field_element(&self.g, &self.h, &v, &v_blinding);
        self.v.push(v);
        self.v_blinding.push(v_blinding);
        self.transcript.commit_point(b"V", &V);

        (V, Variable::Committed(i))
    }

    /// Use a challenge, `z`, to flatten the constraints in the
    /// constraint system into vectors used for proving and
    /// verification.
    ///
    /// # Output
    ///
    /// Returns a tuple of
    /// ```text
    /// (wL, wR, wO, wV)
    /// ```
    /// where `w{L,R,O}` is `z.z^Q.W{L,R,O}`.
    fn flattened_constraints(
        &self,
        z: &FieldElement,
    ) -> (
        FieldElementVector,
        FieldElementVector,
        FieldElementVector,
        FieldElementVector,
    ) {
        let n = self.a_L.len();
        let m = self.v.len();

        let mut wL = FieldElementVector::new(n);
        let mut wR = FieldElementVector::new(n);
        let mut wO = FieldElementVector::new(n);
        let mut wV = FieldElementVector::new(m);

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
                        // The prover doesn't need to handle constant terms
                    }
                }
            }
            exp_z = &exp_z * z;
        }

        (wL, wR, wO, wV)
    }

    // This is used only for debugging
    // #[cfg(test)]
    // fn get_weight_matrices(
    //     &self,
    // ) -> (
    //     Vec<FieldElementVector>,
    //     Vec<FieldElementVector>,
    //     Vec<FieldElementVector>,
    //     Vec<FieldElementVector>,
    // ) {
    //     let n = self.a_L.len();
    //     let m = self.v.len();
    //     let q = self.constraints.len();
    //     let mut WL = vec![FieldElementVector::new(n); q];
    //     let mut WR = vec![FieldElementVector::new(n); q];
    //     let mut WO = vec![FieldElementVector::new(n); q];
    //     let mut WV = vec![FieldElementVector::new(m); q];
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
    //                     // The prover doesn't need to handle constant terms
    //                 }
    //             }
    //         }
    //     }
    //
    //     (WL, WR, WO, WV)
    // }

    // This is used only for debugging
    // #[cfg(test)]
    // fn flattened_constraints_elaborated(
    //     &self,
    //     z: &FieldElement,
    // ) -> (
    //     FieldElementVector,
    //     FieldElementVector,
    //     FieldElementVector,
    //     FieldElementVector,
    // ) {
    //     use amcl_wrapper::field_elem::multiply_row_vector_with_matrix;
    //
    //     let (WL, WR, WO, WV) = self.get_weight_matrices();
    //
    //     /*println!("Left Weight matrix");
    //     util::print_2d_matrix(&WL);
    //     println!("Right Weight matrix");
    //     util::print_2d_matrix(&WR);
    //     println!("Out Weight matrix");
    //     util::print_2d_matrix(&WO);
    //     println!("Comm Weight matrix");
    //     util::print_2d_matrix(&WV);*/
    //
    //     let q = self.constraints.len();
    //     let z_exp: FieldElementVector = FieldElementVector::new_vandermonde_vector(z, q + 1)
    //         .into_iter()
    //         .skip(1)
    //         .collect::<Vec<_>>()
    //         .into();
    //
    //     let minus_z_exp: FieldElementVector = z_exp
    //         .iter()
    //         .map(|e| (*e).negation())
    //         .collect::<Vec<_>>()
    //         .into();
    //     let wL = multiply_row_vector_with_matrix(&z_exp, &WL).unwrap();
    //     let wR = multiply_row_vector_with_matrix(&z_exp, &WR).unwrap();
    //     let wO = multiply_row_vector_with_matrix(&z_exp, &WO).unwrap();
    //     let wV = multiply_row_vector_with_matrix(&minus_z_exp, &WV).unwrap();
    //
    //     /*println!("Flattened weights");
    //     util::print_vector(&wL);
    //     util::print_vector(&wR);
    //     util::print_vector(&wO);
    //     util::print_vector(&wV);*/
    //
    //     (wL, wR, wO, wV)
    // }

    fn eval(&self, lc: &LinearCombination) -> FieldElement {
        lc.terms
            .iter()
            .fold(FieldElement::zero(), |sum, (var, coeff)| {
                let val = match var {
                    Variable::MultiplierLeft(i) => self.a_L[*i].clone(),
                    Variable::MultiplierRight(i) => self.a_R[*i].clone(),
                    Variable::MultiplierOutput(i) => self.a_O[*i].clone(),
                    Variable::Committed(i) => self.v[*i].clone(),
                    Variable::One() => FieldElement::one(),
                };
                sum + coeff * val
            })
    }

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
            let mut wrapped_self = RandomizingProver { prover: self };
            for callback in callbacks.drain(..) {
                callback(&mut wrapped_self)?;
            }
            Ok(wrapped_self.prover)
        }
    }

    /// Consume this `ConstraintSystem` to produce a proof.
    pub fn prove(mut self, G: &G1Vector, H: &G1Vector) -> Result<R1CSProof, R1CSError> {
        // Commit a length _suffix_ for the number of high-level variables.
        // We cannot do this in advance because user can commit variables one-by-one,
        // but this suffix provides safe disambiguation because each variable
        // is prefixed with a separate label.
        self.transcript.append_u64(b"m", self.v.len() as u64);

        // Commit to the first-phase low-level witness variables.
        let n1 = self.a_L.len();

        if G.len() < n1 {
            return Err(R1CSErrorKind::InvalidGeneratorsLength {
                length: G.len(),
                expected: n1,
            }
            .into());
        }

        let i_blinding1 = FieldElement::random();
        let o_blinding1 = FieldElement::random();
        let s_blinding1 = FieldElement::random();

        // Blinding for L and R for 1st phase
        let s_L1 = FieldElementVector::random(n1);
        let s_R1 = FieldElementVector::random(n1);

        let G_n1: G1Vector = G.as_slice()[0..n1].into();
        let H_n1: G1Vector = H.as_slice()[0..n1].into();

        // A_I = <a_L, G> + <a_R, H> + i_blinding * B_blinding
        let A_I1 = commit_to_field_element_vectors(
            &G_n1,
            &H_n1,
            &self.h,
            &self.a_L,
            &self.a_R,
            &i_blinding1,
        )
        .unwrap();

        // A_O = <a_O, G> + o_blinding * B_blinding
        let A_O1 =
            G_n1.inner_product_const_time(self.a_O.as_slice()).unwrap() + self.h * &o_blinding1;

        // S = <s_L, G> + <s_R, H> + s_blinding * B_blinding
        let S1 = commit_to_field_element_vectors(&G_n1, &H_n1, &self.h, &s_L1, &s_R1, &s_blinding1)
            .unwrap();

        self.transcript.commit_point(b"A_I1", &A_I1);
        self.transcript.commit_point(b"A_O1", &A_O1);
        self.transcript.commit_point(b"S1", &S1);

        // Process the remaining constraints.
        self = self.create_randomized_constraints()?;

        // Pad zeros to the next power of two (or do that implicitly when creating vectors)

        // If the number of multiplications is not 0 or a power of 2, then pad the circuit.
        let n = self.a_L.len();
        let n2 = n - n1;
        let padded_n = n.next_power_of_two();
        let pad = padded_n - n;

        if G.len() < padded_n {
            return Err(R1CSErrorKind::InvalidGeneratorsLength {
                length: G.len(),
                expected: padded_n,
            }
            .into());
        }

        // Commit to the second-phase low-level witness variables

        let has_2nd_phase_commitments = n2 > 0;

        let (i_blinding2, o_blinding2, s_blinding2) = if has_2nd_phase_commitments {
            (
                FieldElement::random(),
                FieldElement::random(),
                FieldElement::random(),
            )
        } else {
            (
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::zero(),
            )
        };

        // Blindings for L and R for 2nd phase
        let s_L2 = FieldElementVector::random(n2);
        let s_R2 = FieldElementVector::random(n2);

        let (A_I2, A_O2, S2) = if has_2nd_phase_commitments {
            let G_n2: G1Vector = G.as_slice()[n1..n].into();
            let H_n2: G1Vector = H.as_slice()[n1..n].into();
            let a_L_n2: FieldElementVector = self.a_L.as_slice()[n1..].into();
            let a_R_n2: FieldElementVector = self.a_R.as_slice()[n1..].into();
            let a_O_n2: FieldElementVector = self.a_O.as_slice()[n1..].into();

            (
                // A_I = <a_L, G> + <a_R, H> + i_blinding * B_blinding
                commit_to_field_element_vectors(
                    &G_n2,
                    &H_n2,
                    self.h,
                    &a_L_n2,
                    &a_R_n2,
                    &i_blinding2,
                )
                .unwrap(),
                // A_O = <a_O, G> + o_blinding * B_blinding
                G_n2.inner_product_const_time(a_O_n2.as_slice()).unwrap() + self.h * &o_blinding2,
                // S = <s_L, G> + <s_R, H> + s_blinding * B_blinding
                commit_to_field_element_vectors(&G_n2, &H_n2, self.h, &s_L2, &s_R2, &s_blinding2)
                    .unwrap(),
            )
        } else {
            (G1::identity(), G1::identity(), G1::identity())
        };

        self.transcript.commit_point(b"A_I2", &A_I2);
        self.transcript.commit_point(b"A_O2", &A_O2);
        self.transcript.commit_point(b"S2", &S2);

        // 4. Compute blinded vector polynomials l(x) and r(x)

        let y = self.transcript.challenge_scalar(b"y");
        let z = self.transcript.challenge_scalar(b"z");

        let (wL, wR, wO, wV) = self.flattened_constraints(&z);
        /*println!("{:?}", &wL);
        println!("{:?}", &wR);
        println!("{:?}", &wO);
        println!("{:?}", &wV);
        let (WL, WR, WO, WV) = self.get_weight_matrices();
        println!("{:?}", &WL);
        println!("{:?}", &WR);
        println!("{:?}", &WO);
        println!("{:?}", &WV);*/
        /*let (wL_, wR_, wO_, wV_) = self.flattened_constraints_elaborated(&z);

        assert_eq!(wL, wL_);
        assert_eq!(wR, wR_);
        assert_eq!(wO, wO_);
        assert_eq!(wV, wV_);*/

        // l_poly has no constant term
        let mut l_poly = VecPoly3::zero(n);
        // r_poly has no 2nd degree term
        let mut r_poly = VecPoly3::zero(n);

        let mut exp_y = FieldElement::one(); // y^n starting at n=0
        let y_inv = y.inverse();
        let exp_y_inv = FieldElementVector::new_vandermonde_vector(&y_inv, padded_n);

        let sLsR = s_L1
            .iter()
            .chain(s_L2.iter())
            .zip(s_R1.iter().chain(s_R2.iter()));
        for (i, (sl, sr)) in sLsR.enumerate() {
            // l_poly.0 = 0
            // l_poly.1 = a_L + y^-n * (z * z^Q * W_R)
            l_poly.1[i] = &self.a_L[i] + (&exp_y_inv[i] * &wR[i]);
            // l_poly.2 = a_O
            l_poly.2[i] = self.a_O[i].clone();
            // l_poly.3 = s_L
            l_poly.3[i] = sl.clone();
            // r_poly.0 = (z * z^Q * W_O) - y^n
            r_poly.0[i] = &wO[i] - &exp_y;
            // r_poly.1 = y^n * a_R + (z * z^Q * W_L)
            r_poly.1[i] = (&exp_y * &self.a_R[i]) + &wL[i];
            // r_poly.2 = 0
            // r_poly.3 = y^n * s_R
            r_poly.3[i] = &exp_y * sr;

            exp_y = exp_y * &y; // y^i -> y^(i+1)
        }

        let t_poly = VecPoly3::special_inner_product(&l_poly, &r_poly);

        let t_1_blinding = FieldElement::random();
        let t_3_blinding = FieldElement::random();
        let t_4_blinding = FieldElement::random();
        let t_5_blinding = FieldElement::random();
        let t_6_blinding = FieldElement::random();

        let T_1 = commit_to_field_element(&self.g, &self.h, &t_poly.t1, &t_1_blinding);
        let T_3 = commit_to_field_element(&self.g, &self.h, &t_poly.t3, &t_3_blinding);
        let T_4 = commit_to_field_element(&self.g, &self.h, &t_poly.t4, &t_4_blinding);
        let T_5 = commit_to_field_element(&self.g, &self.h, &t_poly.t5, &t_5_blinding);
        let T_6 = commit_to_field_element(&self.g, &self.h, &t_poly.t6, &t_6_blinding);

        self.transcript.commit_point(b"T_1", &T_1);
        self.transcript.commit_point(b"T_3", &T_3);
        self.transcript.commit_point(b"T_4", &T_4);
        self.transcript.commit_point(b"T_5", &T_5);
        self.transcript.commit_point(b"T_6", &T_6);

        let u = self.transcript.challenge_scalar(b"u");
        let x = self.transcript.challenge_scalar(b"x");

        // t_2_blinding = <z*z^Q, W_V * v_blinding>
        // in the t_x_blinding calculations, line 76.
        let t_2_blinding = wV.inner_product(&self.v_blinding).unwrap();

        let t_blinding_poly = Poly6 {
            t1: t_1_blinding,
            t2: t_2_blinding,
            t3: t_3_blinding,
            t4: t_4_blinding,
            t5: t_5_blinding,
            t6: t_6_blinding,
        };

        let t_x = t_poly.eval(&x);
        let t_x_blinding = t_blinding_poly.eval(&x);
        let mut l_vec = l_poly.eval(&x);
        // add 0 padding, i.e. 0,0,...pad number of times
        l_vec.append(&mut FieldElementVector::new(pad));

        let mut r_vec = r_poly.eval(&x);

        // Since r_poly contains terms of y without any multiplicand, i.e. in the constant term
        // For more, check https://doc-internal.dalek.rs/bulletproofs/notes/r1cs_proof/index.html#padding-mathbflx-and-mathbfrx-for-the-inner-product-proof
        for _ in n..padded_n {
            r_vec.push(exp_y.negation());
            exp_y = exp_y * &y; // y^i -> y^(i+1)
        }

        let i_blinding = i_blinding1 + &u * i_blinding2;
        let o_blinding = &o_blinding1 + &u * &o_blinding2;
        let s_blinding = s_blinding1 + &u * s_blinding2;

        let e_blinding = &x * (i_blinding + &x * (o_blinding + &x * s_blinding));

        self.transcript.commit_scalar(b"t_x", &t_x);
        self.transcript
            .commit_scalar(b"t_x_blinding", &t_x_blinding);
        self.transcript.commit_scalar(b"e_blinding", &e_blinding);

        // Get a challenge value to combine statements for the IPP
        let w = self.transcript.challenge_scalar(b"w");
        let Q = self.g * w;

        let G_factors: FieldElementVector = iter::repeat(FieldElement::one())
            .take(n1)
            .chain(iter::repeat(u).take(n2 + pad))
            .collect::<Vec<_>>()
            .into();
        let H_factors: FieldElementVector = exp_y_inv
            .clone()
            .into_iter()
            .zip(G_factors.iter())
            .map(|(y, u_or_1)| y * u_or_1)
            .collect::<Vec<_>>()
            .into();

        let ipp_proof = IPP::create_ipp(
            self.transcript,
            &Q,
            &G_factors,
            &H_factors,
            &G.as_slice()[0..padded_n].into(),
            &H.as_slice()[0..padded_n].into(),
            &l_vec,
            &r_vec,
        );

        Ok(R1CSProof {
            A_I1,
            A_O1,
            S1,
            A_I2,
            A_O2,
            S2,
            T_1,
            T_3,
            T_4,
            T_5,
            T_6,
            t_x,
            t_x_blinding,
            e_blinding,
            ipp_proof,
        })
    }

    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    pub fn num_multipliers(&self) -> usize {
        self.a_O.len()
    }
}

impl<'a, 'b> ConstraintSystem for Prover<'a, 'b> {
    type RandomizedCS = RandomizingProver<'a, 'b>;

    fn multiply(
        &mut self,
        mut left: LinearCombination,
        mut right: LinearCombination,
    ) -> (Variable, Variable, Variable) {
        // Synthesize the assignments for l,r,o
        let l = self.eval(&left);
        let r = self.eval(&right);
        let o = &l * &r;

        let (l_var, r_var, o_var) = self._allocate_vars(l, r, o);

        // Constrain l,r,o:
        left.terms.push((l_var, FieldElement::minus_one()));
        right.terms.push((r_var, FieldElement::minus_one()));
        self.constrain(left);
        self.constrain(right);

        (l_var, r_var, o_var)
    }

    fn allocate(&mut self, assignment: Option<FieldElement>) -> Result<Variable, R1CSError> {
        let scalar = assignment.ok_or(R1CSError::from(R1CSErrorKind::MissingAssignment))?;

        match self.pending_multiplier {
            None => {
                let i = self.a_L.len();
                self.pending_multiplier = Some(i);
                self.a_L.push(scalar);
                self.a_R.push(FieldElement::zero());
                self.a_O.push(FieldElement::zero());
                Ok(Variable::MultiplierLeft(i))
            }
            Some(i) => {
                self.pending_multiplier = None;
                self.a_R[i] = scalar;
                self.a_O[i] = &self.a_L[i] * &self.a_R[i];
                Ok(Variable::MultiplierRight(i))
            }
        }
    }

    fn allocate_multiplier(
        &mut self,
        input_assignments: Option<(FieldElement, FieldElement)>,
    ) -> Result<(Variable, Variable, Variable), R1CSError> {
        let (l, r) = input_assignments.ok_or(R1CSError::from(R1CSErrorKind::MissingAssignment))?;
        let o = &l * &r;

        Ok(self._allocate_vars(l, r, o))
    }

    fn constrain(&mut self, lc: LinearCombination) {
        // TODO: check that the linear combinations are valid
        // (e.g. that variables are valid, that the linear combination evals to 0 for prover, etc).
        self.constraints.push(lc);
    }

    fn specify_randomized_constraints<F>(&mut self, callback: F) -> Result<(), R1CSError>
    where
        F: 'static + Fn(&mut Self::RandomizedCS) -> Result<(), R1CSError>,
    {
        self.deferred_constraints.push(Box::new(callback));
        Ok(())
    }

    fn evaluate_lc(&self, lc: &LinearCombination) -> Option<FieldElement> {
        Some(self.eval(lc))
    }

    fn allocate_single(
        &mut self,
        assignment: Option<FieldElement>,
    ) -> Result<(Variable, Option<Variable>), R1CSError> {
        let var = self.allocate(assignment)?;
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

impl<'a, 'b> Prover<'a, 'b> {
    // Allocate variables for l, r and o and assign values
    fn _allocate_vars(
        &mut self,
        l: FieldElement,
        r: FieldElement,
        o: FieldElement,
    ) -> (Variable, Variable, Variable) {
        // Create variables for l,r,o ...
        let l_var = Variable::MultiplierLeft(self.a_L.len());
        let r_var = Variable::MultiplierRight(self.a_R.len());
        let o_var = Variable::MultiplierOutput(self.a_O.len());
        // ... and assign them
        self.a_L.push(l);
        self.a_R.push(r);
        self.a_O.push(o);

        (l_var, r_var, o_var)
    }
}

impl<'a, 'b> ConstraintSystem for RandomizingProver<'a, 'b> {
    type RandomizedCS = Self;

    fn multiply(
        &mut self,
        left: LinearCombination,
        right: LinearCombination,
    ) -> (Variable, Variable, Variable) {
        self.prover.multiply(left, right)
    }

    fn allocate(&mut self, assignment: Option<FieldElement>) -> Result<Variable, R1CSError> {
        self.prover.allocate(assignment)
    }

    fn allocate_multiplier(
        &mut self,
        input_assignments: Option<(FieldElement, FieldElement)>,
    ) -> Result<(Variable, Variable, Variable), R1CSError> {
        self.prover.allocate_multiplier(input_assignments)
    }

    fn constrain(&mut self, lc: LinearCombination) {
        self.prover.constrain(lc)
    }

    fn specify_randomized_constraints<F>(&mut self, callback: F) -> Result<(), R1CSError>
    where
        F: 'static + Fn(&mut Self::RandomizedCS) -> Result<(), R1CSError>,
    {
        callback(self)
    }

    fn evaluate_lc(&self, lc: &LinearCombination) -> Option<FieldElement> {
        self.prover.evaluate_lc(lc)
    }

    fn allocate_single(
        &mut self,
        assignment: Option<FieldElement>,
    ) -> Result<(Variable, Option<Variable>), R1CSError> {
        self.prover.allocate_single(assignment)
    }
}

impl<'a, 'b> RandomizedConstraintSystem for RandomizingProver<'a, 'b> {
    fn challenge_scalar(&mut self, label: &'static [u8]) -> FieldElement {
        self.prover.transcript.challenge_scalar(label)
    }
}
