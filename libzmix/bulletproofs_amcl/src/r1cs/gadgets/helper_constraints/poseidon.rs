use crate::errors::{BulletproofError, BulletproofErrorKind, R1CSError};
use crate::r1cs::linear_combination::AllocatedQuantity;
use crate::r1cs::{ConstraintSystem, LinearCombination, Variable};
use amcl_wrapper::field_elem::FieldElement;

use super::super::helper_constraints::constrain_lc_with_scalar;
use super::super::helper_constraints::non_zero::is_nonzero_gadget;
use crate::r1cs::gadgets::poseidon_constants::*;

// Poseidon is described here https://eprint.iacr.org/2019/458
// TODO: Give a overview of Poseidon construction relative of the code.
#[derive(Clone, Debug)]
pub struct PoseidonParams {
    pub width: usize,
    // Number of full SBox rounds in beginning
    pub full_rounds_beginning: usize,
    // Number of full SBox rounds in end
    pub full_rounds_end: usize,
    // Number of partial SBox rounds in beginning
    pub partial_rounds: usize,
    pub round_keys: Vec<FieldElement>,
    pub MDS_matrix: Vec<Vec<FieldElement>>,
}

/// Read the defined round keys and MDS matrix for the corresponding curve from file `poseidon_constants.rs`.
/// Reads constants `ROUND_CONSTS_W_<width>` and `MDS_ENTRIES_W_<width>`
impl PoseidonParams {
    pub fn new(
        width: usize,
        full_rounds_beginning: usize,
        full_rounds_end: usize,
        partial_rounds: usize,
    ) -> Result<PoseidonParams, BulletproofError> {
        if width != 3 && width != 5 && width != 9 {
            return Err(BulletproofErrorKind::UnacceptableWidthForPoseidon {
                width,
                acceptable: vec![3, 5, 9],
            }
            .into());
        }
        let total_rounds = full_rounds_beginning + partial_rounds + full_rounds_end;
        let round_keys = Self::get_round_keys(width, total_rounds)?;
        let matrix_2 = Self::get_MDS_matrix(width)?;
        Ok(PoseidonParams {
            width,
            full_rounds_beginning,
            full_rounds_end,
            partial_rounds,
            round_keys,
            MDS_matrix: matrix_2,
        })
    }

    /// Get the round keys for the curve and given width
    fn get_round_keys(
        width: usize,
        total_rounds: usize,
    ) -> Result<Vec<FieldElement>, BulletproofError> {
        let cap = total_rounds * width;
        //(0..cap).map(|_| FieldElement::random()).collect::<Vec<_>>()
        //vec![FieldElement::one(); cap]
        let ROUND_CONSTS = match width {
            3 => ROUND_CONSTS_W_3.to_vec(),
            5 => ROUND_CONSTS_W_5.to_vec(),
            9 => ROUND_CONSTS_W_9.to_vec(),
            _ => {
                return Err(BulletproofErrorKind::UnacceptableWidthForPoseidon {
                    width,
                    acceptable: vec![3, 5, 9],
                }
                .into())
            }
        };
        if ROUND_CONSTS.len() < cap {
            return Err(BulletproofErrorKind::IncorrectRoundConstantsForPoseidon {
                expected: cap,
                found: ROUND_CONSTS.len(),
            }
            .into());
        }
        let mut rc = vec![];
        for i in 0..cap {
            rc.push(Self::get_field_element_from_hex_str(&ROUND_CONSTS[i])?);
        }
        Ok(rc)
    }

    /// Get the MDS matrix for the curve and given width
    fn get_MDS_matrix(width: usize) -> Result<Vec<Vec<FieldElement>>, BulletproofError> {
        //(0..width).map(|_| (0..width).map(|_| FieldElement::random()).collect::<Vec<_>>()).collect::<Vec<Vec<_>>>()
        //vec![vec![FieldElement::one(); width]; width]

        // `MDS_ENTRIES` is the MDS matrix, it needs to be a square matrix with no of rows and
        // columns equal to `width`
        let MDS_ENTRIES = match width {
            3 => MDS_ENTRIES_W_3
                .to_vec()
                .iter()
                .map(|v| v.to_vec())
                .collect::<Vec<Vec<_>>>(),
            5 => MDS_ENTRIES_W_5
                .to_vec()
                .iter()
                .map(|v| v.to_vec())
                .collect::<Vec<Vec<_>>>(),
            9 => MDS_ENTRIES_W_9
                .to_vec()
                .iter()
                .map(|v| v.to_vec())
                .collect::<Vec<Vec<_>>>(),
            _ => {
                return Err(BulletproofErrorKind::UnacceptableWidthForPoseidon {
                    width,
                    acceptable: vec![3, 5, 9],
                }
                .into())
            }
        };
        if MDS_ENTRIES.len() != width {
            return Err(BulletproofErrorKind::IncorrectMSDRowCountForPoseidon {
                found: MDS_ENTRIES.len(),
                expected: width,
            }
            .into());
        }
        let mut mds: Vec<Vec<FieldElement>> = vec![vec![FieldElement::zero(); width]; width];
        for i in 0..width {
            if MDS_ENTRIES[i].len() != width {
                return Err(BulletproofErrorKind::IncorrectMSDColCountForPoseidon {
                    found: MDS_ENTRIES[i].len(),
                    expected: width,
                }
                .into());
            }
            for j in 0..width {
                mds[i][j] = Self::get_field_element_from_hex_str(&MDS_ENTRIES[i][j])?;
            }
        }
        Ok(mds)
    }

    /// Convert a hex string of form "0x4d4..." to a field element
    fn get_field_element_from_hex_str(hex_str: &str) -> Result<FieldElement, BulletproofError> {
        let mut c = hex_str.to_string();
        // Remove "0x" from beginning
        let l = c.len();
        if l < 3 {
            return Err(BulletproofErrorKind::ParseErrorForPoseidonConstant {
                constant: c,
                error_msg: format!("Length of constant is {} which is less than 3", l),
            }
            .into());
        }
        c.replace_range(..2, "");
        FieldElement::from_hex(c).map_err(|_| {
            BulletproofError::from(BulletproofErrorKind::ParseErrorForPoseidonConstant {
                constant: hex_str[2..].to_string(),
                error_msg: String::from("Cannot convert to hex"),
            })
        })
    }
}

#[derive(Copy, Clone, Debug)]
pub enum SboxType {
    Cube,
    Inverse,
    Quint,
}

impl SboxType {
    /// Apply the Sbox on the given element
    fn apply_sbox(&self, elem: &FieldElement) -> FieldElement {
        match self {
            SboxType::Cube => {
                // elem^3. When squaring, don't use `elem * elem` but `elem.square()` since its faster
                let sqr = elem.square();
                sqr * elem
            }
            SboxType::Inverse => elem.inverse(),
            SboxType::Quint => {
                // elem^5
                let sq = elem.square();
                let f = sq.square();
                f * elem
            }
        }
    }

    /// Enforce the constraints of this Sbox
    fn synthesize_sbox<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
        input_var: LinearCombination,
        round_key: FieldElement,
    ) -> Result<Variable, R1CSError> {
        match self {
            SboxType::Cube => Self::synthesize_cube_sbox(cs, input_var, round_key),
            SboxType::Inverse => Self::synthesize_inverse_sbox(cs, input_var, round_key),
            SboxType::Quint => Self::synthesize_quint_sbox(cs, input_var, round_key),
        }
    }

    /// Allocate variables in circuit and enforce constraints when Sbox as cube, i.e. (input_var + round_key)^3
    fn synthesize_cube_sbox<CS: ConstraintSystem>(
        cs: &mut CS,
        input_var: LinearCombination,
        round_key: FieldElement,
    ) -> Result<Variable, R1CSError> {
        let inp_plus_const: LinearCombination = input_var + round_key;
        let (i, _, sqr) = cs.multiply(inp_plus_const.clone(), inp_plus_const);
        let (_, _, cube) = cs.multiply(sqr.into(), i.into());
        Ok(cube)
    }

    /// Allocate variables in circuit and enforce constraints when Sbox as quint, i.e. (input_var + round_key)^5
    fn synthesize_quint_sbox<CS: ConstraintSystem>(
        cs: &mut CS,
        input_var: LinearCombination,
        round_key: FieldElement,
    ) -> Result<Variable, R1CSError> {
        let inp_plus_const: LinearCombination = input_var + round_key;
        let (i, _, sqr) = cs.multiply(inp_plus_const.clone(), inp_plus_const);
        let (_, _, qr) = cs.multiply(sqr.into(), sqr.into());
        let (_, _, qi) = cs.multiply(qr.into(), i.into());
        Ok(qi)
    }

    /// Allocate variables in circuit and enforce constraints when Sbox as inverse, i.e. (input_var + round_key)^-1
    fn synthesize_inverse_sbox<CS: ConstraintSystem>(
        cs: &mut CS,
        input_var: LinearCombination,
        round_key: FieldElement,
    ) -> Result<Variable, R1CSError> {
        let inp_plus_const: LinearCombination = input_var + round_key;

        let val_l = cs.evaluate_lc(&inp_plus_const);
        let val_r = val_l.clone().map(|l| l.inverse());

        let (var_l, _) = cs.allocate_single(val_l)?;
        let (var_r, var_o) = cs.allocate_single(val_r)?;

        // Ensure `inp_plus_const` is not zero
        is_nonzero_gadget(cs, var_l, var_r)?;

        // Constrain product of ``inp_plus_const` and its inverse to be 1.
        constrain_lc_with_scalar::<CS>(cs, var_o.unwrap().into(), &FieldElement::one());

        Ok(var_r)
    }
}

/// Computes the permutation on the given inputs, parameters and Sbox and outputs the result of the permutation
pub fn Poseidon_permutation(
    input: &[FieldElement],
    params: &PoseidonParams,
    sbox: &SboxType,
) -> Vec<FieldElement> {
    let width = params.width;
    assert_eq!(input.len(), width);

    let full_rounds_beginning = params.full_rounds_beginning;
    let partial_rounds = params.partial_rounds;
    let full_rounds_end = params.full_rounds_end;

    // Each round of the permutation will change current_state.
    let mut current_state = input.to_owned();

    // Temporary layer to hold the output of the linear layer
    let mut current_state_temp = vec![FieldElement::zero(); width];

    let mut round_keys_offset = 0;

    /// Apply given number of full rounds.
    // Using closure makes me wrap the mutables, i.e. current_state, current_state_temp, round_keys_offset
    // in `RefCell`s which results in using borrow and borrow_mut at other places in code.
    fn apply_full_rounds(
        num_rounds: usize,
        current_state: &mut Vec<FieldElement>,
        current_state_temp: &mut Vec<FieldElement>,
        round_keys_offset: &mut usize,
        params: &PoseidonParams,
        sbox: &SboxType,
    ) {
        for _ in 0..num_rounds {
            // Sbox layer
            for i in 0..params.width {
                current_state[i] += &params.round_keys[*round_keys_offset];
                current_state[i] = sbox.apply_sbox(&current_state[i]);
                *round_keys_offset += 1;
            }

            // linear layer
            for i in 0..params.width {
                for j in 0..params.width {
                    current_state_temp[i] += &current_state[j] * &params.MDS_matrix[j][i];
                }
            }

            // Output of this round becomes input to next round
            for i in 0..params.width {
                current_state[i] = current_state_temp.remove(0);
                current_state_temp.push(FieldElement::zero());
            }
        }
    }

    // full Sbox rounds
    apply_full_rounds(
        full_rounds_beginning,
        &mut current_state,
        &mut current_state_temp,
        &mut round_keys_offset,
        params,
        sbox,
    );

    // middle partial Sbox rounds
    for _ in full_rounds_beginning..(full_rounds_beginning + partial_rounds) {
        for i in 0..width {
            current_state[i] += &params.round_keys[round_keys_offset];
            round_keys_offset += 1;
        }

        // partial Sbox layer, apply Sbox to only 1 element of the state.
        // Here the last one is chosen but the choice is arbitrary.
        // TODO: This should be written in the paper not just in a diagram.
        current_state[width - 1] = sbox.apply_sbox(&current_state[width - 1]);

        // linear layer
        for i in 0..width {
            for j in 0..width {
                current_state_temp[i] += &current_state[j] * &params.MDS_matrix[j][i];
            }
        }

        // Output of this round becomes input to next round
        for i in 0..width {
            current_state[i] = current_state_temp.remove(0);
            current_state_temp.push(FieldElement::zero());
        }
    }

    // TODO: Remove duplicate code below.
    // last full Sbox rounds
    apply_full_rounds(
        full_rounds_end,
        &mut current_state,
        &mut current_state_temp,
        &mut round_keys_offset,
        params,
        sbox,
    );

    current_state
}

/// Enforces the constraints of the Poseidon permutation with the given constraint system on the
/// given inputs, parameters and Sbox. Output is a vector where each element of it is a linear
/// combination corresponding to an output. The number of outputs is same as number of inputs
pub fn Poseidon_permutation_constraints<'a, CS: ConstraintSystem>(
    cs: &mut CS,
    input: Vec<LinearCombination>,
    params: &'a PoseidonParams,
    sbox_type: &SboxType,
) -> Result<Vec<LinearCombination>, R1CSError> {
    let width = params.width;
    assert_eq!(input.len(), width);

    fn apply_linear_layer(
        sbox_outs: Vec<LinearCombination>,
        next_inputs: &mut Vec<LinearCombination>,
        matrix_2: &Vec<Vec<FieldElement>>,
    ) {
        let width = sbox_outs.len();
        for i in 0..width {
            for j in 0..width {
                next_inputs[i] += &matrix_2[j][i] * sbox_outs[j].clone();
            }
        }
    }

    let mut current_state_vars: Vec<LinearCombination> = input;

    let mut round_keys_offset = 0;

    let full_rounds_beginning = params.full_rounds_beginning;
    let partial_rounds = params.partial_rounds;
    let full_rounds_end = params.full_rounds_end;

    /// Apply full rounds
    fn apply_full_rounds<CS: ConstraintSystem>(
        num_rounds: usize,
        cs: &mut CS,
        input_vars: &mut Vec<LinearCombination>,
        round_keys_offset: &mut usize,
        params: &PoseidonParams,
        sbox_type: &SboxType,
    ) -> Result<(), R1CSError> {
        for _ in 0..num_rounds {
            let mut sbox_outputs: Vec<LinearCombination> =
                vec![LinearCombination::default(); params.width];

            // Substitution (S-box) layer
            for i in 0..params.width {
                let round_key = params.round_keys[*round_keys_offset].clone();
                sbox_outputs[i] = sbox_type
                    .synthesize_sbox(cs, input_vars[i].clone(), round_key)?
                    .into();

                *round_keys_offset += 1;
            }

            let mut next_input_vars: Vec<LinearCombination> =
                vec![LinearCombination::default(); params.width];

            apply_linear_layer(sbox_outputs, &mut next_input_vars, &params.MDS_matrix);

            for i in 0..params.width {
                // replace input_vars with next_input_vars
                input_vars[i] = next_input_vars.remove(0);
            }
        }
        Ok(())
    }

    // ------------ First full rounds begin --------------------

    apply_full_rounds(
        full_rounds_beginning,
        cs,
        &mut current_state_vars,
        &mut round_keys_offset,
        params,
        sbox_type,
    )?;

    // ------------ First full_rounds_beginning rounds end --------------------

    // ------------ Middle rounds begin --------------------

    for _ in full_rounds_beginning..(full_rounds_beginning + partial_rounds) {
        let mut sbox_outputs: Vec<LinearCombination> = vec![LinearCombination::default(); width];

        // Substitution (S-box) layer
        for i in 0..width {
            let round_key = params.round_keys[round_keys_offset].clone();

            // apply Sbox to only 1 element of the state.
            // Here the last one is chosen but the choice is arbitrary.
            if i == width - 1 {
                sbox_outputs[i] = sbox_type
                    .synthesize_sbox(cs, current_state_vars[i].clone(), round_key)?
                    .into();
            } else {
                sbox_outputs[i] = current_state_vars[i].clone() + round_key;
            }

            round_keys_offset += 1;
        }

        // Linear layer

        let mut next_input_vars: Vec<LinearCombination> = vec![LinearCombination::default(); width];

        apply_linear_layer(sbox_outputs, &mut next_input_vars, &params.MDS_matrix);

        for i in 0..width {
            // replace input_vars with simplified next_input_vars
            current_state_vars[i] = next_input_vars.remove(0).simplify();
        }
    }

    // ------------ Middle rounds end --------------------

    // ------------ Last full rounds begin --------------------

    apply_full_rounds(
        full_rounds_end,
        cs,
        &mut current_state_vars,
        &mut round_keys_offset,
        params,
        sbox_type,
    )?;

    // ------------ Last rounds with full SBox end --------------------

    Ok(current_state_vars)
}

/// More specific than `Poseidon_permutation_constraints`. Takes input and expected output and
/// checks that the permutation output matches the expected output.
/// Input are circuit variables (or linear combinations of them) and output is a public element
pub fn Poseidon_permutation_gadget<'a, CS: ConstraintSystem>(
    cs: &mut CS,
    input: Vec<AllocatedQuantity>,
    params: &'a PoseidonParams,
    sbox_type: &SboxType,
    output: &[FieldElement],
) -> Result<(), R1CSError> {
    let width = params.width;
    assert_eq!(output.len(), width);

    let input_vars: Vec<LinearCombination> = input.iter().map(|e| e.variable.into()).collect();
    let permutation_output =
        Poseidon_permutation_constraints::<CS>(cs, input_vars, params, sbox_type)?;

    for i in 0..width {
        constrain_lc_with_scalar::<CS>(cs, permutation_output[i].to_owned(), &output[i]);
    }

    Ok(())
}

// TODO: Say about the 2 types of hash, fixed input vs var input. Explain why capacity constant?
// Hash from the permutation by passing the first input as capacity constant.
// Capacity constants should have the least significant width-1 bits set and rest unset
// Capacity constant for width 3,   000000000...0011
pub const CAP_CONST_W_3: u64 = 3;
// Capacity constant for width 5,   0000000...001111
pub const CAP_CONST_W_5: u64 = 31;
// Capacity constant for width 9,   000...0011111111
pub const CAP_CONST_W_9: u64 = 511;

// Tradeoff: For various `Poseidon_hash_{2/4/8}`, `Poseidon_hash_{2/4/8}_constraints` and `Poseidon_hash_{2/4/8}_gadget`
// functions below, a better way (since they will always take {2/4/8} elements) is to make inputs an
// array of {2/4/8} rather than a vector but then below i have to use `mem::replace` and `mem::uninitialized`
// to move values out of `inputs` which are unsafe.
// The upside of using vectors is that allocations are done only once whereas if i use an array, i
// have to eventually move its elements to a vector before passing to the permutation since permutation
// needs to work on variable length inputs.
// Another alternative is to check crate "arrayvec"

/// Hashes 2 inputs to give a single output
pub fn Poseidon_hash_2(
    mut inputs: Vec<FieldElement>,
    params: &PoseidonParams,
    sbox: &SboxType,
) -> Result<FieldElement, BulletproofError> {
    // Only 2 elements to the permutation are set to the input of this hash function,
    // one is set to the capacity constant.
    // Always keep the 1st element of the permutation as the capacity constant.
    if inputs.len() != 2 {
        return Err(BulletproofErrorKind::IncorrectWidthForPoseidon {
            width: 2,
            expected: inputs.len(),
        }
        .into());
    }

    let mut input = vec![FieldElement::from(CAP_CONST_W_3)];
    input.append(&mut inputs);

    // Never take the first output
    let out = Poseidon_permutation(&input, params, sbox).remove(1);
    Ok(out)
}

/// Enforces constraints for Poseidon_hash_2 for the given constraint system and Poseidon params
pub fn Poseidon_hash_2_constraints<'a, CS: ConstraintSystem>(
    cs: &mut CS,
    mut inputs: Vec<LinearCombination>,
    capacity_const: LinearCombination,
    params: &'a PoseidonParams,
    sbox_type: &SboxType,
) -> Result<LinearCombination, R1CSError> {
    assert_eq!(inputs.len(), 2);

    // Always keep the 1st input as 0
    let mut input = vec![capacity_const];
    input.append(&mut inputs);

    let permutation_output = Poseidon_permutation_constraints::<CS>(cs, input, params, sbox_type)?;
    Ok(permutation_output[1].to_owned())
}

/// Enforces constraints for Poseidon_hash_2 for the given constraint system and Poseidon params
/// and constraints the output of the hash to given `image`.
pub fn Poseidon_hash_2_gadget<'a, CS: ConstraintSystem>(
    cs: &mut CS,
    input: Vec<Variable>,
    capacity_const: Variable,
    params: &'a PoseidonParams,
    sbox_type: &SboxType,
    image: &FieldElement,
) -> Result<(), R1CSError> {
    let hash = Poseidon_hash_2_constraints::<CS>(
        cs,
        input
            .into_iter()
            .map(|s| s.into())
            .collect::<Vec<LinearCombination>>(),
        capacity_const.into(),
        params,
        sbox_type,
    )?;

    constrain_lc_with_scalar::<CS>(cs, hash, image);

    Ok(())
}

/// Hashes 4 inputs to give a single output
pub fn Poseidon_hash_4(
    mut inputs: Vec<FieldElement>,
    params: &PoseidonParams,
    sbox: &SboxType,
) -> Result<FieldElement, BulletproofError> {
    // Only 4 inputs to the permutation are set to the input of this hash function,
    // one is set to the capacity constant. Always keep the 1st element of the permutation as the
    // capacity constant.
    if inputs.len() != 4 {
        return Err(BulletproofErrorKind::IncorrectWidthForPoseidon {
            width: 4,
            expected: inputs.len(),
        }
        .into());
    }

    let mut input = vec![FieldElement::from(CAP_CONST_W_5)];
    input.append(&mut inputs);
    // Never take the first output
    let out = Poseidon_permutation(&input, params, sbox).remove(1);
    Ok(out)
}

/// Enforces constraints for Poseidon_hash_4 for the given constraint system and Poseidon params
pub fn Poseidon_hash_4_constraints<'a, CS: ConstraintSystem>(
    cs: &mut CS,
    inputs: Vec<LinearCombination>,
    capacity_const: LinearCombination,
    params: &'a PoseidonParams,
    sbox_type: &SboxType,
) -> Result<LinearCombination, R1CSError> {
    // TODO: Code deduplication with macros
    // Only 4 inputs to the permutation are set to the input of this hash function.
    assert_eq!(inputs.len(), 4);

    // Always keep the 1st input as 0
    let mut input = vec![capacity_const];
    input.extend(inputs.into_iter());

    let permutation_output = Poseidon_permutation_constraints::<CS>(cs, input, params, sbox_type)?;
    Ok(permutation_output[1].to_owned())
}

/// Enforces constraints for Poseidon_hash_4 for the given constraint system and Poseidon params
/// and constraints the output of the hash to given `image`.
pub fn Poseidon_hash_4_gadget<'a, CS: ConstraintSystem>(
    cs: &mut CS,
    input: Vec<Variable>,
    capacity_const: Variable,
    params: &'a PoseidonParams,
    sbox_type: &SboxType,
    image: &FieldElement,
) -> Result<(), R1CSError> {
    assert_eq!(input.len(), 4);

    let hash = Poseidon_hash_4_constraints::<CS>(
        cs,
        input
            .into_iter()
            .map(|s| s.into())
            .collect::<Vec<LinearCombination>>(),
        capacity_const.into(),
        params,
        sbox_type,
    )?;

    constrain_lc_with_scalar::<CS>(cs, hash, image);

    Ok(())
}

/// Hashes 2 inputs to give a single output
/// Only 8 inputs to the permutation are set to the input of this hash function,
/// one is set to capacity constant. Always keep the 1st input as capacity constant
pub fn Poseidon_hash_8(
    inputs: Vec<FieldElement>,
    params: &PoseidonParams,
    sbox: &SboxType,
) -> Result<FieldElement, BulletproofError> {
    if inputs.len() != 8 {
        return Err(BulletproofErrorKind::IncorrectWidthForPoseidon {
            width: 8,
            expected: inputs.len(),
        }
        .into());
    }
    let mut input = vec![FieldElement::from(CAP_CONST_W_9)];
    input.extend(inputs.into_iter());

    // Never take the first output
    let out = Poseidon_permutation(&input, params, sbox).remove(1);
    Ok(out)
}

/// Enforces constraints for Poseidon_hash_8 for the given constraint system and Poseidon params
pub fn Poseidon_hash_8_constraints<'a, CS: ConstraintSystem>(
    cs: &mut CS,
    mut input: Vec<LinearCombination>,
    capacity_const: LinearCombination,
    params: &'a PoseidonParams,
    sbox_type: &SboxType,
) -> Result<LinearCombination, R1CSError> {
    assert_eq!(input.len(), 8);

    // Always keep the 1st input as capacity constant
    let mut inputs = vec![capacity_const];
    inputs.append(&mut input);

    let permutation_output = Poseidon_permutation_constraints::<CS>(cs, inputs, params, sbox_type)?;
    Ok(permutation_output[1].to_owned())
}

/// Enforces constraints for Poseidon_hash_8 for the given constraint system and Poseidon params
/// and constraints the output of the hash to given `image`.
pub fn Poseidon_hash_8_gadget<'a, CS: ConstraintSystem>(
    cs: &mut CS,
    input: Vec<Variable>,
    capacity_const: Variable,
    params: &'a PoseidonParams,
    sbox_type: &SboxType,
    image: &FieldElement,
) -> Result<(), R1CSError> {
    assert_eq!(input.len(), 8);
    let hash = Poseidon_hash_8_constraints::<CS>(
        cs,
        input
            .into_iter()
            .map(|s| s.into())
            .collect::<Vec<LinearCombination>>(),
        capacity_const.into(),
        params,
        sbox_type,
    )?;

    constrain_lc_with_scalar::<CS>(cs, hash, image);

    Ok(())
}
