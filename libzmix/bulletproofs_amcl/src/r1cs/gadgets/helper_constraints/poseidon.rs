use crate::errors::R1CSError;
use crate::r1cs::linear_combination::AllocatedQuantity;
use crate::r1cs::{ConstraintSystem, LinearCombination, Variable};
use amcl_wrapper::field_elem::FieldElement;

use super::super::helper_constraints::constrain_lc_with_scalar;
use super::super::helper_constraints::non_zero::is_nonzero_gadget;
use crate::r1cs::gadgets::poseidon_constants::*;

// Poseidon is described here https://eprint.iacr.org/2019/458
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

impl PoseidonParams {
    pub fn new(
        width: usize,
        full_rounds_beginning: usize,
        full_rounds_end: usize,
        partial_rounds: usize,
    ) -> PoseidonParams {
        if width != 3 && width != 5 && width != 9 {
            panic!("Only width of 3, 5 or 9 are supported")
        }
        let total_rounds = full_rounds_beginning + partial_rounds + full_rounds_end;
        let round_keys = Self::gen_round_keys(width, total_rounds);
        let matrix_2 = Self::gen_MDS_matrix(width);
        PoseidonParams {
            width,
            full_rounds_beginning,
            full_rounds_end,
            partial_rounds,
            round_keys,
            MDS_matrix: matrix_2,
        }
    }

    fn gen_round_keys(width: usize, total_rounds: usize) -> Vec<FieldElement> {
        let cap = total_rounds * width;
        //(0..cap).map(|_| FieldElement::random()).collect::<Vec<_>>()
        //vec![FieldElement::one(); cap]
        let ROUND_CONSTS = match width {
            3 => ROUND_CONSTS_W_3.to_vec(),
            5 => ROUND_CONSTS_W_5.to_vec(),
            9 => ROUND_CONSTS_W_9.to_vec(),
            _ => panic!("Unsupported width {}", width),
        };
        if ROUND_CONSTS.len() < cap {
            panic!(
                "Not enough round constants, need {}, found {}",
                cap,
                ROUND_CONSTS.len()
            );
        }
        let mut rc = vec![];
        for i in 0..cap {
            // TODO: Remove unwrap, handle error
            let mut c = ROUND_CONSTS[i].to_string();
            c.replace_range(..2, "");
            rc.push(FieldElement::from_hex(c).unwrap());
        }
        rc
    }

    fn gen_MDS_matrix(width: usize) -> Vec<Vec<FieldElement>> {
        //(0..width).map(|_| (0..width).map(|_| FieldElement::random()).collect::<Vec<_>>()).collect::<Vec<Vec<_>>>()
        //vec![vec![FieldElement::one(); width]; width]

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
            _ => panic!("Unsupported width {}", width),
        };
        if MDS_ENTRIES.len() != width {
            panic!("Incorrect width, only width {} is supported now", width);
        }
        let mut mds: Vec<Vec<FieldElement>> = vec![vec![FieldElement::zero(); width]; width];
        for i in 0..width {
            if MDS_ENTRIES[i].len() != width {
                panic!("Incorrect width, only width {} is supported now", width);
            }
            for j in 0..width {
                // TODO: Remove unwrap, handle error
                let mut c = MDS_ENTRIES[i][j].to_string();
                c.replace_range(..2, "");
                mds[i][j] = FieldElement::from_hex(c).unwrap();
            }
        }
        mds
    }
}

#[derive(Copy, Clone, Debug)]
pub enum SboxType {
    Cube,
    Inverse,
    Quint,
}

impl SboxType {
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

    // Allocate variables in circuit and enforce constraints when Sbox as cube
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

    // Allocate variables in circuit and enforce constraints when Sbox as quint
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

    // Allocate variables in circuit and enforce constraints when Sbox as inverse
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

    let mut current_state = input.to_owned();
    let mut current_state_temp = vec![FieldElement::zero(); width];

    let mut round_keys_offset = 0;

    // full Sbox rounds
    for _ in 0..full_rounds_beginning {
        // Sbox layer
        for i in 0..width {
            current_state[i] += &params.round_keys[round_keys_offset];
            current_state[i] = sbox.apply_sbox(&current_state[i]);
            round_keys_offset += 1;
        }

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

    // middle partial Sbox rounds
    for _ in full_rounds_beginning..(full_rounds_beginning + partial_rounds) {
        for i in 0..width {
            current_state[i] += &params.round_keys[round_keys_offset];
            round_keys_offset += 1;
        }

        // partial Sbox layer, apply Sbox to only 1 element of the state.
        // Here the last one is chosen but the choice is arbitrary.
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

    // last full Sbox rounds
    let loop_begin = full_rounds_beginning + partial_rounds;
    let loop_end = full_rounds_beginning + partial_rounds + full_rounds_end;
    for _ in loop_begin..loop_end {
        // Sbox layer
        for i in 0..width {
            current_state[i] += &params.round_keys[round_keys_offset];
            current_state[i] = sbox.apply_sbox(&current_state[i]);
            round_keys_offset += 1;
        }

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

    current_state
}

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
                next_inputs[i] += (&matrix_2[j][i] * sbox_outs[j].clone());
            }
        }
    }

    let mut input_vars: Vec<LinearCombination> = input;

    let mut round_keys_offset = 0;

    let full_rounds_beginning = params.full_rounds_beginning;
    let partial_rounds = params.partial_rounds;
    let full_rounds_end = params.full_rounds_end;

    // ------------ First full_rounds_beginning rounds begin --------------------

    for _ in 0..full_rounds_beginning {
        let mut sbox_outputs: Vec<LinearCombination> = vec![LinearCombination::default(); width];

        // Substitution (S-box) layer
        for i in 0..width {
            let round_key = params.round_keys[round_keys_offset].clone();
            sbox_outputs[i] = sbox_type
                .synthesize_sbox(cs, input_vars[i].clone(), round_key)?
                .into();

            round_keys_offset += 1;
        }

        let mut next_input_vars: Vec<LinearCombination> = vec![LinearCombination::default(); width];

        apply_linear_layer(sbox_outputs, &mut next_input_vars, &params.MDS_matrix);

        for i in 0..width {
            // replace input_vars with next_input_vars
            input_vars[i] = next_input_vars.remove(0);
        }
    }

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
                    .synthesize_sbox(cs, input_vars[i].clone(), round_key)?
                    .into();
            } else {
                sbox_outputs[i] = input_vars[i].clone() + round_key;
            }

            round_keys_offset += 1;
        }

        // Linear layer

        let mut next_input_vars: Vec<LinearCombination> = vec![LinearCombination::default(); width];

        apply_linear_layer(sbox_outputs, &mut next_input_vars, &params.MDS_matrix);

        for i in 0..width {
            // replace input_vars with simplified next_input_vars
            input_vars[i] = next_input_vars.remove(0).simplify();
            //println!("len={}", input_vars[i].len());
        }
    }

    // ------------ Middle rounds end --------------------

    // ------------ Last rounds with full SBox begin --------------------

    // 3 rounds
    for _ in full_rounds_beginning + partial_rounds
        ..(full_rounds_beginning + partial_rounds + full_rounds_end)
    {
        let mut sbox_outputs: Vec<LinearCombination> = vec![LinearCombination::default(); width];

        // Substitution (S-box) layer
        for i in 0..width {
            let round_key = params.round_keys[round_keys_offset].clone();
            sbox_outputs[i] = sbox_type
                .synthesize_sbox(cs, input_vars[i].clone(), round_key)?
                .into();

            round_keys_offset += 1;
        }

        // Linear layer

        let mut next_input_vars: Vec<LinearCombination> = vec![LinearCombination::default(); width];

        apply_linear_layer(sbox_outputs, &mut next_input_vars, &params.MDS_matrix);

        for i in 0..width {
            // replace input_vars with next_input_vars
            input_vars[i] = next_input_vars.remove(0);
        }
    }

    // ------------ Last rounds with full SBox end --------------------

    Ok(input_vars)
}

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

/// 2:1 (2 inputs, 1 output) hash from the permutation by passing the first input as zero, 2 of the next 4 as non-zero, a padding constant and rest zero. Choose one of the outputs.

// Choice is arbitrary
pub const PADDING_CONST: u64 = 101;
pub const ZERO_CONST: u64 = 0;

pub fn Poseidon_hash_2(
    xl: FieldElement,
    xr: FieldElement,
    params: &PoseidonParams,
    sbox: &SboxType,
) -> FieldElement {
    // Only 2 inputs to the permutation are set to the input of this hash function,
    // one is set to the padding constant and rest are 0. Always keep the 1st input as 0

    let input = vec![FieldElement::from(ZERO_CONST), xl, xr];

    // Never take the first output
    let out = Poseidon_permutation(&input, params, sbox).remove(1);
    out
}

pub fn Poseidon_hash_2_constraints<'a, CS: ConstraintSystem>(
    cs: &mut CS,
    xl: LinearCombination,
    xr: LinearCombination,
    statics: Vec<LinearCombination>,
    params: &'a PoseidonParams,
    sbox_type: &SboxType,
) -> Result<LinearCombination, R1CSError> {
    let width = params.width;
    // Only 2 inputs to the permutation are set to the input of this hash function.
    assert_eq!(statics.len(), width - 2);

    // Always keep the 1st input as 0
    let mut inputs = vec![statics[0].to_owned()];
    inputs.push(xl);
    inputs.push(xr);

    // statics correspond to committed variables with values as PADDING_CONST and 0s and randomness as 0
    for i in 1..statics.len() {
        inputs.push(statics[i].to_owned());
    }
    let permutation_output = Poseidon_permutation_constraints::<CS>(cs, inputs, params, sbox_type)?;
    Ok(permutation_output[1].to_owned())
}

pub fn Poseidon_hash_2_gadget<'a, CS: ConstraintSystem>(
    cs: &mut CS,
    xl: Variable,
    xr: Variable,
    statics: Vec<Variable>,
    params: &'a PoseidonParams,
    sbox_type: &SboxType,
    output: &FieldElement,
) -> Result<(), R1CSError> {
    let hash = Poseidon_hash_2_constraints::<CS>(
        cs,
        xl.into(),
        xr.into(),
        statics
            .into_iter()
            .map(|s| s.into())
            .collect::<Vec<LinearCombination>>(),
        params,
        sbox_type,
    )?;

    constrain_lc_with_scalar::<CS>(cs, hash, output);

    Ok(())
}

pub fn Poseidon_hash_4(
    mut inputs: Vec<FieldElement>,
    params: &PoseidonParams,
    sbox: &SboxType,
) -> FieldElement {
    // Only 4 inputs to the permutation are set to the input of this hash function,
    // one is set to the padding constant and one is set to 0. Always keep the 1st input as 0
    assert_eq!(inputs.len(), 4);
    let mut input = vec![FieldElement::from(ZERO_CONST)];
    input.append(&mut inputs);
    //input.push(FieldElement::from(PADDING_CONST));
    // Never take the first output
    let out = Poseidon_permutation(&input, params, sbox).remove(1);
    out
}

pub fn Poseidon_hash_4_constraints<'a, CS: ConstraintSystem>(
    cs: &mut CS,
    mut inputs: Vec<LinearCombination>,
    mut statics: Vec<LinearCombination>,
    params: &'a PoseidonParams,
    sbox_type: &SboxType,
) -> Result<LinearCombination, R1CSError> {
    let width = params.width;
    // Only 4 inputs to the permutation are set to the input of this hash function.
    assert_eq!(inputs.len(), 4);
    assert_eq!(statics.len(), width - 4);

    // Always keep the 1st input as 0
    let mut input = vec![statics.remove(0)];
    input.append(&mut inputs);

    // statics correspond to committed variables with values as PADDING_CONST and 0s and randomness as 0
    input.append(&mut statics);
    let permutation_output = Poseidon_permutation_constraints::<CS>(cs, input, params, sbox_type)?;
    Ok(permutation_output[1].to_owned())
}

pub fn Poseidon_hash_4_gadget<'a, CS: ConstraintSystem>(
    cs: &mut CS,
    input: Vec<Variable>,
    statics: Vec<Variable>,
    params: &'a PoseidonParams,
    sbox_type: &SboxType,
    output: &FieldElement,
) -> Result<(), R1CSError> {
    assert_eq!(input.len(), 4);

    let hash = Poseidon_hash_4_constraints::<CS>(
        cs,
        input
            .into_iter()
            .map(|s| s.into())
            .collect::<Vec<LinearCombination>>(),
        statics
            .into_iter()
            .map(|s| s.into())
            .collect::<Vec<LinearCombination>>(),
        params,
        sbox_type,
    )?;

    constrain_lc_with_scalar::<CS>(cs, hash, output);

    Ok(())
}

/// Only 8 inputs to the permutation are set to the input of this hash function,
/// one is set to 0. Always keep the 1st input as 0
pub fn Poseidon_hash_8(
    mut inputs: Vec<FieldElement>,
    params: &PoseidonParams,
    sbox: &SboxType,
) -> FieldElement {
    assert_eq!(inputs.len(), 8);
    let mut input = vec![FieldElement::from(ZERO_CONST)];
    input.append(&mut inputs);

    // Never take the first output
    let out = Poseidon_permutation(&input, params, sbox).remove(1);
    out
}

pub fn Poseidon_hash_8_constraints<'a, CS: ConstraintSystem>(
    cs: &mut CS,
    mut input: Vec<LinearCombination>,
    zero: LinearCombination,
    params: &'a PoseidonParams,
    sbox_type: &SboxType,
) -> Result<LinearCombination, R1CSError> {
    assert_eq!(input.len(), 8);
    let width = params.width;
    // zero corresponds to committed variable with value as ZERO_CONST and randomness as 0

    // Always keep the 1st input as 0
    let mut inputs = vec![zero];
    inputs.append(&mut input);

    let permutation_output = Poseidon_permutation_constraints::<CS>(cs, inputs, params, sbox_type)?;
    Ok(permutation_output[1].to_owned())
}

pub fn Poseidon_hash_8_gadget<'a, CS: ConstraintSystem>(
    cs: &mut CS,
    input: Vec<Variable>,
    zero: Variable,
    params: &'a PoseidonParams,
    sbox_type: &SboxType,
    output: &FieldElement,
) -> Result<(), R1CSError> {
    assert_eq!(input.len(), 8);
    let hash = Poseidon_hash_8_constraints::<CS>(
        cs,
        input
            .into_iter()
            .map(|s| s.into())
            .collect::<Vec<LinearCombination>>(),
        zero.into(),
        params,
        sbox_type,
    )?;

    constrain_lc_with_scalar::<CS>(cs, hash, output);

    Ok(())
}
