use bn::{BigNumber, BigNumberContext};
use errors::IndyCryptoError;


/// Generate a pedersen commitment
///
/// Generate a pedersen commitment to a given number
///
/// # Arguments
/// * `gen_1` - first generator
/// * `gen_2` - second generator
/// * `m` - exponent of the first generator
/// * `r` - exponent of the second generator
/// * `modulus` - all computations are done this modulo
/// * `ctx` - optional big number context
///
/// # Result
/// Return the pedersen commitment, i.e `(gen_1^m)*(gen_2^r)`

pub fn get_pedersen_commitment(gen_1: &BigNumber, m: &BigNumber,
                               gen_2: &BigNumber, r: &BigNumber,
                               modulus: &BigNumber, ctx: &mut BigNumberContext) -> Result<BigNumber, IndyCryptoError> {
    let commitment = gen_1.mod_exp(m, modulus, Some(ctx))?
        .mod_mul(&gen_2.mod_exp(r, modulus, Some(ctx))?,
                 modulus, Some(ctx))?;
    Ok(commitment)
}

