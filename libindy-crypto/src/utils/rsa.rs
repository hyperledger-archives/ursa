use bn::{BigNumber, BigNumberContext};
use errors::IndyCryptoError;

/// Generate an RSA modulus of a given size
///
/// # Arguments
/// * `size` - size in bits of the the RSA modulus
/// * `ctx` - big number context
///
/// # Result
/// Return the RSA modulus and the factors
pub fn generate_rsa_modulus(size: usize,
                            ctx: &mut BigNumberContext) -> Result<(BigNumber, BigNumber, BigNumber), IndyCryptoError> {
    if size % 2 != 0 {
        return Err(IndyCryptoError::InvalidParam1(
            format!("Need an even number of bits, found {}", size))
        );
    }

    let factor_size = size / 2;
    let p = BigNumber::generate_safe_prime(factor_size)?;
    let q = BigNumber::generate_safe_prime(factor_size)?;
    let n = p.mul(&q, Some(ctx))?;
    Ok((n, p, q))
}


/// Generate the witness from the initial witness and subsequent exponents
///
/// # Arguments
/// * `initial_witness` - size in bits of the the RSA modulus
/// * `exponents` - new exponents
/// * `modulus` - exponentiations are done this modulo
/// * `ctx` - big number context
///
/// # Result
/// Return the new witness
pub fn generate_witness(initial_witness: &BigNumber, exponents: &Vec<BigNumber>,
                        modulus: &BigNumber, ctx: &mut BigNumberContext) -> Result<BigNumber, IndyCryptoError> {
    let mut updated_witness = initial_witness.clone()?;
    for ref e in exponents.iter() {
        updated_witness = updated_witness.mod_exp(&e, modulus, Some(ctx))?;
    }
    Ok(updated_witness)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_rsa_modulus_basic() {
        // check modulus is the product of 2 primes
        let mut ctx = BigNumber::new_context().unwrap();
        let (n, p, q) = generate_rsa_modulus(2048, &mut ctx).unwrap();
        assert!(BigNumber::is_prime(&p,Some(&mut ctx)).unwrap());
        assert!(BigNumber::is_prime(&q,Some(&mut ctx)).unwrap());
        assert_eq!(n, p.mul(&q, Some(&mut ctx)).unwrap());
    }

    #[test]
    fn test_generate_witness() {
        // check modulus is the product of 2 primes
        let mut ctx = BigNumber::new_context().unwrap();
        let initial_witness = BigNumber::from_dec("5").unwrap();
        let e1 = BigNumber::from_u32(3).unwrap();
        let e2 = BigNumber::from_u32(5).unwrap();
        let e3 = BigNumber::from_u32(7).unwrap();
        let e4 = BigNumber::from_u32(11).unwrap();
        let e5 = BigNumber::from_u32(13).unwrap();
        let exps = vec![e1, e2, e3, e4, e5];
        let n = BigNumber::from_u32(17).unwrap();
        assert_eq!(BigNumber::from_u32(10).unwrap(), generate_witness(&initial_witness,
                                                                        &exps, &n, &mut ctx).unwrap())
    }

}
