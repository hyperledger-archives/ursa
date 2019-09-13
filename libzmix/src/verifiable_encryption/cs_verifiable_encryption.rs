// Copyright contributors to Hyperledger Ursa.
// SPDX-License-Identifier: Apache-2.0

/// Camenisch-Shoup verifiable encryption.
/// Based on the paper Practical Verifiable Encryption and Decryption of Discrete Logarithms. https://www.shoup.net/papers/verenc.pdf.
/// Various code comments refer this paper
/// Need to be used with Anonymous credentials as described in Specification of the Identity
/// Mixer Cryptographic Library, https://domino.research.ibm.com/library/cyberdig.nsf/papers/EEB54FF3B91C1D648525759B004FBBB1/$File/rz3730_revised.pdf
/// sections 5.3, 6.2.10 and 6.2.19.
use super::bn::{BigNumber, BigNumberContext, BIGNUMBER_1, BIGNUMBER_2};
use super::errors::prelude::*;

use super::cl::constants::*;
use super::cl::hash::get_hash_as_int;
use super::cl::helpers::*;

// g and h correspond to the symbols with same name in paper "Practical Verifiable Encryption...."
#[derive(Serialize, Deserialize)]
pub struct PaillierGroup {
    pub g: BigNumber,
    pub h: BigNumber,
    pub n_by_4: BigNumber,  // n/4, precomputation
    pub modulus: BigNumber, // n^2
}

// x1, x2 and x3 correspond to the symbols with same name in the paper
#[derive(Serialize, Deserialize)]
pub struct CSEncPrikey {
    pub x1: Vec<BigNumber>,
    pub x2: BigNumber,
    pub x3: BigNumber,
}

// n, y1, y2 and y3 correspond to the symbols with same name in the paper
#[derive(Serialize, Deserialize)]
pub struct CSEncPubkey {
    pub n: BigNumber,
    pub two_inv_times_2: BigNumber, // (2^-1 % n) * 2, precomputation
    pub paillier_group: PaillierGroup,
    pub y1: Vec<BigNumber>,
    pub y2: BigNumber,
    pub y3: BigNumber,
}

// u, e and v correspond to the symbols with same name in the paper
#[derive(Serialize, Deserialize)]
pub struct CSCiphertext {
    pub u: BigNumber,
    pub e: Vec<BigNumber>,
    pub v: BigNumber,
}

pub struct CSKeypair {
    pub pri_key: CSEncPrikey,
    pub pub_key: CSEncPubkey,
}

impl PaillierGroup {
    /// Order (modulus) is n^2. n, g_prime, g and h correspond to the symbols in the paper "Practical Verifiable Encryption...."
    pub fn new(n: &BigNumber, ctx: &mut BigNumberContext) -> UrsaCryptoResult<Self> {
        let modulus = n.sqr(Some(ctx))?; // n^2
        let mut n_mul_2 = n.try_clone()?; // n*2
        n_mul_2 = n_mul_2.lshift1()?;
        let g_prime = modulus.rand_range()?;
        let g = g_prime.mod_exp(&n_mul_2, &modulus, Some(ctx))?;
        Ok(Self {
            g,
            h: n.increment()?,    // h = n+1
            n_by_4: n.rshift(2)?, // n/4
            modulus,
        })
    }

    /// self.g^exp % self.modulus
    pub fn exponentiate_g(
        &self,
        exp: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        self.exponentiate(&self.g, exp, ctx)
    }

    /// self.h^exp % self.modulus
    pub fn exponentiate_h(
        &self,
        exp: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        self.exponentiate(&self.h, exp, ctx)
    }

    /// exponentiate in this Paillier group meaning the result is taken modulo this group's order (modulus). base^exp % self.modulus
    pub fn exponentiate(
        &self,
        base: &BigNumber,
        exp: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        base.mod_exp(exp, &self.modulus, ctx)
    }

    /// base^2 % self.modulus
    pub fn sqr(
        &self,
        base: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        match ctx {
            Some(mut ctx) => base
                .sqr(Some(&mut ctx))?
                .modulus(&self.modulus, Some(&mut ctx)),
            None => base.sqr(None)?.modulus(&self.modulus, None),
        }
    }

    /// Return a random element modulo the group order, i.e. modulus
    pub fn rand(&self) -> UrsaCryptoResult<BigNumber> {
        self.modulus.rand_range()
    }

    /// Return a random element modulo sqrt(modulo)/4
    pub fn rand_for_enc(&self) -> UrsaCryptoResult<BigNumber> {
        self.n_by_4.rand_range()
    }

    /// if a > (n^2)/2 then n^2 - a else a
    /// section 3.2 of paper
    pub fn abs(
        &self,
        a: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> UrsaCryptoResult<BigNumber> {
        let a = a.modulus(&self.modulus, ctx)?;
        let modulus_by_2 = self.modulus.rshift(1)?;
        if a > modulus_by_2 {
            self.modulus.sub(&a)
        } else {
            Ok(a)
        }
    }
}

/// The public and private keys used for encryption and decryption.
impl CSKeypair {
    /// Create public and private key for encryption. Also initialize the Paillier group.
    /// `num_messages` is the maximum number of messages that the public-private key will support.
    /// Trying to encrypt more than `num_messages` messages will result in error. Encrypting less is fine.
    /// Key Generation from section 3.2 of the Practical Verifiable Encryption ... paper
    pub fn new(num_messages: usize) -> UrsaCryptoResult<Self> {
        if num_messages < 1 {
            return Err(UrsaCryptoError::from_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                "number of messages should be greater than 0",
            ));
        }
        let mut ctx = BigNumber::new_context()?;

        let p_safe = generate_safe_prime(LARGE_PRIME)?;
        let q_safe = generate_safe_prime(LARGE_PRIME)?;
        let n = p_safe.mul(&q_safe, Some(&mut ctx))?;
        let two_inv_times_2 = BIGNUMBER_2.inverse(&n, Some(&mut ctx))?.lshift1()?;
        let paillier_group = PaillierGroup::new(&n, &mut ctx)?;
        let n_sqr_by_4 = paillier_group.modulus.rshift(2)?; // (n^2)/4
        let mut x1 = Vec::with_capacity(num_messages);
        let mut y1 = Vec::with_capacity(num_messages);
        for _ in 0..num_messages {
            let x = n_sqr_by_4.rand_range()?;
            let y = paillier_group.exponentiate_g(&x, Some(&mut ctx))?;
            x1.push(x);
            y1.push(y);
        }
        let x2 = n_sqr_by_4.rand_range()?;
        let x3 = n_sqr_by_4.rand_range()?;
        let y2 = paillier_group.exponentiate_g(&x2, Some(&mut ctx))?;
        let y3 = paillier_group.exponentiate_g(&x3, Some(&mut ctx))?;
        Ok(Self {
            pri_key: CSEncPrikey { x1, x2, x3 },
            pub_key: CSEncPubkey {
                n,
                two_inv_times_2,
                paillier_group,
                y1,
                y2,
                y3,
            },
        })
    }
}

/// Decryption from section 3.2
pub fn decrypt(
    label: &[u8],
    ciphertext: &CSCiphertext,
    pub_key: &CSEncPubkey,
    pri_key: &CSEncPrikey,
) -> UrsaCryptoResult<Vec<BigNumber>> {
    if ciphertext.e.len() > pri_key.x1.len() {
        return Err(UrsaCryptoError::from_msg(
            UrsaCryptoErrorKind::InvalidStructure,
            format!(
                "number of messages {} is more than supported by public key {}",
                ciphertext.e.len(),
                pri_key.x1.len()
            ),
        ));
    }
    let mut ctx = BigNumber::new_context()?;

    let paillier_group = &pub_key.paillier_group;

    // Check if abs(v) == v?
    if ciphertext.v != paillier_group.abs(&ciphertext.v, Some(&mut ctx))? {
        return Err(UrsaCryptoError::from_msg(
            UrsaCryptoErrorKind::InvalidStructure,
            format!("absolute check failed for v {:?}", &ciphertext.v),
        ));
    }
    let hs = &hash(&ciphertext.u, &ciphertext.e, label)?;
    let hs_x3 = hs.mul(&pri_key.x3, Some(&mut ctx))?;
    let hs_x3_x2_times_2 = hs_x3.add(&pri_key.x2)?.lshift1()?;
    let u_sqr = paillier_group.exponentiate(&ciphertext.u, &hs_x3_x2_times_2, Some(&mut ctx))?;
    let v_sqr = paillier_group.sqr(&ciphertext.v, Some(&mut ctx))?;
    if v_sqr != u_sqr {
        return Err(UrsaCryptoError::from_msg(
            UrsaCryptoErrorKind::InvalidStructure,
            format!("u^2 != v^2, {:?} != {:?}", &u_sqr, &v_sqr),
        ));
    }
    let mut messages = Vec::<BigNumber>::with_capacity(ciphertext.e.len());
    for i in 0..ciphertext.e.len() {
        let u_x1 = paillier_group.exponentiate(&ciphertext.u, &pri_key.x1[i], Some(&mut ctx))?;
        // 1/u^{x_1}
        let u_x1_inv = u_x1.inverse(&paillier_group.modulus, Some(&mut ctx))?;
        // (e/u^{x_1})
        let e_u_x1_inv =
            &ciphertext.e[i].mod_mul(&u_x1_inv, &paillier_group.modulus, Some(&mut ctx))?;

        // m_hat = (e/u^{x_1})^2*t
        let m_hat =
            paillier_group.exponentiate(&e_u_x1_inv, &pub_key.two_inv_times_2, Some(&mut ctx))?;
        if m_hat.modulus(&pub_key.n, Some(&mut ctx))? == *BIGNUMBER_1 {
            let mut m = m_hat.modulus(&paillier_group.modulus, Some(&mut ctx))?;
            m.sub_word(1)?;
            m = m.div(&pub_key.n, Some(&mut ctx))?;
            messages.push(m);
        } else {
            return Err(UrsaCryptoError::from_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                format!("Decryption failed for message {}", i + 1),
            ));
        }
    }

    Ok(messages)
}

/// Encrypt multiple messages.
/// Encryption from section 3.2
pub fn encrypt(
    messages: &[BigNumber],
    label: &[u8],
    pub_key: &CSEncPubkey,
) -> UrsaCryptoResult<CSCiphertext> {
    if messages.len() > pub_key.y1.len() {
        return Err(UrsaCryptoError::from_msg(
            UrsaCryptoErrorKind::InvalidStructure,
            format!(
                "number of messages {} is more than supported by public key {}",
                messages.len(),
                pub_key.y1.len()
            ),
        ));
    }

    let paillier_group = &pub_key.paillier_group;
    let r = paillier_group.rand_for_enc()?;

    encrypt_using_random_value(&r, messages, label, pub_key)
}

/// 1st phase of sigma protocol. Compute ciphertext and commitments (t values).
/// Return ciphertext, commitments and random values created during encryption and t value
/// "The protocol" from section 5.2. Not using t = g^m*h^s as the idemix protocol does not use it.
/// Guess is that since the knowledge of m is proved in the credential attribute proving protocol.
pub fn encrypt_and_prove_phase_1(
    messages: &[BigNumber],
    blindings: &[BigNumber],
    label: &[u8],
    pub_key: &CSEncPubkey,
) -> UrsaCryptoResult<(CSCiphertext, CSCiphertext, BigNumber, BigNumber)> {
    if messages.len() != blindings.len() {
        return Err(UrsaCryptoError::from_msg(
            UrsaCryptoErrorKind::InvalidStructure,
            format!(
                "number of messages {} is not equal to the number of blindings {}",
                messages.len(),
                blindings.len()
            ),
        ));
    }

    if messages.len() > pub_key.y1.len() {
        return Err(UrsaCryptoError::from_msg(
            UrsaCryptoErrorKind::InvalidStructure,
            format!(
                "number of messages {} is more than supported by public key {}",
                messages.len(),
                pub_key.y1.len()
            ),
        ));
    }

    let paillier_group = &pub_key.paillier_group;
    // random value for ciphertext
    let r = paillier_group.rand_for_enc()?;
    // random value for commitment
    let r_tilde = paillier_group.rand_for_enc()?;
    let ciphertext = encrypt_using_random_value(&r, messages, label, pub_key)?;
    let hash = hash(&ciphertext.u, &ciphertext.e, label)?;
    let ciphertext_t_values = ciphertext_t_values(&r_tilde, &blindings, &hash, pub_key)?;
    Ok((ciphertext, ciphertext_t_values, r, r_tilde))
}

/// Return r_hat = r_tilde - r.x
/// "The protocol" from section 5.2.
pub fn encrypt_and_prove_phase_2(
    r: &BigNumber,
    r_tilde: &BigNumber,
    challenge: &BigNumber,
    pub_key: &CSEncPubkey,
    ctx: Option<&mut BigNumberContext>,
) -> UrsaCryptoResult<BigNumber> {
    r_tilde.sub(&(r.mod_mul(&challenge, &pub_key.paillier_group.modulus, ctx)?))
}

/// Used by verifier to reconstruct blindings.
/// "The protocol" from section 5.2.
pub fn reconstruct_blindings_ciphertext(
    ciphertext: &CSCiphertext,
    message_s_values: &[BigNumber],
    r_hat: &BigNumber,
    challenge: &BigNumber,
    label: &[u8],
    pub_key: &CSEncPubkey,
) -> UrsaCryptoResult<CSCiphertext> {
    if message_s_values.len() > pub_key.y1.len() {
        return Err(UrsaCryptoError::from_msg(
            UrsaCryptoErrorKind::InvalidStructure,
            format!(
                "number of messages {} is more than supported by public key {}",
                message_s_values.len(),
                pub_key.y1.len()
            ),
        ));
    }

    let challenge = &(challenge.lshift1()?);
    let r_hat = &(r_hat.lshift1()?);

    let paillier_group = &pub_key.paillier_group;
    let mut ctx = BigNumber::new_context()?;

    let u_c = paillier_group.exponentiate(&ciphertext.u, challenge, Some(&mut ctx))?;
    let g_r_hat = paillier_group.exponentiate_g(r_hat, Some(&mut ctx))?;
    // Reconstruct u blinding
    let u_blinded = u_c.mod_mul(&g_r_hat, &paillier_group.modulus, Some(&mut ctx))?;

    // Reconstruct e blinding
    let mut e_blinded = vec![];
    for i in 0..message_s_values.len() {
        let e_c = paillier_group.exponentiate(&ciphertext.e[i], challenge, Some(&mut ctx))?;
        let y_r_hat = paillier_group.exponentiate(&pub_key.y1[i], r_hat, Some(&mut ctx))?;
        let h_m_hat =
            paillier_group.exponentiate_h(&(message_s_values[i].lshift1()?), Some(&mut ctx))?;
        e_blinded.push(
            e_c.mod_mul(&y_r_hat, &paillier_group.modulus, Some(&mut ctx))?
                .mod_mul(&h_m_hat, &paillier_group.modulus, Some(&mut ctx))?,
        );
    }

    // Reconstruct v blinding
    let v_c = paillier_group.exponentiate(&ciphertext.v, challenge, Some(&mut ctx))?;
    let y3_hs = paillier_group.exponentiate(
        &pub_key.y3,
        &hash(&ciphertext.u, &ciphertext.e, label)?,
        Some(&mut ctx),
    )?;
    let y2_y3_hs = &pub_key
        .y2
        .mod_mul(&y3_hs, &paillier_group.modulus, Some(&mut ctx))?;
    let y2_y3_hs_r_hat = paillier_group.exponentiate(&y2_y3_hs, r_hat, Some(&mut ctx))?;
    let v_blinded = v_c.mod_mul(&y2_y3_hs_r_hat, &paillier_group.modulus, Some(&mut ctx))?;
    Ok(CSCiphertext {
        u: u_blinded,
        e: e_blinded,
        v: v_blinded,
    })
}

/// Compute u, e and v
fn encrypt_using_random_value(
    random_value: &BigNumber,
    messages: &[BigNumber],
    label: &[u8],
    pub_key: &CSEncPubkey,
) -> UrsaCryptoResult<CSCiphertext> {
    let mut ctx = BigNumber::new_context()?;

    let u = compute_u(random_value, pub_key, &mut ctx)?;
    let e = compute_e(messages, random_value, pub_key, &mut ctx)?;
    let hash = hash(&u, &e, label)?;
    let v = compute_v(random_value, &hash, pub_key, &mut ctx, true)?;
    Ok(CSCiphertext { u, e, v })
}

/// Compute commitments for ciphertext when proving encryption is correct.
fn ciphertext_t_values(
    random_value: &BigNumber,
    messages: &[BigNumber],
    hash: &BigNumber,
    pub_key: &CSEncPubkey,
) -> UrsaCryptoResult<CSCiphertext> {
    let mut ctx = BigNumber::new_context()?;
    let messages: Vec<_> = messages.iter().map(|m| m.lshift1().unwrap()).collect();
    let random_value = random_value.lshift1()?;
    let u = compute_u(&random_value, pub_key, &mut ctx)?;
    let e = compute_e(&messages, &random_value, pub_key, &mut ctx)?;
    let v = compute_v(&random_value, hash, pub_key, &mut ctx, false)?;
    Ok(CSCiphertext { u, e, v })
}

fn compute_u(
    random_value: &BigNumber,
    pub_key: &CSEncPubkey,
    mut ctx: &mut BigNumberContext,
) -> UrsaCryptoResult<BigNumber> {
    pub_key
        .paillier_group
        .exponentiate_g(random_value, Some(&mut ctx))
}

fn compute_e(
    messages: &[BigNumber],
    random_value: &BigNumber,
    pub_key: &CSEncPubkey,
    mut ctx: &mut BigNumberContext,
) -> UrsaCryptoResult<Vec<BigNumber>> {
    let paillier_group = &pub_key.paillier_group;
    let mut e = Vec::with_capacity(messages.len());
    for i in 0..messages.len() {
        let y = paillier_group.exponentiate(&pub_key.y1[i], random_value, Some(&mut ctx))?;
        let h_m = paillier_group.exponentiate_h(&messages[i], Some(&mut ctx))?;
        e.push(y.mod_mul(&h_m, &paillier_group.modulus, Some(&mut ctx))?);
    }
    Ok(e)
}

/// If `take_abs` is true, absolute value of v is taken else not. This switch is present for
/// code-reuse as during the proof for encryption, in the commitment step (1st step of sigma protocol)
/// absolute value is not taken.
fn compute_v(
    random_value: &BigNumber,
    hash: &BigNumber,
    pub_key: &CSEncPubkey,
    mut ctx: &mut BigNumberContext,
    take_abs: bool,
) -> UrsaCryptoResult<BigNumber> {
    let paillier_group = &pub_key.paillier_group;
    let y3_hs = paillier_group.exponentiate(&pub_key.y3, hash, Some(&mut ctx))?;
    let y2_y3_hs = &pub_key
        .y2
        .mod_mul(&y3_hs, &paillier_group.modulus, Some(&mut ctx))?;
    let y2_y3_hs_r = paillier_group.exponentiate(&y2_y3_hs, random_value, Some(&mut ctx))?;
    if take_abs {
        paillier_group.abs(&y2_y3_hs_r, Some(&mut ctx))
    } else {
        Ok(y2_y3_hs_r)
    }
}

fn hash(u: &BigNumber, e: &[BigNumber], label: &[u8]) -> UrsaCryptoResult<BigNumber> {
    let mut arr = vec![u.to_bytes()?];
    for b in e {
        arr.push(b.to_bytes()?)
    }
    arr.push(label.to_vec());
    get_hash_as_int(&arr)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn paillier_abs() {
        let mut ctx = BigNumber::new_context().unwrap();

        let p_safe = generate_safe_prime(LARGE_PRIME).unwrap();
        let q_safe = generate_safe_prime(LARGE_PRIME).unwrap();
        let n = p_safe.mul(&q_safe, Some(&mut ctx)).unwrap();
        let paillier_group = PaillierGroup::new(&n, &mut ctx).unwrap();

        for _ in 0..10 {
            let v = paillier_group.rand().unwrap();
            let abs_v = paillier_group.abs(&v, Some(&mut ctx)).unwrap();
            let v_sqr = paillier_group.sqr(&v, Some(&mut ctx)).unwrap();
            println!("v^2 created");
            let abs_v_sqr = paillier_group.sqr(&abs_v, Some(&mut ctx)).unwrap();
            println!("abs(v)^2 created");
            assert_eq!(v_sqr, abs_v_sqr);
        }
    }

    #[test]
    fn cs_encryption_serialization_deserialization() {
        let keypair = CSKeypair::new(1).unwrap();
        let (pub_key, pri_key) = (&keypair.pub_key, &keypair.pri_key);
        let messages = vec![keypair.pub_key.n.rand_range().unwrap()];
        let label = "test".as_bytes();

        // Create ciphertext
        let ciphertext = encrypt(&messages, label, pub_key).unwrap();

        // Serialize public and private keys
        let serz_pub_key = serde_json::to_string(pub_key);
        assert!(serz_pub_key.is_ok());
        let serz_pri_key = serde_json::to_string(pri_key);
        assert!(serz_pri_key.is_ok());

        // Deserialize public and private keys
        let desz_pub_key: CSEncPubkey = serde_json::from_str(&serz_pub_key.unwrap()).unwrap();
        let desz_pri_key: CSEncPrikey = serde_json::from_str(&serz_pri_key.unwrap()).unwrap();

        // Decrypt using deserialized public and private keys
        let decrypted_messages = decrypt(label, &ciphertext, &desz_pub_key, &desz_pri_key).unwrap();
        assert_eq!(decrypted_messages, messages);
    }

    #[test]
    fn cs_encryption_smaller_public_key() {
        // Public key supports encryption of only 1 message but encryption of 2 messages is attempted
        let keypair = CSKeypair::new(1).unwrap();
        let messages = vec![
            keypair.pub_key.n.rand_range().unwrap(),
            keypair.pub_key.n.rand_range().unwrap(),
        ];
        assert!(encrypt(&messages, "test".as_bytes(), &keypair.pub_key).is_err())
    }

    #[test]
    fn cs_encryption_single_message() {
        let keypair = CSKeypair::new(1).unwrap();
        let messages = vec![keypair.pub_key.n.rand_range().unwrap()];
        let ciphertext = encrypt(&messages, "test".as_bytes(), &keypair.pub_key).unwrap();
        let decrypted_messages = decrypt(
            "test".as_bytes(),
            &ciphertext,
            &keypair.pub_key,
            &keypair.pri_key,
        )
        .unwrap();
        assert_eq!(decrypted_messages, messages);
    }

    #[test]
    fn cs_encryption_multiple_messages() {
        let num_messages = 10;
        let keypair = CSKeypair::new(num_messages).unwrap();
        let messages: Vec<_> = (0..num_messages)
            .map(|_| keypair.pub_key.n.rand_range().unwrap())
            .collect();
        let ciphertext = encrypt(&messages, "test2".as_bytes(), &keypair.pub_key).unwrap();
        let decrypted_messages = decrypt(
            "test2".as_bytes(),
            &ciphertext,
            &keypair.pub_key,
            &keypair.pri_key,
        )
        .unwrap();
        assert_eq!(decrypted_messages, messages);
    }

    #[test]
    fn cs_encryption_label_mismatch() {
        let num_messages = 2;
        let keypair = CSKeypair::new(num_messages).unwrap();
        let messages: Vec<_> = (0..num_messages)
            .map(|_| keypair.pub_key.n.rand_range().unwrap())
            .collect();
        let label_enc = "test1".as_bytes();
        let label_dec = "test2".as_bytes();
        let ciphertext = encrypt(&messages, label_enc, &keypair.pub_key).unwrap();
        assert!(decrypt(label_dec, &ciphertext, &keypair.pub_key, &keypair.pri_key,).is_err())
    }

    #[test]
    fn cs_encryption_single_message_bigger_public_key() {
        // Public key supports encryption of 2 messages but only 1 message is encrypted
        let keypair = CSKeypair::new(2).unwrap();
        let messages = vec![keypair.pub_key.n.rand_range().unwrap()];
        let ciphertext = encrypt(&messages, "test".as_bytes(), &keypair.pub_key).unwrap();
        let decrypted_messages = decrypt(
            "test".as_bytes(),
            &ciphertext,
            &keypair.pub_key,
            &keypair.pri_key,
        )
        .unwrap();
        assert_eq!(decrypted_messages, messages);
    }

    #[test]
    fn cs_decryption_smaller_public_key() {
        // // Public key supports encryption of only 1 message but decryption of 2 message ciphertext is attempted
        let mut keypair = CSKeypair::new(2).unwrap();
        let messages = vec![
            keypair.pub_key.n.rand_range().unwrap(),
            keypair.pub_key.n.rand_range().unwrap(),
        ];
        let ciphertext = encrypt(&messages, "test".as_bytes(), &keypair.pub_key).unwrap();

        // Make public key smaller
        keypair.pri_key.x1.pop();
        assert!(decrypt(
            "test".as_bytes(),
            &ciphertext,
            &keypair.pub_key,
            &keypair.pri_key
        )
        .is_err());
    }

    #[test]
    fn prove_cs_encryption_single_message() {
        let mut ctx = BigNumber::new_context().unwrap();

        let keypair = CSKeypair::new(1).unwrap();
        let messages = vec![keypair.pub_key.n.rand_range().unwrap()];
        let ciphertext = encrypt(&messages, "test".as_bytes(), &keypair.pub_key).unwrap();
        let decrypted_messages = decrypt(
            "test".as_bytes(),
            &ciphertext,
            &keypair.pub_key,
            &keypair.pri_key,
        )
        .unwrap();
        assert_eq!(decrypted_messages, messages);

        // Message blinding are m_tilde values and they will be created by the main proving protocol not this verifiable encryption module
        let blindings = vec![keypair.pub_key.n.rand_range().unwrap()];

        let start = ::std::time::Instant::now();
        // Proving starts, create t values
        let (ciphertext, blindings_ciphertext, r, r_tilde) =
            encrypt_and_prove_phase_1(&messages, &blindings, "test2".as_bytes(), &keypair.pub_key)
                .unwrap();

        // The verifier sends this challenge or this challenge can be created by hashing `blindings_ciphertext`
        let challenge = keypair.pub_key.n.rand_range().unwrap();

        // Proving finishes, create s values
        let r_hat =
            encrypt_and_prove_phase_2(&r, &r_tilde, &challenge, &keypair.pub_key, Some(&mut ctx))
                .unwrap();
        println!(
            "Proving time for CS verifiable encryption with single message is: {:?}",
            start.elapsed()
        );

        // m_hat will be created by the main proving protocol not this verifiable encryption module
        let m_hat = blindings[0]
            .sub(
                &(messages[0]
                    .mod_mul(
                        &challenge,
                        &keypair.pub_key.paillier_group.modulus,
                        Some(&mut ctx),
                    )
                    .unwrap()),
            )
            .unwrap();

        let start = ::std::time::Instant::now();
        // Next part is done by verifier
        let blindings_ciphertext_1 = reconstruct_blindings_ciphertext(
            &ciphertext,
            &vec![m_hat],
            &r_hat,
            &challenge,
            "test2".as_bytes(),
            &keypair.pub_key,
        )
        .unwrap();

        assert_eq!(blindings_ciphertext.u, blindings_ciphertext_1.u);
        assert_eq!(blindings_ciphertext.e[0], blindings_ciphertext_1.e[0]);
        assert_eq!(blindings_ciphertext.v, blindings_ciphertext_1.v);
        println!(
            "Verification time for CS verifiable encryption with single message is: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn prove_cs_encryption_smaller_public_key() {
        let keypair = CSKeypair::new(1).unwrap();
        let messages = vec![
            keypair.pub_key.n.rand_range().unwrap(),
            keypair.pub_key.n.rand_range().unwrap(),
        ];
        let blindings = vec![
            keypair.pub_key.n.rand_range().unwrap(),
            keypair.pub_key.n.rand_range().unwrap(),
        ];
        assert!(encrypt_and_prove_phase_1(
            &messages,
            &blindings,
            "test2".as_bytes(),
            &keypair.pub_key
        )
        .is_err());
    }

    #[test]
    fn prove_cs_encryption_incorrect_number_of_blindings() {
        // No of blindings should be same as number of messages
        let keypair = CSKeypair::new(2).unwrap();
        let messages = vec![
            keypair.pub_key.n.rand_range().unwrap(),
            keypair.pub_key.n.rand_range().unwrap(),
        ];

        // Less blindings
        let blindings_1 = vec![keypair.pub_key.n.rand_range().unwrap()];
        assert!(encrypt_and_prove_phase_1(
            &messages,
            &blindings_1,
            "test2".as_bytes(),
            &keypair.pub_key
        )
        .is_err());

        // More blindings
        let blindings_2 = vec![
            keypair.pub_key.n.rand_range().unwrap(),
            keypair.pub_key.n.rand_range().unwrap(),
            keypair.pub_key.n.rand_range().unwrap(),
        ];
        assert!(encrypt_and_prove_phase_1(
            &messages,
            &blindings_2,
            "test2".as_bytes(),
            &keypair.pub_key
        )
        .is_err());
    }

    #[test]
    fn prove_cs_encryption_multiple_messages() {
        let mut ctx = BigNumber::new_context().unwrap();

        let num_messages = 10;

        let keypair = CSKeypair::new(num_messages).unwrap();
        let messages: Vec<_> = (0..num_messages)
            .map(|_| keypair.pub_key.n.rand_range().unwrap())
            .collect();
        let ciphertext = encrypt(&messages, "test2".as_bytes(), &keypair.pub_key).unwrap();
        let decrypted_messages = decrypt(
            "test2".as_bytes(),
            &ciphertext,
            &keypair.pub_key,
            &keypair.pri_key,
        )
        .unwrap();
        assert_eq!(decrypted_messages, messages);

        let blindings: Vec<_> = (0..num_messages)
            .map(|_| keypair.pub_key.n.rand_range().unwrap())
            .collect();

        let start = ::std::time::Instant::now();
        let (ciphertext, blindings_ciphertext, r, r_tilde) =
            encrypt_and_prove_phase_1(&messages, &blindings, "test2".as_bytes(), &keypair.pub_key)
                .unwrap();

        let challenge = keypair.pub_key.n.rand_range().unwrap();

        let r_hat =
            encrypt_and_prove_phase_2(&r, &r_tilde, &challenge, &keypair.pub_key, Some(&mut ctx))
                .unwrap();
        println!(
            "Proving time for CS verifiable encryption with {} messages is: {:?}",
            num_messages,
            start.elapsed()
        );

        let mut m_hats = vec![];
        for i in 0..num_messages {
            let m_hat = blindings[i]
                .sub(
                    &(messages[i]
                        .mod_mul(
                            &challenge,
                            &keypair.pub_key.paillier_group.modulus,
                            Some(&mut ctx),
                        )
                        .unwrap()),
                )
                .unwrap();
            m_hats.push(m_hat);
        }

        let start = ::std::time::Instant::now();
        let blindings_ciphertext_1 = reconstruct_blindings_ciphertext(
            &ciphertext,
            &m_hats,
            &r_hat,
            &challenge,
            "test2".as_bytes(),
            &keypair.pub_key,
        )
        .unwrap();

        assert_eq!(blindings_ciphertext.u, blindings_ciphertext_1.u);
        for i in 0..num_messages {
            assert_eq!(blindings_ciphertext.e[i], blindings_ciphertext_1.e[i]);
        }
        assert_eq!(blindings_ciphertext.v, blindings_ciphertext_1.v);
        println!(
            "Verification time for CS verifiable encryption with {} messages is: {:?}",
            num_messages,
            start.elapsed()
        );
    }
}
