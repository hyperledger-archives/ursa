use amcl::bls381::ecp::ECP;
use amcl::bls381::big::{BIG, MODBYTES};
use amcl::bls381::rom::CURVE_ORDER;

use hash_functions::HashFunction;
use hash_functions::bls12_381_hash::BLS12_381_SHA256_G1;

use commitments::CommitmentScheme;
use commitments::CommitmentError;
use utils::random::random_big_number;

const SETUP_SEED_G1: &'static str = "Hyperledger-Cryptolib-Pedersen-Commitment-BLS-12-381-G1";
const GROUP_G1_SIZE: usize = 2 * MODBYTES + 1;

struct PedersenCommitmentBls12381Sha256G1 {}

impl CommitmentScheme for PedersenCommitmentBls12381Sha256G1 {
    // Returns `num_elements` + 1 generators. This is useful when committing to several messages say
    // m_1, m_2, m_3, and so on. `setup` will this output g_1, g_2, g_3, g_4 and so on which can then be
    // used for commitment f(g_1, g_2, g_3, g_4, ..., m_1, m_2, m_3...)
    fn setup(num_elements: usize) -> Result<Vec<Vec<u8>>, CommitmentError> {
        if num_elements == 0 {
            return Err(CommitmentError::ZeroCountInPedersenSetup(String::from("num_elements cannot be 0")))
        }
        let mut generators: Vec<ECP> = vec![];
        let mut hf = BLS12_381_SHA256_G1::new(None)?;
        hf.update(SETUP_SEED_G1.as_bytes());
        for _ in 0..num_elements+1 {
            generators.push(hf.hash_on_group());
            let m = hf.digest(None)?;
            hf.update(&m);
        }
        Ok(generators.iter_mut().map(|g| {
            let mut temp: [u8; GROUP_G1_SIZE] = [0; GROUP_G1_SIZE];
            g.tobytes(&mut temp, false);
            temp.to_vec()
            }).collect()
        )
    }

    fn commit(generators: &[&[u8]], messages: &[&[u8]]) -> Result<(Vec<u8>, Vec<u8>), CommitmentError> {
        match Self::verify_generator_message_count(generators, messages) {
            Ok(_) => (),
            Err(err) => return Err(err)
        }

        let mut commitment = Self::commit_to_messages(generators, messages)?;
        let idx = messages.len();
        let gen = Self::get_point_from_bytes(generators[idx])?;
        let mut blinding_factor_bytes: [u8; MODBYTES] = [0; MODBYTES];

        let mut blinding_factor = random_big_number(&CURVE_ORDER, None);
        commitment.add(&gen.mul(&blinding_factor));

        blinding_factor.tobytes(&mut blinding_factor_bytes);

        // Zero the bytes of blinding factor.
        // TODO: A better mechanism is needed. Use either libsodium or some other library that makes sure that `blinding_factor`
        // was never swapped to disk or was core dumped.
        blinding_factor.zero();

        let mut comm_bytes: [u8; GROUP_G1_SIZE] = [0; GROUP_G1_SIZE];
        commitment.tobytes(&mut comm_bytes, false);

        Ok((comm_bytes.to_vec(), blinding_factor_bytes.to_vec()))
    }

    fn verify(commitment: &[u8], opening: &[u8], generators: &[&[u8]], messages: &[&[u8]]) -> Result<bool, CommitmentError> {
        let mut commitment = Self::get_point_from_bytes(commitment)?;
        let opening = Self::get_bignum_from_bytes(opening)?;

        match Self::verify_generator_message_count(generators, messages) {
            Ok(_) => (),
            Err(err) => return Err(err)
        }

        let mut to_check = Self::commit_to_messages(generators, messages)?;
        let idx = messages.len();
        let gen = Self::get_point_from_bytes(generators[idx])?;
        to_check.add(&gen.mul(&opening));
        Ok(to_check.equals(&mut commitment))
    }
}

impl PedersenCommitmentBls12381Sha256G1 {
    // Check that there are enough generators for messages
    fn verify_generator_message_count(generators: &[&[u8]], messages: &[&[u8]]) -> Result<(), CommitmentError> {
        if messages.len() < 1 {
            return Err(CommitmentError::ZeroMessageCount(String::from("messages cannot be empty")))
        }
        // Extra generators will not be used.
        if generators.len() < (messages.len() + 1) {
            return Err(CommitmentError::InvalidGeneratorCount(generators.len(), messages.len()))
        }
        Ok(())
    }
    
    fn get_point_from_bytes(point_bytes: &[u8]) -> Result<ECP, CommitmentError> {
        if point_bytes.len() != GROUP_G1_SIZE {
            return Err(CommitmentError::InvalidPointSize(point_bytes.len(), GROUP_G1_SIZE))
        }
        Ok(ECP::frombytes(point_bytes))
    }

    fn get_bignum_from_bytes(bignum_bytes: &[u8]) -> Result<BIG, CommitmentError> {
        if bignum_bytes.len() != MODBYTES {
            return Err(CommitmentError::InvalidBigNumSize(bignum_bytes.len(), MODBYTES))
        }
        Ok(BIG::frombytes(bignum_bytes))
    }

    // Used during both commitment and verification
    fn commit_to_messages(generators: &[&[u8]], messages: &[&[u8]]) -> Result<ECP, CommitmentError> {
        let mut commitment = ECP::new();
        for i in 0..messages.len() {
            let gen = Self::get_point_from_bytes(generators[i])?;
            let mut hf = BLS12_381_SHA256_G1::new(None)?;
            hf.update(messages[i]);
            let msg = hf.digest(None)?;
            let c = gen.mul(&BIG::frombytes(&msg));
            commitment.add(&c);
        }
        Ok(commitment)
    }
}

// Alternate implementation

/*
impl<Group> CommitmentScheme for PedersenCommitment {
    fn setup(num_elements: u32) -> Vec<Group::Element> {
        unimplemented!();
    }
}
*/
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn check_g1_elem_length(elem: &[u8]) {
        assert_eq!(elem.len(), GROUP_G1_SIZE);
    }

    fn check_bignum_elem_length(elem: &[u8]) {
        assert_eq!(elem.len(), MODBYTES);
    }

    #[test]
    fn test_setup() {
        assert!(PedersenCommitmentBls12381Sha256G1::setup(0).is_err());

        for l in vec![1, 2, 3, 10, 100] {
            let result = PedersenCommitmentBls12381Sha256G1::setup(l).unwrap();
            assert_eq!(result.len(), l+1);

            let mut gens: HashSet<Vec<u8>> = HashSet::new();

            for r in result {
                // All generators have valid size
                check_g1_elem_length(&r);

                // All generators can be used to create the group element
                ECP::frombytes(&r);

                gens.insert(r);
            }

            // All generators are distinct
            assert_eq!(gens.len(), l+1);
        }
    }

    #[test]
    fn test_commit() {
        let gens_1 = PedersenCommitmentBls12381Sha256G1::setup(1).unwrap();
        let gens_1: Vec<&[u8]> = gens_1.iter().map(|g|g.as_slice()).collect();
        let msgs_1 = vec!["hello".as_bytes(), "world".as_bytes()];

        // No messages
        assert!(PedersenCommitmentBls12381Sha256G1::commit(&gens_1,
                                                           &vec![]).is_err());
        // Insufficient number of generators
        assert!(PedersenCommitmentBls12381Sha256G1::commit(&gens_1,
                                                           &msgs_1).is_err());

        // Extra bytes in one of the generator
        let mut gens_2 = PedersenCommitmentBls12381Sha256G1::setup(1).unwrap();
        let mut v = gens_2[1].clone();
        v.push(8);
        gens_2[1] = v;
        let msgs_2 = vec!["hello world".as_bytes()];
        let gens_2: Vec<&[u8]> = gens_2.iter().map(|g|g.as_slice()).collect();
        assert!(PedersenCommitmentBls12381Sha256G1::commit(&gens_2,
                                                           &msgs_2).is_err());

        let msgs = vec!["hello world", "going to die now", "i am dead"];

        for i in 0..msgs.len() {
            let gens = PedersenCommitmentBls12381Sha256G1::setup(i+1).unwrap();
            let gens: Vec<&[u8]> = gens.iter().map(|g|g.as_slice()).collect();
            let m: Vec<&[u8]> = msgs.iter().take(i+1).map(|msg| msg.as_bytes()).collect();
            let (c, b) = PedersenCommitmentBls12381Sha256G1::commit(&gens,
                                                                    &m).unwrap();
            check_g1_elem_length(&c);
            check_bignum_elem_length(&b);
        }
    }

    #[test]
    fn test_verify() {
        let msgs = vec!["hello world", "going to die now", "i am dead"];

        let msg_list_producing_error = vec!["hello world", "going to die now", "i am dead", "extra message"];

        assert!(msg_list_producing_error.len() > msgs.len());

        let m_err: Vec<&[u8]> = msg_list_producing_error.iter().map(|msg| msg.as_bytes()).collect();

        for i in 0..msgs.len() {
            let gens_ = PedersenCommitmentBls12381Sha256G1::setup(i+1).unwrap();
            let gens: Vec<&[u8]> = gens_.iter().map(|g|g.as_slice()).collect();
            let m: Vec<&[u8]> = msgs.iter().take(i+1).map(|msg| msg.as_bytes()).collect();
            let (mut c, mut b) = PedersenCommitmentBls12381Sha256G1::commit(&gens,
                                                                            &m).unwrap();
            check_g1_elem_length(&c);
            check_bignum_elem_length(&b);
            assert!(PedersenCommitmentBls12381Sha256G1::verify(&c, &b, &gens, &m).unwrap());

            // No messages
            assert!(PedersenCommitmentBls12381Sha256G1::verify(&c, &b, &gens, &vec![]).is_err());

            // Insufficient number of generators
            assert!(PedersenCommitmentBls12381Sha256G1::verify(&c, &b, &gens, &m_err).is_err());

            // Extra bytes in one of the commitment
            let mut c_1 = c.clone();
            c_1.push(10);

            assert!(PedersenCommitmentBls12381Sha256G1::verify(&c_1, &b, &gens, &m).is_err());

            // Extra bytes in one of the opening
            let mut b_1 = b.clone();
            b_1.push(11);

            assert!(PedersenCommitmentBls12381Sha256G1::verify(&c, &b_1, &gens, &m).is_err());

            // Extra bytes in one of the commitment and opening
            assert!(PedersenCommitmentBls12381Sha256G1::verify(&c_1, &b_1, &gens, &m).is_err());
        }
    }
}
