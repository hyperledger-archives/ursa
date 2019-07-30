use amcl_miracl::arch::Chunk;
use amcl_miracl::bls381::big::BIG;
use amcl_miracl::rand::RAND;
use rand::rngs::EntropyRng;
use rand::RngCore;

pub fn get_seeded_rng(entropy_size: usize, rng: Option<EntropyRng>) -> RAND {
    // initialise from at least 128 byte string of raw random entropy
    let mut entropy = vec![0; entropy_size];
    match rng {
        Some(mut rng) => rng.fill_bytes(&mut entropy.as_mut_slice()),
        None => {
            let mut rng = EntropyRng::new();
            rng.fill_bytes(&mut entropy.as_mut_slice());
        }
    }
    let mut r = RAND::new();
    r.clean();
    r.seed(entropy_size, &entropy);
    r
}

pub fn random_big_number(order: &[Chunk], rng: Option<EntropyRng>) -> BIG {
    // initialise from at least 128 byte string of raw random entropy
    let entropy_size = 256;
    let mut r = get_seeded_rng(entropy_size, rng);
    BIG::randomnum(&BIG::new_ints(&order), &mut r)
}
