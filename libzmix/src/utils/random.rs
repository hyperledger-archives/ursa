use rand::RngCore;
use rand::rngs::EntropyRng;
use amcl::rand::RAND;
use amcl::arch::Chunk;
use amcl::bls381::big::BIG;


pub fn get_seeded_RNG(entropy_size: usize, rng: Option<EntropyRng>) -> RAND {
    // initialise from at least 128 byte string of raw random entropy
    let mut entropy = vec![0; entropy_size];
    match rng {
        Some(mut rng) =>  rng.fill_bytes(&mut entropy.as_mut_slice()),
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
    let mut r = get_seeded_RNG(entropy_size, rng);
    BIG::randomnum(&BIG::new_ints(&order), &mut r)
}
