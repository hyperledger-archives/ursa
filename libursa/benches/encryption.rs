#[macro_use]
extern crate criterion;
extern crate rand;
extern crate ursa;

use criterion::Criterion;
use rand::{thread_rng, RngCore};
use ursa::encryption::symm::prelude::*;

macro_rules! make_bench {
    ($name:ident, $algorithm:ident) => {
        fn $name(c: &mut Criterion) {
            let mut rng = thread_rng();
            for msg_len in vec![128, 1024, 16384, 1048576] {
                let mut msg = vec![0u8; msg_len];
                rng.fill_bytes(msg.as_mut_slice());
                let aad = b"Encrypt/Decrypt test";
                let encryptor = SymmetricEncryptor::<$algorithm>::default();
                c.bench_function(
                    format!(
                        "Encrypt/Decrypt for {} for {} bytes",
                        stringify!($algorithm),
                        msg_len
                    )
                    .as_str(),
                    move |b| {
                        b.iter(|| {
                            let ciphertext = encryptor.encrypt_easy(&aad[..], &msg[..]).unwrap();
                            encryptor
                                .decrypt_easy(&aad[..], ciphertext.as_slice())
                                .unwrap();
                        })
                    },
                );
            }
        }
    };
}

make_bench!(bench_aes128_cbc_hmac256, Aes128CbcHmac256);
make_bench!(bench_aes256_cbc_hmac512, Aes256CbcHmac512);
make_bench!(bench_aes128_gcm, Aes128Gcm);
make_bench!(bench_aes256_gcm, Aes256Gcm);
make_bench!(bench_xchacha20_poly1305, XChaCha20Poly1305);

criterion_group!(
    name = bench_encryption;
    config = Criterion::default();
    targets = bench_aes128_cbc_hmac256, bench_aes256_cbc_hmac512, bench_aes128_gcm, bench_aes256_gcm, bench_xchacha20_poly1305
);

criterion_main!(bench_encryption);
