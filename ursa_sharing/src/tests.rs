// Copyright 2020 Hyperledger Ursa Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use super::{
    error::SharingResult,
    feldman::{FeldmanVerifier, Scheme as FeldmanVss},
    pedersen::{PedersenVssResult, Scheme as PedersenVss},
    shamir::{Scheme, Share},
    Field, Group,
};
use rand::prelude::*;

/// Test invalid split arguments
pub fn split_invalid_args<S: Field>() {
    assert!(Scheme::new(0, 0).is_err());
    assert!(Scheme::new(3, 2).is_err());
    assert!(Scheme::new(1, 10).is_err());
    let scheme = Scheme::new(2, 3).unwrap();
    let mut rng = thread_rng();
    assert!(scheme.split_secret(&mut rng, &S::zero()).is_err());
    assert!(S::from_bytes(&[65u8; 1000]).is_err());
}

/// Test that combining should fail
pub fn combine_invalid<S: Field>() {
    let scheme = Scheme::new(2, 3).unwrap();
    // No shares
    let shares: Vec<Share> = Vec::new();
    assert!(scheme.combine_shares::<S, S>(shares.as_slice()).is_err());

    // No secret
    let shares = vec![Share::new(1, &[]), Share::new(2, &[])];
    assert!(scheme.combine_shares::<S, S>(shares.as_slice()).is_err());

    // Zero identifier
    let shares = vec![Share::new(0, b"abc"), Share::new(2, b"abc")];
    assert!(scheme.combine_shares::<S, S>(shares.as_slice()).is_err());

    // Duplicate shares
    let shares = vec![Share::new(1, b"abc"), Share::new(1, b"abc")];
    assert!(scheme.combine_shares::<S, S>(shares.as_slice()).is_err());
}

/// Test recombining for a single set of shares
pub fn combine_single<S: Field, R: Group<S>>() {
    let scheme = Scheme::new(2, 3).unwrap();
    let secret = S::from_bytes(b"hello").unwrap();

    let mut rng = thread_rng();

    let res = scheme.split_secret(&mut rng, &secret);
    assert!(res.is_ok(), "{:?}", res);
    let shares = res.unwrap();

    let res = scheme.combine_shares::<S, S>(shares.as_slice());
    assert!(res.is_ok());
    let secret_1 = res.unwrap();

    assert_eq!(secret.to_bytes(), secret_1.to_bytes());

    // Feldman test
    let scheme = FeldmanVss::new(2, 3).unwrap();
    let secret = S::from_bytes(b"hello").unwrap();

    let res: SharingResult<(FeldmanVerifier<S, R>, Vec<Share>)> =
        scheme.split_secret(&mut rng, &secret, None);
    assert!(res.is_ok());
    let (verifier, shares) = res.unwrap();

    for s in &shares {
        assert!(scheme.verify_share(s, &verifier).is_ok());
    }

    let res = scheme.combine_shares::<S, S>(shares.as_slice());
    assert!(res.is_ok());
    let secret_1 = res.unwrap();

    assert_eq!(secret.to_bytes(), secret_1.to_bytes());

    // Pedersen test
    let scheme = PedersenVss::new(2, 3).unwrap();
    let secret = S::from_bytes(b"hello").unwrap();

    let res: SharingResult<PedersenVssResult<S, R>> =
        scheme.split_secret(&mut rng, &secret, None, None);
    assert!(res.is_ok());
    let pedersen_res = res.unwrap();

    for i in 0..(&pedersen_res.secret_shares).len() {
        assert!(scheme
            .verify_share(
                &pedersen_res.secret_shares[i],
                &pedersen_res.blinding_shares[i],
                &pedersen_res.verifier
            )
            .is_ok());
    }

    let res = scheme.combine_shares::<S, S>(shares.as_slice());
    assert!(res.is_ok());
    let secret_1 = res.unwrap();

    assert_eq!(secret.to_bytes(), secret_1.to_bytes());
}

/// Test recombining with all possible subsets of shares
pub fn combine_all_combinations<S: Field, R: Group<S>>() {
    let secret = S::from_bytes(b"hello").unwrap();
    let scheme = Scheme::new(3, 5).unwrap();
    let feldman_vss = FeldmanVss::new(3, 5).unwrap();
    let pedersen_vss = PedersenVss::new(3, 5).unwrap();

    let mut rng = thread_rng();

    let res = scheme.split_secret(&mut rng, &secret);
    assert!(res.is_ok());
    let shamir_shares = res.unwrap();

    let res: SharingResult<(FeldmanVerifier<S, R>, Vec<Share>)> =
        feldman_vss.split_secret(&mut rng, &secret, None);
    assert!(res.is_ok());
    let (verifier, feldman_shares) = res.unwrap();

    for (s, b) in feldman_shares.iter().zip(shamir_shares.iter()) {
        // Assert feldman share is good
        assert!(feldman_vss.verify_share(s, &verifier).is_ok());
        // Assert share from different polynomial is bad
        assert!(feldman_vss.verify_share(b, &verifier).is_err());
    }

    let res: SharingResult<PedersenVssResult<S, R>> =
        pedersen_vss.split_secret(&mut rng, &secret, None, None);
    assert!(res.is_ok());
    let pedersen_res = res.unwrap();

    for (s, b) in pedersen_res
        .secret_shares
        .iter()
        .zip(pedersen_res.blinding_shares.iter())
    {
        assert!(pedersen_vss
            .verify_share(s, b, &pedersen_res.verifier)
            .is_ok());
    }

    // There is 5*4*3 possible choices
    // try them all. May take a while
    for i in 0..5 {
        for j in 0..5 {
            if i == j {
                continue;
            }

            for k in 0..5 {
                if k == i || k == j {
                    continue;
                }
                let parts = &[
                    shamir_shares[i].clone(),
                    shamir_shares[j].clone(),
                    shamir_shares[k].clone(),
                ];

                let res = scheme.combine_shares::<S, S>(parts);
                assert!(res.is_ok());
                let secret_1 = res.unwrap();
                assert!(secret.to_bytes() == secret_1.to_bytes());

                let parts = &[
                    feldman_shares[i].clone(),
                    feldman_shares[j].clone(),
                    feldman_shares[k].clone(),
                ];

                let res = feldman_vss.combine_shares::<S, S>(parts);
                assert!(res.is_ok());
                let secret_1 = res.unwrap();
                assert!(secret.to_bytes() == secret_1.to_bytes());

                let parts = &[
                    pedersen_res.secret_shares[i].clone(),
                    pedersen_res.secret_shares[j].clone(),
                    pedersen_res.secret_shares[k].clone(),
                ];
                let res = pedersen_vss.combine_shares::<S, S>(parts);
                assert!(res.is_ok());
                let secret_1 = res.unwrap();
                assert!(secret.to_bytes() == secret_1.to_bytes());

                let parts = &[
                    pedersen_res.blinding_shares[i].clone(),
                    pedersen_res.blinding_shares[j].clone(),
                    pedersen_res.blinding_shares[k].clone(),
                ];
                let res = pedersen_vss.combine_shares::<S, S>(parts);
                assert!(res.is_ok());
                let secret_1 = res.unwrap();
                assert!(pedersen_res.blinding.to_bytes() == secret_1.to_bytes());
            }
        }
    }
}
