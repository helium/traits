//! Tests for `PasswordHash` encoding/decoding.
//!
//! Each test implements a different permutation of the possible combinations
//! of the string encoding, and ensures password hashes round trip under each
//! of the conditions.

use core::convert::TryInto;
use password_hash::{Ident, Params, PasswordHash};

const EXAMPLE_ALGORITHM: Ident<'static> = Ident::new("argon2d");
const EXAMPLE_SALT: &str = "saltsaltsaltsaltsalt";
const EXAMPLE_HASH: &[u8] = &[
    0x85, 0xab, 0x21, 0x85, 0xab, 0x21, 0x85, 0xab, 0x21, 0x85, 0xab, 0x21, 0x85, 0xab, 0x21, 0x85,
    0xab, 0x21, 0x85, 0xab, 0x21, 0x85, 0xab, 0x21, 0x85, 0xab, 0x21, 0x85, 0xab, 0x21, 0x85, 0xab,
];

/// Example parameters
fn example_params() -> Params<'static> {
    Params::from_slice(&[
        ("a".try_into().unwrap(), 1i32.into()),
        ("b".try_into().unwrap(), 2i32.into()),
        ("c".try_into().unwrap(), 3i32.into()),
    ])
    .unwrap()
}

#[test]
fn algorithm_alone() {
    let ph = PasswordHash {
        algorithm: EXAMPLE_ALGORITHM,
        version: None,
        params: Params::new(),
        salt: None,
        hash: None,
    };

    let s = ph.to_string();
    assert_eq!(s, "$argon2d");

    let ph2 = PasswordHash::new(&s).unwrap();
    assert_eq!(ph, ph2);
}

#[test]
fn params() {
    let ph = PasswordHash {
        algorithm: EXAMPLE_ALGORITHM,
        version: None,
        params: example_params(),
        salt: None,
        hash: None,
    };

    let s = ph.to_string();
    assert_eq!(s, "$argon2d$a=1,b=2,c=3");

    let ph2 = PasswordHash::new(&s).unwrap();
    assert_eq!(ph, ph2);
}

#[test]
fn salt() {
    let ph = PasswordHash {
        algorithm: EXAMPLE_ALGORITHM,
        version: None,
        params: Params::new(),
        salt: Some(EXAMPLE_SALT.try_into().unwrap()),
        hash: None,
    };

    let s = ph.to_string();
    assert_eq!(s, "$argon2d$saltsaltsaltsaltsalt");

    let ph2 = PasswordHash::new(&s).unwrap();
    assert_eq!(ph, ph2);
}

#[test]
fn one_param_and_salt() {
    let params = Params::from_slice(&[("a".try_into().unwrap(), 1i32.into())]).unwrap();

    let ph = PasswordHash {
        algorithm: EXAMPLE_ALGORITHM,
        version: None,
        params,
        salt: Some(EXAMPLE_SALT.try_into().unwrap()),
        hash: None,
    };

    let s = ph.to_string();
    assert_eq!(s, "$argon2d$a=1$saltsaltsaltsaltsalt");

    let ph2 = PasswordHash::new(&s).unwrap();
    assert_eq!(ph, ph2);
}

#[test]
fn params_and_salt() {
    let ph = PasswordHash {
        algorithm: EXAMPLE_ALGORITHM,
        version: None,
        params: example_params(),
        salt: Some(EXAMPLE_SALT.try_into().unwrap()),
        hash: None,
    };

    let s = ph.to_string();
    assert_eq!(s, "$argon2d$a=1,b=2,c=3$saltsaltsaltsaltsalt");

    let ph2 = PasswordHash::new(&s).unwrap();
    assert_eq!(ph, ph2);
}

#[test]
fn salt_and_hash() {
    let ph = PasswordHash {
        algorithm: EXAMPLE_ALGORITHM,
        version: None,
        params: Params::default(),
        salt: Some(EXAMPLE_SALT.try_into().unwrap()),
        hash: Some(EXAMPLE_HASH.try_into().unwrap()),
    };

    let s = ph.to_string();
    assert_eq!(
        s,
        "$argon2d$saltsaltsaltsaltsalt$hashhashhashhashhashhashhashhashhashhashhas"
    );

    let ph2 = PasswordHash::new(&s).unwrap();
    assert_eq!(ph, ph2);
}

#[test]
fn all_fields() {
    let ph = PasswordHash {
        algorithm: EXAMPLE_ALGORITHM,
        version: Some(19),
        params: example_params(),
        salt: Some(EXAMPLE_SALT.try_into().unwrap()),
        hash: Some(EXAMPLE_HASH.try_into().unwrap()),
    };

    let s = ph.to_string();
    assert_eq!(
        s,
        "$argon2d$v=19$a=1,b=2,c=3$saltsaltsaltsaltsalt$hashhashhashhashhashhashhashhashhashhashhas"
    );

    let ph2 = PasswordHash::new(&s).unwrap();
    assert_eq!(ph, ph2);
}
