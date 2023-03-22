use crate::{mechs::gen_mech::DRBG_Mechanism_Functions, self_tests::{hmac_mech_tests, hash_mech_tests}};
use super::zeroization;

pub fn run_tests<T: DRBG_Mechanism_Functions>() -> usize{
    if T::drbg_name() == "HMAC-DRBG" {
        return zeroization::test_zeroization::<T>() +
                hmac_mech_tests::run_all::run_tests();
    }
    else if T::drbg_name() == "Hash-DRBG" {
        return zeroization::test_zeroization::<T>() +
                hash_mech_tests::run_all::run_tests();
    }
    else {
        0
    }

}