use crate::self_tests::mech_tests::*;
use crate::mechs::gen_mech::DRBG_Mechanism_Functions;

pub fn run_tests<T: DRBG_Mechanism_Functions>() -> usize{
    // if T::drbg_name() == "HMAC-DRBG" {
    //     return zeroization::test_zeroization::<T>() +
    //             kats::run_all::<T>() +
    //             nist_vectors::nist_vectors::<T>() +
    //             instantiation::hmac_instantiation::run_tests();
    // }
    // else if T::drbg_name() == "Hash-DRBG" {
    //     return zeroization::test_zeroization::<T>() +
    //             kats::run_all::<T>() +
    //             nist_vectors::nist_vectors::<T>() +
    //             instantiation::hash_instantiation::run_tests();
    // }
    // else {
    //     0
    // }

    return zeroization::test_zeroization::<T>() +
                kats::run_all::<T>() +
                nist_vectors::nist_vectors::<T>() +
                instantiation_test::run_tests::<T>();
}