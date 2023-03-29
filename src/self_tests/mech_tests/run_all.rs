use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::self_tests::mech_tests::*;

pub fn run_tests<T: DRBG_Mechanism_Functions>() -> usize{
    return instantiation_test::run_tests::<T>() + 
            generate_test::run_tests::<T>() +
            reseed_test::run_tests::<T>() +
            zeroization_test::test_zeroization::<T>() +
            kats::run_all::<T>() +
            nist_vectors::test_vectors::<T>();
}