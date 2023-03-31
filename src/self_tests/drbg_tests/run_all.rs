use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use super::*;

pub fn run_tests<T: DRBG_Mechanism_Functions + 'static>(strength: usize) -> usize {
    return instantiation::run_tests::<T>(strength) +
            reseed::run_tests::<T>(strength) +
            generate::run_tests::<T>(strength) +
            uninstantiate::run_tests::<T>(strength);
}