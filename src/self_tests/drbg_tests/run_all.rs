use crate::{mechs::gen_mech::DRBG_Mechanism_Functions};
use super::*;

pub fn run_tests<T: DRBG_Mechanism_Functions>() -> usize {
    return instantiation::run_tests::<T>() +
            reseed::run_tests::<T>() +
            generate::run_tests::<T>() +
            uninstantiate::run_tests::<T>();
}