use crate::{self_tests::formats, mechs::gen_mech::DRBG_Mechanism_Functions};
use super::*;

pub fn run_tests<T: DRBG_Mechanism_Functions>() -> usize {
    let mut log_message = "\n*** STARTING ".to_string();
    log_message.push_str(T::drbg_name().as_str());
    log_message.push_str(" TESTS ***\n");

    formats::write_to_log(log_message);

    return instantiation::run_tests::<T>() +
            reseed::run_tests::<T>() +
            generate::run_tests::<T>() +
            uninstantiate::run_tests::<T>();
}