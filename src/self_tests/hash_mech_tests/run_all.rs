use crate::self_tests::formats;
use super::*;

pub fn run_tests() -> usize {
    formats::write_to_log("\n*** STARTING Hash-DRBG-MECH TESTS ***\n".to_string());

    return hash_kats::run_all() +
            hash_instantiation::run_tests();
}