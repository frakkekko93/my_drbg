use crate::self_tests::formats;
use super::*;

pub fn run_tests() -> usize {
    formats::write_to_log("\n*** STARTING HMAC-DRBG-MECH TESTS ***\n".to_string());

    return hash_kats::run_all() +
            hash_instantiation::run_tests() +
            hash_zeroization_test::test_zeroization();
}