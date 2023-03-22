use crate::self_tests::formats;
use super::*;

pub fn run_tests() -> usize {
    formats::write_to_log("\n*** STARTING HMAC-DRBG-MECH TESTS ***\n".to_string());

    return hmac_kats::run_all() +
            hmac_instantiation::run_tests() +
            hmac_zeroization_test::test_zeroization();
}