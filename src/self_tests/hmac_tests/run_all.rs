use crate::self_tests::formats;
use super::*;

pub fn run_tests() -> usize {
    formats::write_to_log("\n*** STARTING HMAC-DRBG TESTS ***\n".to_string());

    return instantiation::run_tests() +
            reseed::run_tests();
}