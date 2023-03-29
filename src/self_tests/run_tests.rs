use sha2::Sha256;
use aes::Aes256;

use crate::mechs::{hash_mech::HashDrbgMech, hmac_mech::HmacDrbgMech, ctr_mech::CtrDrbgMech};

use super::{drbg_tests, mech_tests, formats};

pub fn run_all() -> usize {

    let mut log_message = "\n*** STARTING Hash-DRBG self-tests ***\n".to_string();
    formats::write_to_log(log_message);

    let res_hash =  mech_tests::run_all::run_tests::<HashDrbgMech<Sha256>>() +
                            drbg_tests::run_all::run_tests::<HashDrbgMech<Sha256>>();

    log_message = "\n*** STARTING HMAC-DRBG self-tests ***\n".to_string();
    formats::write_to_log(log_message);

    let res_hmac =  mech_tests::run_all::run_tests::<HmacDrbgMech<Sha256>>() +
                            drbg_tests::run_all::run_tests::<HmacDrbgMech<Sha256>>();

    log_message = "\n*** STARTING CTR-DRBG self-tests ***\n".to_string();
    formats::write_to_log(log_message);

    let res_ctr =  mech_tests::run_all::run_tests::<CtrDrbgMech<Aes256>>() +
                            drbg_tests::run_all::run_tests::<CtrDrbgMech<Aes256>>();

    return res_hash + res_hmac + res_ctr;         
}