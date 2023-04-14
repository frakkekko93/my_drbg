use crate::mechs::{hash_mech::HashDrbgMech, hmac_mech::HmacDrbgMech, ctr_mech::CtrDrbgMech, ctr_mech_with_df::CtrDrbgMech_DF};
use super::{drbg_tests, mech_tests, formats};
use sha2::*;
use aes::*;

pub fn run_all() -> usize {

    let mut log_message = "\n*** STARTING Hash-DRBG Sha-256 self-tests ***\n".to_string();
    formats::write_to_log(log_message);

    let mut res_hash =  mech_tests::run_all::run_tests::<HashDrbgMech<Sha256>>(256) +
                            drbg_tests::run_all::run_tests::<HashDrbgMech<Sha256>>(256);
    
    log_message = "\n*** STARTING Hash-DRBG Sha-512 self-tests ***\n".to_string();
    formats::write_to_log(log_message);

    res_hash +=  mech_tests::run_all::run_tests::<HashDrbgMech<Sha512>>(256) +
                            drbg_tests::run_all::run_tests::<HashDrbgMech<Sha512>>(256);

    log_message = "\n*** STARTING HMAC-DRBG Sha-256 self-tests ***\n".to_string();
    formats::write_to_log(log_message);

    let mut res_hmac =  mech_tests::run_all::run_tests::<HmacDrbgMech<Sha256>>(256) +
                            drbg_tests::run_all::run_tests::<HmacDrbgMech<Sha256>>(256);

    log_message = "\n*** STARTING HMAC-DRBG Sha-512 self-tests ***\n".to_string();
    formats::write_to_log(log_message);

    res_hmac +=  mech_tests::run_all::run_tests::<HmacDrbgMech<Sha512>>(256) +
                            drbg_tests::run_all::run_tests::<HmacDrbgMech<Sha512>>(256);

    log_message = "\n*** STARTING CTR-DRBG AES-128 (no DF) self-tests ***\n".to_string();
    formats::write_to_log(log_message);

    let mut res_ctr =  mech_tests::run_all::run_tests::<CtrDrbgMech<Aes128>>(128) +
                            drbg_tests::run_all::run_tests::<CtrDrbgMech<Aes128>>(128);

    log_message = "\n*** STARTING CTR-DRBG AES-192 (no DF) self-tests ***\n".to_string();
    formats::write_to_log(log_message);

    res_ctr +=  mech_tests::run_all::run_tests::<CtrDrbgMech<Aes192>>(192) +
                            drbg_tests::run_all::run_tests::<CtrDrbgMech<Aes192>>(192);                

    log_message = "\n*** STARTING CTR-DRBG AES-256 (no DF) self-tests ***\n".to_string();
    formats::write_to_log(log_message);

    res_ctr +=  mech_tests::run_all::run_tests::<CtrDrbgMech<Aes256>>(256) +
                            drbg_tests::run_all::run_tests::<CtrDrbgMech<Aes256>>(256);

    log_message = "\n*** STARTING CTR-DRBG AES-128 (DF) self-tests ***\n".to_string();
    formats::write_to_log(log_message);

    let mut res_ctr_df =  mech_tests::run_all::run_tests::<CtrDrbgMech_DF<Aes128>>(128) +
                            drbg_tests::run_all::run_tests::<CtrDrbgMech_DF<Aes128>>(128);

    log_message = "\n*** STARTING CTR-DRBG AES-192 (DF) self-tests ***\n".to_string();
    formats::write_to_log(log_message);

    res_ctr_df +=  mech_tests::run_all::run_tests::<CtrDrbgMech_DF<Aes192>>(192) +
                            drbg_tests::run_all::run_tests::<CtrDrbgMech_DF<Aes192>>(192);                

    log_message = "\n*** STARTING CTR-DRBG AES-256 (DF) self-tests ***\n".to_string();
    formats::write_to_log(log_message);

    res_ctr_df +=  mech_tests::run_all::run_tests::<CtrDrbgMech_DF<Aes256>>(256) +
                            drbg_tests::run_all::run_tests::<CtrDrbgMech_DF<Aes256>>(256);

    return res_hash + res_hmac + res_ctr + res_ctr_df;         
}