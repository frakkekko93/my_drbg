use crate::mechs::{hash_mech::HashDrbgMech, hmac_mech::HmacDrbgMech, ctr_mech::CtrDrbgMech, ctr_mech_with_df::CtrDrbgMech_DF};
use super::{drbg_tests, mech_tests, formats};
use sha2::*;
use aes::*;
use crate::drbg::drbg_conf::*;

/*  Here we are running self-tests for every DRBG and every mechanism that is available in this crate.
    These self-tests include:
    
        DRBG-TESTS: testing each function of the drbg/gen_drbg.rs module. This module is responsible for
                    handling the logic of a generic DRBG that is independent from the actual mechanisms that
                    is used in a particular instance
        
        MECH-TESTS: these tests are designed to run every function defined in the trait DRBG_Mechanisms_Functions,
                    this trait defines functionalities that are common between every DRBG mechanism used in this crate.
                    The goal of these tests is to make sure that every mechanisms is working properly.
                    Inside these tests we also run the NIST vectors associated to each specific DRBG mechanism.
*/
pub fn run_all() -> usize {
    /*  We set this variable to avoid that during self-testing the same tests are run after first
        instantiations of each mechanism. This variable is then unset once the execution of the
        overall self-tests is over.
    */
    unsafe { OVERALL_TEST_RUN = true };

    let mut log_message;
    let mut res_hash;
    let mut res_hmac;
    let mut res_ctr;
    let mut res_ctr_df;

    /*  HASH-DRBG SHA-256 */
    log_message = "\n*** STARTING Hash-DRBG Sha-256 self-tests ***\n".to_string();
    formats::write_to_log(log_message);
    res_hash =  mech_tests::run_all::run_tests::<HashDrbgMech<Sha256>>(32) +
                            drbg_tests::run_all::run_tests::<HashDrbgMech<Sha256>>(32);
    
    /*  HASH-DRBG SHA-512 */
    log_message = "\n*** STARTING Hash-DRBG Sha-512 self-tests ***\n".to_string();
    formats::write_to_log(log_message);
    res_hash +=  mech_tests::run_all::run_tests::<HashDrbgMech<Sha512>>(32) +
                            drbg_tests::run_all::run_tests::<HashDrbgMech<Sha512>>(32);

    /*  HMAC-DRBG SHA-256 */
    log_message = "\n*** STARTING HMAC-DRBG Sha-256 self-tests ***\n".to_string();
    formats::write_to_log(log_message);
    res_hmac =  mech_tests::run_all::run_tests::<HmacDrbgMech<Sha256>>(32) +
                            drbg_tests::run_all::run_tests::<HmacDrbgMech<Sha256>>(32);

    /*  HMAC-DRBG SHA-512 */
    log_message = "\n*** STARTING HMAC-DRBG Sha-512 self-tests ***\n".to_string();
    formats::write_to_log(log_message);
    res_hmac +=  mech_tests::run_all::run_tests::<HmacDrbgMech<Sha512>>(32) +
                            drbg_tests::run_all::run_tests::<HmacDrbgMech<Sha512>>(32);

    /*  CTR-DRBG (no DF) AES-128 */
    log_message = "\n*** STARTING CTR-DRBG AES-128 (no DF) self-tests ***\n".to_string();
    formats::write_to_log(log_message);
    res_ctr =  mech_tests::run_all::run_tests::<CtrDrbgMech<Aes128>>(16) +
                            drbg_tests::run_all::run_tests::<CtrDrbgMech<Aes128>>(16);

    /*  CTR-DRBG (no DF) AES-192 */
    log_message = "\n*** STARTING CTR-DRBG AES-192 (no DF) self-tests ***\n".to_string();
    formats::write_to_log(log_message);
    res_ctr +=  mech_tests::run_all::run_tests::<CtrDrbgMech<Aes192>>(24) +
                            drbg_tests::run_all::run_tests::<CtrDrbgMech<Aes192>>(24);                

    /*  CTR-DRBG (no DF) AES-256 */
    log_message = "\n*** STARTING CTR-DRBG AES-256 (no DF) self-tests ***\n".to_string();
    formats::write_to_log(log_message);
    res_ctr +=  mech_tests::run_all::run_tests::<CtrDrbgMech<Aes256>>(32) +
                            drbg_tests::run_all::run_tests::<CtrDrbgMech<Aes256>>(32);

    /*  CTR-DRBG (DF) AES-128 */
    log_message = "\n*** STARTING CTR-DRBG AES-128 (DF) self-tests ***\n".to_string();
    formats::write_to_log(log_message);
    res_ctr_df =  mech_tests::run_all::run_tests::<CtrDrbgMech_DF<Aes128>>(16) +
                            drbg_tests::run_all::run_tests::<CtrDrbgMech_DF<Aes128>>(16);

    /*  CTR-DRBG (DF) AES-192 */
    log_message = "\n*** STARTING CTR-DRBG AES-192 (DF) self-tests ***\n".to_string();
    formats::write_to_log(log_message);
    res_ctr_df +=  mech_tests::run_all::run_tests::<CtrDrbgMech_DF<Aes192>>(24) +
                            drbg_tests::run_all::run_tests::<CtrDrbgMech_DF<Aes192>>(24);                

    /*  CTR-DRBG (DF) AES-256 */
    log_message = "\n*** STARTING CTR-DRBG AES-256 (DF) self-tests ***\n".to_string();
    formats::write_to_log(log_message);
    res_ctr_df +=  mech_tests::run_all::run_tests::<CtrDrbgMech_DF<Aes256>>(32) +
                            drbg_tests::run_all::run_tests::<CtrDrbgMech_DF<Aes256>>(32);

    unsafe { OVERALL_TEST_RUN = false };
    return res_hash + res_hmac + res_ctr + res_ctr_df;         
}