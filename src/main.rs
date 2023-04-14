extern crate my_drbg;
#[allow(unused_imports)]
use my_drbg::demos::{utility::get_input, run_demo};
use my_drbg::{self_tests::{formats, mech_tests, drbg_tests}, mechs::ctr_mech_with_df::CtrDrbgMech_DF};
#[allow(unused_imports)]
use my_drbg::{mechs::*, self_tests};
use rand::Rng;
#[allow(unused_imports)]
use sha2::*;
#[allow(unused_imports)]
use aes::*;

// Simulates the start-up of a potential fips provider by calling the self test functions.
#[allow(dead_code)]
fn fips_sim(){
    println!("\n\n*** Simulating the start-up of FIPS provider / on-call test of DRBG. ***\n");

    let res = self_tests::run_tests::run_all();

    if res != 0 {
        println!("MAIN: {res} tests have failed, see the log for more details.");
    }
    else {
        println!("MAIN: all tests have passed.");
    }
}

#[allow(dead_code)]
fn gen_vecs() {
    print!("MAIN: how many bytes do you need?: ");

    let byte_num = get_input();

    //Bytes are generated at a CHUNK_DIM-wide chunk ratio (CHUNK_DIM*8 bits at a time).
    const CHUNK_DIM: usize = 8;
    let mut chunk: [u8; CHUNK_DIM] = [0; CHUNK_DIM];

    // Generate CHUNK_DIM bytes at a time and copy the generated chunk into result.
    let mut count = 0;
    let mut end = false;
    let mut result = Vec::<u8>::new();
    while result.len() < byte_num && !end {
        rand::thread_rng().fill(&mut chunk);
        for j in 0..chunk.len() {

            // The requested number of bytes has been reached, stop generation
            if count+j >= byte_num{
                end = true;
                break;
            }
            result.push(chunk[j]);
        }
        // Next chunk.
        count += CHUNK_DIM;
    }

    println!("MAIN: here are your bytes:\n\n{:?}\n\nLen:{}\n", &result, result.len());
}

#[allow(unused_assignments)]
fn main(){  
    // fips_sim();
    // run_demo();
    // gen_vecs();

    // self_tests::mech_tests::nist_vectors::test_vectors::<mechs::ctr_mech::CtrDrbgMech<Aes128>>("AES 128", 128);
    // self_tests::mech_tests::nist_vectors::test_vectors::<mechs::ctr_mech::CtrDrbgMech<Aes192>>("AES 192", 192);
    // self_tests::mech_tests::nist_vectors::test_vectors::<mechs::ctr_mech::CtrDrbgMech<Aes256>>("AES 256", 256);
    // self_tests::mech_tests::nist_vectors::test_vectors::<mechs::hash_mech::HashDrbgMech<Sha256>>("Sha 256", 256);
    // self_tests::mech_tests::nist_vectors::test_vectors::<mechs::hash_mech::HashDrbgMech<Sha512>>("Sha 512", 256);
    // self_tests::mech_tests::nist_vectors::test_vectors::<mechs::hmac_mech::HmacDrbgMech<Sha256>>("Sha 256", 256);
    // self_tests::mech_tests::nist_vectors::test_vectors::<mechs::hmac_mech::HmacDrbgMech<Sha512>>("Sha 512", 256);

    let mut log_message = "\n*** STARTING CTR-DRBG AES-128 (DF) self-tests ***\n".to_string();
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

    assert_eq!(0, res_ctr_df);
}
