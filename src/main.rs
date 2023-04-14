extern crate my_drbg;

#[allow(unused_imports)]
use sha2::*;
#[allow(unused_imports)]
use aes::*;
use rand::Rng;

// Simulates the start-up of a potential fips provider by calling the self test functions.
#[allow(dead_code)]
fn fips_sim(){
    println!("\n\n*** Simulating the start-up of FIPS provider / on-call test of DRBG. ***\n");

    let res = my_drbg::self_tests::run_tests::run_all();

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

    let byte_num = my_drbg::demos::utility::get_input();

    //Bytes are generated at a CHUNK_DIM-wide chunk ratio (CHUNK_DIM bytes at a time).
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
    my_drbg::demos::run_demo();
    // gen_vecs();

    // my_drbg::self_tests::mech_tests::nist_vectors::test_vectors::<my_drbg::mechs::ctr_mech::CtrDrbgMech<Aes128>>("AES 128", 16);
    // my_drbg::self_tests::mech_tests::nist_vectors::test_vectors::<my_drbg::mechs::ctr_mech::CtrDrbgMech<Aes192>>("AES 192", 24);
    // my_drbg::self_tests::mech_tests::nist_vectors::test_vectors::<my_drbg::mechs::ctr_mech::CtrDrbgMech<Aes256>>("AES 256", 32);
    // my_drbg::self_tests::mech_tests::nist_vectors::test_vectors::<my_drbg::mechs::ctr_mech_with_df::CtrDrbgMech_DF<Aes128>>("AES 128", 16);
    // my_drbg::self_tests::mech_tests::nist_vectors::test_vectors::<my_drbg::mechs::ctr_mech_with_df::CtrDrbgMech_DF<Aes192>>("AES 192", 24);
    // my_drbg::self_tests::mech_tests::nist_vectors::test_vectors::<my_drbg::mechs::ctr_mech_with_df::CtrDrbgMech_DF<Aes256>>("AES 256", 32);
    // my_drbg::self_tests::mech_tests::nist_vectors::test_vectors::<my_drbg::mechs::hash_mech::HashDrbgMech<Sha256>>("Sha 256", 32);
    // my_drbg::self_tests::mech_tests::nist_vectors::test_vectors::<my_drbg::mechs::hash_mech::HashDrbgMech<Sha512>>("Sha 512", 32);
    // my_drbg::self_tests::mech_tests::nist_vectors::test_vectors::<my_drbg::mechs::hmac_mech::HmacDrbgMech<Sha256>>("Sha 256", 32);
    // my_drbg::self_tests::mech_tests::nist_vectors::test_vectors::<my_drbg::mechs::hmac_mech::HmacDrbgMech<Sha512>>("Sha 512", 32);
}
