extern crate my_drbg;
use aes::*;
use my_drbg::{self_tests, mechs::gen_mech::DRBG_Mechanism_Functions};
#[allow(unused_imports)]
use my_drbg::demos::*; 
use my_drbg::mechs::ctr_mech::CtrDrbgMech;
use rand::Rng;

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

#[allow(unused_assignments)]
fn main(){  
    //fips_sim();
    //run_demo();
    let entropy_part:[u8; 32] = rand::thread_rng().gen();
    let entropy_part2: [u8; 16] = rand::thread_rng().gen();
    let mut entropy = Vec::<u8>::new();
    entropy.append(&mut entropy_part.to_vec());
    entropy.append(&mut entropy_part2.to_vec());
    let res = CtrDrbgMech::<Aes256>::new(&entropy, "Trial nonce".as_bytes(), "Trial nonce".as_bytes());

    let _drbg;
    match res {
        None => {
            println!("MAIN: instantiation failed.");
        }
        Some(inst) => {
            println!("MAIN: instantiation succeeded.");
            _drbg = inst;
        }
    }
}