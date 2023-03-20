extern crate my_drbg;
use my_drbg::drbgs::gen_drbg::{DRBG, DRBG_Functions};
use my_drbg::mechs::hmac_mech::HmacDrbgMech;
use std::ascii::escape_default;
use std::str;
use sha2::*;

//  Function that converts a byte array into a string in order to be printed
#[allow(dead_code)]
fn show(bs: &[u8]) -> String {
    let mut visible = String::new();
    for &b in bs {
        let part: Vec<u8> = escape_default(b).collect();
        visible.push_str(str::from_utf8(&part).unwrap());
    }
    visible
}

// Simulates the start-up of a potential fips provider by calling the self test functions.
#[allow(dead_code)]
fn fips_sim(){
    println!("*** Simulating the start-up of FIPS provider / on-call test of HMAC-DRBG. ***\n");

    let res = DRBG::<HmacDrbgMech::<Sha256>>::new(256, None);

    let mut drbg;
    match res {
        Err(err) => {
            panic!("MAIN: HMAC-DRBG instantiation failed with error: {}.", err);
        }
        Ok(inst) => {
            println!("MAIN: HMAC-DRBG instantiation succeeded.");
            drbg = inst;
        }
    }

    println!("MAIN: running HMAC-DRBG self-tests...");
    let test_res = drbg.run_self_tests();

    if test_res != 0 {
        println!("MAIN: some self test has failed, see log file for more info.");
    }
    else {
        println!("MAIN: all HMAC-DRBG health tests have passed.")
    }
}

fn main(){  
    fips_sim();
}