extern crate my_drbg;
use my_drbg::drbgs::gen_drbg::{DRBG, DRBG_Functions};
use my_drbg::mechs::gen_mech::DRBG_Mechanism_Functions;
use my_drbg::mechs::hash_mech::HashDrbgMech;
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

fn test_hash() {
    let entropy = "Trial entropy".as_bytes();
    let nonce = "Trial nonce".as_bytes();
    let ps = "Trial pers string".as_bytes();
    let res = HashDrbgMech::<Sha256>::new(&entropy, &nonce, &ps);

    let mut drbg;
    match res {
        None => {
            panic!("MAIN: instantiation failed.");
        }
        Some(inst) => {
            println!("MAIN: instantiation succeeded.");
            drbg = inst;
        }
    }

    let reseed_entr = "Trial reseed entropy".as_bytes();
    let reseed_add = "Trial reseed add in".as_bytes();
    let mut res = drbg.reseed(&reseed_entr, Some(&reseed_add));

    if res != 0 {
        panic!("MAIN: reseed failed (Err: {}).", res);   
    }
    else {
        println!("MAIN: reseed succeeded.");
    }

    let mut bits = Vec::<u8>::new();

    res = drbg.generate(&mut bits, 128, Some("Add-in".as_bytes()));

    if res != 0 {
        panic!("MAIN: generate failed (Err: {}).", res);   
    }
    else {
        println!("MAIN: generated bits {}.", hex::encode(bits));
    }

    res = drbg.zeroize();

    if res != 0 {
        panic!("MAIN: zeroization failed (Err: {}).", res);   
    }
    else {
        println!("MAIN: zeroization succeeded.");
    }
}

fn main(){  
    //fips_sim();
    test_hash(); 
}