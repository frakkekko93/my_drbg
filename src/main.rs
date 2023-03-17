use std::ascii::escape_default;
use std::str;

extern crate my_drbg;
use my_drbg::drbgs::gen_drbg::{DRBG, DRBG_Functions};
use my_drbg::mechs::hmac_mech::HmacDrbgMech;
use sha2::Sha256;

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

fn main(){
    println!("*** Simulating the start-up of FIPS provider / on-call test of HMAC-DRBG. ***\n");

    let res = DRBG::<HmacDrbgMech::<Sha256>>::new(256, None);

    let drbg;
    match res {
        Err(err) => {
            panic!("MAIN: HMAC-DRBG instantiation failed with error: {}.", err);
        }
        Ok(inst) => {
            println!("MAIN: HMAC-DRBG instantiation succeeded.");
            drbg = inst;
        }
    }

    println!("MAIN: running HMAC-DRBG self-tests...\n");
    let test_res = drbg.run_self_tests();

    if test_res != 0 {
        panic!("\nMAIN: self-tests failed on HMAC-DRBG testing!");
    }
    else {
        println!("\nMAIN: all HMAC-DRBG self-tests passed.");
    }
}