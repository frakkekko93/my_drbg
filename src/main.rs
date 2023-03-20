extern crate my_drbg;
use my_drbg::drbgs::gen_drbg::{DRBG, DRBG_Functions};
use my_drbg::mechs::hmac_mech::HmacDrbgMech;
use rand::Rng;
use std::ascii::escape_default;
use std::str;
use sha2::*;
use my_drbg::self_tests::formats::format_message;

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

    println!("MAIN: running HMAC-DRBG self-tests...\n");
    let test_res = drbg.run_self_tests();

    check_res(test_res, 0, 
        "MAIN".to_string(), 
        "fips_sim".to_string(),
        "DRBG health tests failed, entering ERROR STATE.".to_string(),
        "DRBG health tests passed.".to_string()
    );
}

fn check_res<T: std::cmp::PartialEq>(result: T, expected: T, module_name: String, test_name: String, fail_msg: String, succ_msg: String) -> usize {
    let mut test_id = "".to_string();
    test_id.push_str(test_name.as_str());
    if result != expected {
        println!("{}", format_message(true, module_name,
                                test_id, 
                                fail_msg
                            )
        );

        return 1;
    }
    else {
        println!("{}", format_message(false, module_name,
                                test_id, 
                                succ_msg
                            )
        );

        return 0;
    }
}


// Retrieves values of the KATs to be implemented.
#[allow(dead_code)]
fn retr_kats() {
    println!("*** Retreiving some values for the HMAC-DRBG's KATs ***\n");
    println!("___ Instantiation ___");
    let add_in = rand::thread_rng().gen::<[u8; 16]>();
    let ps = rand::thread_rng().gen::<[u8; 16]>();
    let res = DRBG::<HmacDrbgMech::<Sha256>>::new(256, Some(ps.as_slice()));

    let mut drbg;
    match res {
        Err(err) => {
            panic!("MAIN: HMAC-DRBG instantiation failed with error: {}.", err);
        }
        Ok(inst) => {
            drbg = inst;
        }
    }
    println!("___ End Instantiation ___\n");

    println!("___ First Generate ___");
    drbg.generate(&mut Vec::<u8>::new(), 128, 256, false, None);
    println!("___ End First Generate ___\n");

    println!("___ Second Generate ___");
    drbg.generate(&mut Vec::<u8>::new(), 128, 256, false, Some(add_in.as_slice()));
    println!("___ End Second Generate ___\n");

    // println!("___ Third Generate ___");
    // drbg.generate(&mut Vec::<u8>::new(), 128, 256, true, None);
    // println!("___ End Third Generate ___\n");

    // println!("___ Reseed No-Addin ___");
    // drbg.reseed(None);
    // println!("___ End Reseed No-Addin ___\n");

    // println!("___ Reseed Addin ___");
    // drbg.reseed(Some(add_in.as_slice()));
    // println!("___ End Reseed Addin ___\n");
}

fn main(){  
    fips_sim();
}