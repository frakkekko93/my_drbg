extern crate my_drbg;
use my_drbg::drbgs::gen_drbg::{DRBG, DRBG_Functions};
use my_drbg::mechs::gen_mech::DRBG_Mechanism_Functions;
use my_drbg::mechs::hmac_mech::HmacDrbgMech;
use rand::Rng;
use std::ascii::escape_default;
use std::str;
use sha2::*;
use serde::Deserialize;
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

fn check_res(result: Vec<u8>, expected: Vec<u8>, test_name: String) -> usize {
    let mut test_id = "hmac_kats::".to_string();
    test_id.push_str(test_name.as_str());
    if result != expected {
        println!("{}", format_message(true, "HMAC-DRBG-Mech".to_string(),
                                test_id, 
                                "failed to test the use of pred_res_req flag.".to_string()
                            )
        );

        return 1;
    }
    else {
        println!("{}", format_message(false, "HMAC-DRBG-Mech".to_string(),
                                test_id, 
                                "succeeded to test the use of pred_res_req flag.".to_string()
                            )
        );

        return 0;
    }
}


// Test KATs for HMAC-DRBG mech.
#[allow(dead_code)]
#[allow(non_snake_case)]
fn test_HMAC_kats() -> usize{
    #[derive(Deserialize, Debug)]
    struct Fixture {
        name: String,
        entropy: String,
        nonce: String,
        pers: Option<String>,
        prr: bool,
        reseed_entropy: Option<String>,
        add: [Option<String>; 2],
        double_gen: bool,
        expected: String,
    }

    let tests: Vec<Fixture> = serde_json::from_str(include_str!("self_tests/hmac_mech_tests/fixtures/hmac_kats.json")).unwrap();

    for test in tests {
        let res = HmacDrbgMech::<Sha256>::new(
            &hex::decode(&test.entropy).unwrap(),
            &hex::decode(&test.nonce).unwrap(),
            &hex::decode(&test.pers.unwrap_or("".to_string())).unwrap());

        let mut drbg;
        match res{
            None => {
                println!("{}", format_message(true, "HMAC-DRBG-Mech".to_string(),
                                    "hmac_kats".to_string(), 
                                    "failed to instantiate DRBG.".to_string()
                                )
                );
                return 1;
            }
            Some(inst) => {
                drbg = inst;
            }
        }

        let expected = hex::decode(&test.expected).unwrap();
        let reseed_entropy = match test.reseed_entropy {
            Some(entr) => hex::decode(&entr).unwrap(),
            None => Vec::<u8>::new()};
        let mut result = Vec::new();
        let full_len = expected.len();
        let add0 = match test.add[0] {
            Some(ref add_in) => Some(hex::decode(&add_in).unwrap()),
            None => None};
        let add1 = match test.add[1] {
            Some(ref add_in) => Some(hex::decode(&add_in).unwrap()),
            None => None};
        
        // Testing the use of prediction resistance request on a single generate (reseed is triggered before generating).
        if test.prr {
            drbg.reseed(&reseed_entropy, 
                match add0 {
                    Some(ref add_in) => Some(&add_in.as_slice()),
                    None => None
                });
            
            drbg.generate(&mut result, full_len, None);
            
            if check_res(result, expected, test.name) != 0 {
                return 1;
            }
        }
        else {
            // Testing double consecutive generation using possibly two additional inputs.
            if test.double_gen {
                drbg.generate(&mut result, full_len, 
                    match add0 {
                    Some(ref add_in) => Some(&add_in.as_slice()),
                    None => None
                });
                
                result.clear();
                drbg.generate(&mut result, full_len, 
                    match add1 {
                        Some(ref add_in) => Some(&add_in.as_slice()),
                        None => None
                    });
                
                if check_res(result, expected, test.name) != 0 {
                    return 1;
                }
            }
            else {
                // Testing generate with no prediction resistance request and optional additional input.
                drbg.generate(&mut result, full_len, 
                    match add0 {
                        Some(ref add_in) => Some(&add_in.as_slice()),
                        None => None
                    });
                
                if check_res(result, expected, test.name) != 0 {
                    return 1;
                }
            }
        }
    }

    0
}

fn main(){  
    // let res = test_HMAC_kats();

    // if res != 0 {
    //     println!("MAIN: KAT tests on HMAC-DRBG failed.");
    // }

    fips_sim();
}