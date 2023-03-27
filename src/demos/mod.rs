pub mod drbg_demo;
pub mod utility;

use crate::mechs::hmac_mech::HmacDrbgMech;
use crate::mechs::hash_mech::HashDrbgMech;
use crate::demos::{utility::*, drbg_demo::*};
use sha2::Sha256;

pub fn run_demo() {
    let mut scelta_drbg;
    let mut user_choice: usize = 1;

    print!("\n***************************************************************************");
    println!("***************************************************************************");
    println!("Welcome to a demo of this DRBG implementation. This DRBG uses all three of the mechanisms that are prescribed in NIST SP 800-90a (HMAC-DRBG, Hash-DRBG");
    println!("and CTR-DRBG). The goal of this demo is to show the capabilities of these implementations. The DRBGs that are used in this crate are supposed to have");
    println!("access to a direct entropy source that provides FULL-ENTROPY bits. This means that each DRBG can always be reseeded using fresh entropy and");
    println!("you can request prediction resistance at any time during bit generation. The DRBGs are also designed to have a reseed counter that allows for a");
    println!("limited number of consecutive generations without accessing the entropy source for fresh entropy. Once this limit has been reached, the DRBG will");
    println!("handle the reseeding by itself and you will be able to continue using the active instance.");
    print!("***************************************************************************");
    println!("***************************************************************************");
    println!("\nThe first step to test this design is to choose which mechanism you would like to use.");
    
    while user_choice != 0 {
        println!("-------------------------------------------------------------------------------------");
        println!("Choose between the following:");
        println!("\t1- Instantiate HMAC-DRBG");
        println!("\t2- Instantiate Hash-DRBG");
        println!("\t3- Instantiate CTR-DRBG");
        println!("\tAnything else - Interrupt the demo");
        print!("\nYour choice: ");

        scelta_drbg = get_input();

        println!("-------------------------------------------------------------------------------------");

        if scelta_drbg == 0 {
            println!("\n\nThanks for testing my drbg!");
            return;
        }

        if scelta_drbg == 3 {
            println!("\n\nCTR NOT YET IMPLEMENTED!");
            continue;
        }

        print!("> Which security strength do you need? (must be <=256): ");
        // print!("\nYour choice: ");

        let strength = get_input();

        println!("> Would you like to use a personalization string for the instantiation?\n\t1- Yes\n\t2- No");
        print!("\nYour choice: ");

        let need_ps = get_input();

        let mut hmac_drbg;
        let mut hash_drbg;
        // let mut ctr_drbg;
        match scelta_drbg {
            1 => {
                let res = inst_drbg::<HmacDrbgMech<Sha256>>(strength, need_ps);

                match res {
                    Err(err) => {
                        match err {
                            1 => {println!("\nInstantiation failed with error {}: inappropriate security strength (112 <= sec_str <= 256).", err);}
                            2 => {println!("\nInstantiation failed with error {}: personalization string is too long (max sec_str bits).", err);}
                            _ => {println!("\nInstantiation failed with error {}: instantiation of the HMAC mechanism failed.", err);}
                        }

                        continue;
                    }
                    Ok(inst) => {
                        hmac_drbg = inst;
                    }
                }
                user_choice = drbg_demo(&mut hmac_drbg);
            }
            2 => {
                let res = inst_drbg::<HashDrbgMech<Sha256>>(strength, need_ps);

                match res {
                    Err(err) => {
                        match err {
                            1 => {println!("\nInstantiation failed with error {}: inappropriate security strength (112 <= sec_str <= 256).", err);}
                            2 => {println!("\nInstantiation failed with error {}: personalization string is too long (max sec_str bits).", err);}
                            _ => {println!("\nInstantiation failed with error {}: instantiation of the HMAC mechanism failed.", err);}
                        }

                        continue;
                    }
                    Ok(inst) => {
                        hash_drbg = inst;
                    }
                }
                user_choice = drbg_demo(&mut hash_drbg);
            }
            3 => {
                println!("\nCTR NOT YET IMPLEMENTED!");
                continue;
            }
            0 => {
                println!("\n\nThanks for testing my drbg!");
                return;
            }
            _ => {
                println!("\nInvalid choice: {}", scelta_drbg);
                continue;
            }
        }
    }
}