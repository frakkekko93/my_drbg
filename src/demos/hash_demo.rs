use crate::drbgs::gen_drbg::{DRBG, DRBG_Functions};
use crate::mechs::hash_mech::HashDrbgMech;
use crate::demos::utility::*;
use sha2::Sha256;


pub fn hash_drbg_demo(drbg: &mut DRBG<HashDrbgMech<Sha256>>) -> usize {
    let mut user_choice = 1;

    println!("\nGreat! Your DRBG has been instantiated.");
    println!("The supported security strength is: {}", drbg.get_sec_str());

    while user_choice != 0 {
        println!("Your reseed counter is of {}", drbg.get_count());
        println!("You still have {} generations before a forced reseed occurs.\n", drbg.get_seed_life() - drbg.get_count());
        println!("What do you want to try?");
        println!("\t1- Generate bits");
        println!("\t2- Reseed the DRBG");
        println!("\t3- Uninstantiate the DRBG and create a new instance");
        println!("\tAnything else - Terminate the demo and exit.");
        print!("\nYour choice: ");

        user_choice = get_input();

        if user_choice == 0 {
            println!("\n\nThanks for testing my drbg!");
            return 0;
        }

        match user_choice {
            1 => {
                user_choice = generate(drbg);
            }
            2 => {
                reseed(drbg);
            }
            3 => {
                uninstantiate(drbg);
                return 1;
            }
            _ => {
                println!("\nInvalid choice: {}", user_choice);
                continue;
            }      
        }
    }

    0
}