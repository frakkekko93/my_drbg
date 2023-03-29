use crate::drbgs::gen_drbg::{DRBG, DRBG_Functions};
use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::demos::utility::*;

pub fn drbg_demo<T: DRBG_Mechanism_Functions>(drbg: &mut DRBG<T>) -> usize {
    let mut user_choice = 1;

    println!("Great! Your DRBG has been instantiated.");
    println!("The supported security strength is: {}", drbg.get_sec_str());

    while user_choice != 0 {
        println!("-------------------------------------------------------------------------------------");
        println!("Your reseed counter is of {}", drbg.get_count());
        println!("You still have {} generations before a forced reseed occurs.\n", drbg.get_seed_life() - drbg.get_count());
        println!("What do you want to try?");
        println!("\t1- Generate bits");
        println!("\t2- Reseed the DRBG");
        println!("\t3- Uninstantiate the DRBG and create a new instance");
        println!("\t4- Run on-demand self-tests for DRBG and mechanism");
        println!("\tAnything else - Terminate the demo and exit.");
        print!("\nYour choice: ");

        user_choice = get_input();

        println!("-------------------------------------------------------------------------------------");

        if user_choice == 0 {
            println!("\n\nThanks for testing my drbg!");
            return 0;
        }

        match user_choice {
            1 => {
                generate(drbg);
            }
            2 => {
                reseed(drbg);
            }
            3 => {
                uninstantiate(drbg);
                return 1;
            }
            4 => {
                let res = run_on_demand_drbg(drbg);

                if res != 0 {
                    return 1;
                }
            }
            _ => {
                println!("\nInvalid choice: {}", user_choice);
                continue;
            }      
        }
    }

    0
}