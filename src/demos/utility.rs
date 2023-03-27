use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::drbgs::gen_drbg::{DRBG, DRBG_Functions};
use std::io::{self, stdin};
use rand::Rng;

/*  Utility function used to get user choices from cmd input. If an error occurs, 0 is returned. */
pub fn get_input() -> usize {
    io::Write::flush(&mut io::stdout()).expect("flush failed!");

    let mut scelta_buf = String::default();
    let input_res = stdin().read_line(&mut scelta_buf);

    match input_res {
        Err(err) => {
            panic!("Input error: {}", err);
        }
        Ok(_) => {
            let parse_res = scelta_buf.trim().parse::<usize>();

            match parse_res {
                Err(_) => {return 0;}
                Ok(value) => {return value;}
            }
        }
    }
}

/*  Utility function that instantiates the desired DRBG with the desired strength and ps. Enventually returns an
    error if instantiation fails. */
pub fn inst_drbg<T: DRBG_Mechanism_Functions>(sec_str: usize, need_ps: usize) -> Result<DRBG<T>, usize> {
    if need_ps == 1 {
        let ps: [u8; 32];
        ps = rand::thread_rng().gen();
        let actual_pers = &ps[0..sec_str/8];
        
        println!("Used pers: {}, len: {}", hex::encode(&actual_pers), actual_pers.len());

        return DRBG::<T>::new(sec_str, Some(&actual_pers));
    }
    else {
        return DRBG::<T>::new(sec_str, None);
    }
}

pub fn generate<T: DRBG_Mechanism_Functions>(drbg: &mut DRBG<T>) -> usize {
    print!("\nHow many bits do you want to generate? (max {}): ", drbg.get_max_pbr());
    let num_bits = get_input();

    print!("\nWhich security strength is required for these bits? (supported <={}): ", drbg.get_sec_str());
    let sec_str = get_input();

    print!("\nIs prediction resistance required for this generation? (1=yes, 2=no, DEFAULT=no): ");
    let prr = get_input();

    print!("\nDo you want to use some additional input? (1=yes, 2=no, DEFAULT=no): ");
    let add = get_input();

    let flag_prr;
    match prr {
        1 => {
            flag_prr = true;
        }
        _ => {
            flag_prr = false;
        }
    }

    let mut bits = Vec::<u8>::new();
    let res;
    let mut actual_add_in = Vec::<u8>::new();
    match add {
        1 => {
            let add_in: [u8; 32];
            add_in = rand::thread_rng().gen();
            add_in[0..sec_str/8].clone_into(& mut actual_add_in);

            println!("\nUsed add-in: {}, len: {}", hex::encode(&actual_add_in), actual_add_in.len());

            res = drbg.generate(&mut bits, num_bits/8, sec_str, flag_prr, Some(actual_add_in.as_slice()));
        }
        _ => {
            res = drbg.generate(&mut bits, num_bits/8, sec_str, flag_prr, None);
        }
    }

    match res {
        0 => {println!("\nHere are the bits you requested:\n\n{}\nLen: {} bits.\n", hex::encode(&bits), bits.len() * 8);}
        1 => {println!("\nGeneration failed with error {}: internal state is not valid.", res);}
        2 => {println!("\nGeneration failed with error {}: you requested too many bits in one go.", res);}
        3 => {println!("\nGeneration failed with error {}: you requested a security strength that is not supported by this instance.", res);}
        4 => {println!("\nGeneration failed with error {}: the additional input provided is too long ({} bits).", res, actual_add_in.len());}
        _ => {println!("\nGeneration failed with error {}: internal state generation failed unexpectedly.", res);}
    }

    1
}

pub fn reseed<T: DRBG_Mechanism_Functions>(drbg: &mut DRBG<T>) -> usize {
    let sec_str = drbg.get_sec_str();

    print!("\nDo you want to use some additional input? (1=yes, 2=no, DEFAULT=no): ");
    let add = get_input();

    let res;
    let mut actual_add_in = Vec::<u8>::new();
    match add {
        1 => {
            let add_in: [u8; 32];
            add_in = rand::thread_rng().gen();
            add_in[0..sec_str/8].clone_into(& mut actual_add_in);

            println!("\nUsed add-in: {}, len: {}", hex::encode(&actual_add_in), actual_add_in.len());

            res = drbg.reseed(Some(actual_add_in.as_slice()));
        }
        _ => {
            res = drbg.reseed(None);
        }
    }

    match res {
        0 => {println!("\nDRBG succesfully reseeded.");}
        1 => {println!("\nReseeding failed with error {}: internal state is not valid.", res);}
        2 => {println!("\nReseeding failed with error {}: additional input is too long ({} bits).", res, actual_add_in.len()*8);}
        _ => {println!("\nReseeding failed with error {}: reseeding of the internal HMAC failed unexpectedly.", res);}
    }

    1
}

pub fn uninstantiate<T: DRBG_Mechanism_Functions>(drbg: &mut DRBG<T>) -> usize {
    let res = drbg.uninstantiate();

    match res {
        0 => {println!("\nDRBG succesfully uninstantiated.");}
        _ => {println!("\nUninstantiation failed with error {}: instance was already zeroized.", res);}
    }

    1
}

pub fn run_on_demand_drbg<T: DRBG_Mechanism_Functions>(drbg: &mut DRBG<T>) -> usize {
    let res = drbg.run_self_tests();

    match res {
        0 => {println!("\nAll DRBG and mechanism self-tests have passed.");}
        _ => {println!("\n{res} DRBG and/or mechanism self-tests have failed (see test log).");}
    }

    1
}