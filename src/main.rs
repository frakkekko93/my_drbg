extern crate my_drbg;
use my_drbg::drbgs::gen_drbg::{DRBG, DRBG_Functions};
use my_drbg::mechs::gen_mech::DRBG_Mechanism_Functions;
use my_drbg::mechs::hash_mech::HashDrbgMech;
#[allow(unused_imports)]
use my_drbg::mechs::hmac_mech::HmacDrbgMech;
use rand::Rng;
use sha2::*;
use std::io::stdin as stdin;

// Simulates the start-up of a potential fips provider by calling the self test functions.
#[allow(dead_code)]
fn fips_sim(){
    println!("*** Simulating the start-up of FIPS provider / on-call test of HMAC-DRBG. ***\n");

    let res = DRBG::<HashDrbgMech::<Sha256>>::new(256, None);

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

#[allow(dead_code)]
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

#[allow(dead_code)]
fn test_hmac() {
    let entropy = "Trial entropy".as_bytes();
    let nonce = "Trial nonce".as_bytes();
    let ps = "Trial pers string".as_bytes();
    let res = HmacDrbgMech::<Sha256>::new(&entropy, &nonce, &ps);

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

#[allow(dead_code)]
fn test_hmac_drbg() {
    println!("*** Trying the Hash-DRBG Functionalities ***");

    let res = DRBG::<HmacDrbgMech<Sha256>>::new(256, Some("Trial pers".as_bytes()));

    let mut drbg;
    match res {
        Err(err) => {
            panic!("MAIN: instantiation failed with error: {}", err);
        }
        Ok(inst) => {
            println!("MAIN: instantiated DRBG.");
            drbg = inst;
        }
    }

    let mut bits =  Vec::<u8>::new();
    let mut res = drbg.generate(&mut bits, 128, 256, true, Some("Some add-in".as_bytes()));

    if res != 0 {
        panic!("MAIN: generation failed with error: {}", res);
    }

    println!("MAIN: generated {} bits: {}", bits.len()*8, hex::encode(bits));

    res = drbg.reseed(Some("Another add-in".as_bytes()));

    if res != 0 {
        panic!("MAIN: reseeding failed with error: {}", res);
    }

    println!("MAIN: reseeding succeeded.");

    res = drbg.uninstantiate();

    if res != 0 {
        panic!("MAIN: uninstantiation failed with error: {}", res);
    }

    println!("MAIN: uninstantiation succeeded.");
}

#[allow(dead_code)]
fn test_hash_drbg() {
    println!("*** Trying the Hash-DRBG Functionalities ***");

    let res = DRBG::<HashDrbgMech<Sha256>>::new(256, Some("Trial pers".as_bytes()));

    let mut drbg;
    match res {
        Err(err) => {
            panic!("MAIN: instantiation failed with error: {}", err);
        }
        Ok(inst) => {
            println!("MAIN: instantiated DRBG.");
            drbg = inst;
        }
    }

    let mut bits =  Vec::<u8>::new();
    let mut res = drbg.generate(&mut bits, 128, 256, true, Some("Some add-in".as_bytes()));

    if res != 0 {
        panic!("MAIN: generation failed with error: {}", res);
    }

    println!("MAIN: generated {} bits: {}", bits.len()*8, hex::encode(bits));

    res = drbg.reseed(Some("Another add-in".as_bytes()));

    if res != 0 {
        panic!("MAIN: reseeding failed with error: {}", res);
    }

    println!("MAIN: reseeding succeeded.");

    res = drbg.uninstantiate();

    if res != 0 {
        panic!("MAIN: uninstantiation failed with error: {}", res);
    }

    println!("MAIN: uninstantiation succeeded.");
}

#[allow(dead_code)]
fn extract_kats<T: DRBG_Mechanism_Functions>() {
    let mut scelta = "".to_string();
    
    println!("Do you want to use a ps? (y or n)");
    let mut input_res = stdin().read_line(&mut scelta);

    match input_res {
        Err(err) => {
            panic!("MAIN: input failed with error: {}", err);
        }
        Ok(_) => {}
    }

    let pers: [u8; 32];
    let inst_res;
    if scelta == "y" {
        pers= rand::thread_rng().gen();
        inst_res = DRBG::<T>::new(256, Some(pers.as_slice()));
    }
    else {
        inst_res = DRBG::<T>::new(256, None);
    }

    let mut drbg;
    match inst_res {
        Err(err) => {
            panic!("MAIN: instantiation failed with error: {}", err);
        }
        Ok(inst) => {
            drbg = inst;
        }
    }
;
    let mut op_res;
    #[allow(while_true)]
    while true {
        let mut bits = Vec::<u8>::new();
        let mut prr = false;
        let add: [u8; 32];

        println!("What do you want to do?");
        println!("\t1- Generate 1024 bits");
        println!("\t2- Reseed DRBG");
        println!("\tAnything else - Uninstantiate DRBG and exit");
        input_res = stdin().read_line(&mut scelta);

        match input_res {
            Err(err) => {
                panic!("MAIN: input failed with error: {}", err);
            }
            Ok(_) => {}
        }

        if scelta == "1" {
            println!("Do you want to use a prr? (y or n)");
            input_res = stdin().read_line(&mut scelta);

            match input_res {
                Err(err) => {
                    panic!("MAIN: input failed with error: {}", err);
                }
                Ok(_) => {}
            }

            if scelta == "y" {
                prr = true;
            }

            println!("Do you want to use a add-in? (y or n)");
            input_res = stdin().read_line(&mut scelta);

            match input_res {
                Err(err) => {
                    panic!("MAIN: input failed with error: {}", err);
                }
                Ok(_) => {}
            }

            if scelta == "y" {
                add = rand::thread_rng().gen();
                op_res = drbg.generate(& mut bits, 1024, 256, prr, Some(add.as_slice()));
            }
            else {
                op_res = drbg.generate(& mut bits, 1024, 256, prr, None);
            }

            if op_res != 0 {
                panic!("MAIN: generation failed with error: {}", op_res);
            }

            println!("Generated bits: {}", hex::encode(bits));
        }
        else if scelta == "2" {
            println!("Do you want to use a add-in? (y or n)");
            input_res = stdin().read_line(&mut scelta);

            match input_res {
                Err(err) => {
                    panic!("MAIN: input failed with error: {}", err);
                }
                Ok(_) => {}
            }

            if scelta == "y" {
                add = rand::thread_rng().gen();
                op_res = drbg.reseed(Some(add.as_slice()));
            }
            else {
                op_res = drbg.reseed(None);
            }

            if op_res != 0 {
                panic!("MAIN: reseeding failed with error: {}", op_res);
            }

            println!("Reseeding succeeded.");
        }
        else {
            drbg.uninstantiate();
            return;
        }
    }
}

fn main(){  
    //fips_sim();
    //test_hash();
    //test_hash_drbg();
    extract_kats::<HashDrbgMech<Sha256>>();
}