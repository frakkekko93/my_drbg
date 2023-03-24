extern crate my_drbg;
use my_drbg::drbgs::gen_drbg::{DRBG, DRBG_Functions};
use my_drbg::mechs::gen_mech::DRBG_Mechanism_Functions;
use my_drbg::mechs::hash_mech::HashDrbgMech;
#[allow(unused_imports)]
use my_drbg::mechs::hmac_mech::HmacDrbgMech;
use my_drbg::self_tests;
use rand::Rng;
use sha2::*;
use std::io::stdin as stdin;
use my_drbg::demos::*; 

// Simulates the start-up of a potential fips provider by calling the self test functions.
#[allow(dead_code)]
fn fips_sim(){
    println!("\n\n*** Simulating the start-up of FIPS provider / on-call test of DRBG. ***\n");

    let res = self_tests::run_tests::run_all();

    if res != 0 {
        println!("MAIN: {res} tests have failed, see the log for more details.");
    }
    else {
        println!("MAIN: all tests have passed.");
    }
}

#[allow(dead_code)]
fn test_hash() {
    let res;
    let entropy = "Trial entropy".as_bytes();
    let nonce = "Trial nonce".as_bytes();
    let ps = "Trial pers string".as_bytes();

    // let binding = hex::decode("ee536bdd2cddf81a1bbeb6e9710b2887cd114581fb133e27588a1ebe37cc5bf7").unwrap();
    // let entropy = binding.as_slice();

    // let binding = hex::decode("09e9d180bb291569ffa1f022abe9cf74").unwrap();
    // let nonce = binding.as_slice();

    // let binding = hex::decode("328cad24e54411bf3faec704b57e3c63bdb858356b9b6c880e906d1df37937da").unwrap();
    // let ps = binding.as_slice();
    
    res = HashDrbgMech::<Sha256>::new(&entropy, &nonce, &ps);

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
    let res = drbg.reseed(&reseed_entr, Some(&reseed_add));

    if res != 0 {
        panic!("MAIN: reseed failed (Err: {}).", res);   
    }
    else {
        println!("MAIN: reseed succeeded.");
    }

    let mut bits = Vec::<u8>::new();

    let res = drbg.generate(&mut bits, 128, None);

    if res != 0 {
        panic!("MAIN: generate failed (Err: {}).", res);   
    }
    else {
        println!("MAIN: generated bits {}.", hex::encode(&bits));
    }

    bits.clear();

    let binding = hex::decode("e49071cf3fed5023ba526441839abd9b8cf90d02b34576c280e0eacc1840d5c1").unwrap();
    let res = drbg.generate(&mut bits, 128, Some(binding.as_slice()));

    if res != 0 {
        panic!("MAIN: generate failed (Err: {}).", res);   
    }
    else {
        println!("MAIN: generated bits {}.", hex::encode(bits));
    }

    let res = drbg.zeroize();

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
fn extract_kats<T: DRBG_Mechanism_Functions>() {
    let mut scelta;
    let mut scelta_buf = String::default();
    
    println!("\nDo you want to use a ps? (1=y or 2=n)");
    let mut input_res = stdin().read_line(&mut scelta_buf);

    match input_res {
        Err(err) => {
            panic!("MAIN: input failed with error: {}", err);
        }
        Ok(_) => {
            scelta = scelta_buf.trim().parse::<u32>().unwrap();
        }
    }

    let pers: [u8; 32];
    let inst_res;
    if scelta == 1 {
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

        println!("\nWhat do you want to do?");
        println!("\t1- Generate 1024 bits");
        println!("\t2- Reseed DRBG");
        println!("\t0 - Uninstantiate DRBG and exit");
        scelta_buf.clear();
        input_res = stdin().read_line(&mut scelta_buf);

        match input_res {
            Err(err) => {
                panic!("MAIN: input failed with error: {}", err);
            }
            Ok(_) => {
                scelta = scelta_buf.trim().parse::<u32>().unwrap();
            }
        }

        if scelta == 1 {
            println!("\nDo you want to use a prr? (1=y or 2=n)");
            scelta_buf.clear();
            input_res = stdin().read_line(&mut scelta_buf);

            match input_res {
                Err(err) => {
                    panic!("MAIN: input failed with error: {}", err);
                }
                Ok(_) => {
                    scelta = scelta_buf.trim().parse::<u32>().unwrap();
                }
            }

            if scelta == 1 {
                prr = true;
            }

            println!("\nDo you want to use a add-in? (1=y or 2=n)");
            scelta_buf.clear();
            input_res = stdin().read_line(&mut scelta_buf);

            match input_res {
                Err(err) => {
                    panic!("MAIN: input failed with error: {}", err);
                }
                Ok(_) => {
                    scelta = scelta_buf.trim().parse::<u32>().unwrap();
                }
            }

            if scelta == 1 {
                add = rand::thread_rng().gen();
                op_res = drbg.generate(& mut bits, 128, 256, prr, Some(add.as_slice()));
            }
            else {
                op_res = drbg.generate(& mut bits, 128, 256, prr, None);
            }

            if op_res != 0 {
                panic!("MAIN: generation failed with error: {}", op_res);
            }

            println!("Generated bits: {} - len: {}.", hex::encode(&bits), bits.len());
        }
        else if scelta == 2 {
            println!("\nDo you want to use a add-in? (1=y or 2=n)");
            scelta_buf.clear();
            input_res = stdin().read_line(&mut scelta_buf);

            match input_res {
                Err(err) => {
                    panic!("MAIN: input failed with error: {}", err);
                }
                Ok(_) => {
                    scelta = scelta_buf.trim().parse::<u32>().unwrap();
                }
            }

            if scelta == 1 {
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
    //extract_kats::<HmacDrbgMech<Sha256>>();
    run_demo();
}