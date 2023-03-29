extern crate my_drbg;
// use aes::*;
// use my_drbg::{self_tests, mechs::gen_mech::DRBG_Mechanism_Functions};
#[allow(unused_imports)]
use my_drbg::demos::*;
use my_drbg::self_tests; 
// use my_drbg::mechs::ctr_mech::CtrDrbgMech;
// use rand::Rng;

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

#[allow(unused_assignments)]
fn main(){  
    //fips_sim();
    run_demo();
    // let mut entropy = Vec::<u8>::new();
    // let entropy_part:[u8; 32] = rand::thread_rng().gen();
    // let entropy_part2: [u8; 16] = rand::thread_rng().gen();
    // entropy.append(&mut entropy_part.to_vec());
    // entropy.append(&mut entropy_part2.to_vec());

    // let mut pers = Vec::<u8>::new();
    // let pers_part:[u8; 24] = rand::thread_rng().gen();
    // //let pers_part2: [u8; 16] = rand::thread_rng().gen();
    // pers.append(&mut pers_part.to_vec());
    // //pers.append(&mut pers_part2.to_vec());

    // let /*mut*/ nonce = Vec::<u8>::new();
    // // let nonce_part:[u8; 32] = rand::thread_rng().gen();
    // // let nonce_part2: [u8; 16] = rand::thread_rng().gen();
    // // nonce.append(&mut nonce_part.to_vec());
    // // nonce.append(&mut nonce_part2.to_vec());

    // let mut add_in = Vec::<u8>::new();
    // let add_in_part:[u8; 24] = rand::thread_rng().gen();
    // //let add_in_part2: [u8; 16] = rand::thread_rng().gen();
    // add_in.append(&mut add_in_part.to_vec());
    // //add_in.append(&mut add_in_part2.to_vec());

    // println!("MAIN: passed entropy: {}, len: {}", hex::encode(&entropy), entropy.len()*8);
    // println!("MAIN: passed nonce: {}, len: {}", hex::encode(&nonce), nonce.len()*8);
    // println!("MAIN: passed pers: {}, len: {}", hex::encode(&pers), pers.len()*8);

    // let res = CtrDrbgMech::<Aes192>::new(&entropy, &nonce, &pers);

    // let mut drbg;
    // match res {
    //     None => {
    //         println!("MAIN: instantiation failed.");
    //         return;
    //     }
    //     Some(inst) => {
    //         println!("MAIN: instantiation succeeded.");
    //         drbg = inst;
    //     }
    // }

    // println!("MAIN: passed entropy: {}, len: {}", hex::encode(&entropy), entropy.len()*8);
    // println!("MAIN: passed add_in: {}, len: {}", hex::encode(&add_in), add_in.len()*8);

    // let mut res = drbg.reseed(&entropy, Some(&add_in));

    // if res == 0 {
    //     println!("MAIN: reseeding succeeded.");
    // }
    // else {
    //     println!("MAIN: instantiation failed with error: {}.", res);
    //     return;
    // }

    // println!("MAIN: passed add_in: {}, len: {}", hex::encode(&add_in), add_in.len()*8);

    // let mut bits = Vec::<u8>::new();
    // res = drbg.generate(&mut bits, 16, Some(&add_in));

    // if res == 0 {
    //     println!("MAIN: generated bits: {}, len: {}.", hex::encode(&bits), bits.len()*8);
    // }
    // else {
    //     println!("MAIN: generation failed with error: {}.", res);
    //     return;
    // }

    // res = drbg.zeroize();

    // if res == 0 {
    //     println!("MAIN: zeroization succeeded.");
    //     assert_eq!(true, drbg._is_zeroized());
    // }
    // else {
    //     println!("MAIN: zeroization failed with error: {}.", res);
    //     assert_eq!(false, drbg._is_zeroized());
    //     return;
    // }
}