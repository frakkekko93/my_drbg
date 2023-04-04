extern crate my_drbg;
#[allow(unused_imports)]
use my_drbg::demos::*;
// use my_drbg::mechs::gen_mech::DRBG_Mechanism_Functions;
use my_drbg::mechs::hash_mech::HashDrbgMech;
use my_drbg::self_tests; 
use my_drbg::demos::utility::get_input;
use rand::Rng;
use sha2::*;
// use my_drbg::mechs::utility::*;

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
fn gen_vecs() {
    print!("MAIN: how many bytes do you need?: ");

    let byte_num = get_input();

    //Bytes are generated at a CHUNK_DIM-wide chunk ratio (CHUNK_DIM*8 bits at a time).
    const CHUNK_DIM: usize = 8;
    let mut chunk: [u8; CHUNK_DIM] = [0; CHUNK_DIM];

    // Generate CHUNK_DIM bytes at a time and copy the generated chunk into result.
    let mut count = 0;
    let mut end = false;
    let mut result = Vec::<u8>::new();
    while result.len() < byte_num && !end {
        rand::thread_rng().fill(&mut chunk);
        for j in 0..chunk.len() {

            // The requested number of bytes has been reached, stop generation
            if count+j >= byte_num{
                end = true;
                break;
            }
            result.push(chunk[j]);
        }
        // Next chunk.
        count += CHUNK_DIM;
    }

    println!("MAIN: here are your bytes:\n\n{:?}\n\nLen:{}\n", &result, result.len());
}

#[allow(unused_assignments)]
fn main(){  
    // fips_sim();
    // run_demo();
    // gen_vecs();

    // let inst_res = HashDrbgMech::<Sha256>::new(
    //     &hex::decode("0996a3825a456db3c5ae7c0058e6f9b5f4384074ddfe37b4ac68e2c98bdb54c5").unwrap(),
    //     &hex::decode("318443aaf8c66f2b81e414dee9553f7c").unwrap(),
    //     &hex::decode("").unwrap(),
    //     &mut 256
    // );

    // let mut drbg;
    // match inst_res {
    //     None => {
    //         panic!("MAIN: instantiation failed.");
    //     }
    //     Some(inst) => {
    //         drbg = inst;
    //     }
    // }

    // let mut res = drbg.reseed(
    //     &hex::decode("f7d284583dc30f5ec4b16f7b916a7a89bced38bbc7d403ad358ec9196913fe6d").unwrap(),
    //     None);

    // if res != 0 {
    //     panic!("MAIN: reseed failed with error: {}", res);
    // }

    // let mut result = Vec::<u8>::new();
    // // let expected = hex::decode("04eec63bb231df2c630a1afbe724949d005a587851e1aa795e477347c8b056621c18bddcdd8d99fc5fc2b92053d8cfacfb0bb8831205fad1ddd6c071318a6018f03b73f5ede4d4d071f9de03fd7aea105d9299b8af99aa075bdb4db9aa28c18d174b56ee2a014d098896ff2282c955a81969e069fa8ce007a180183a07dfae17").unwrap();
    
    // res = drbg.generate(
    //     &mut result,
    //     128,
    //     None
    // );

    // if res != 0 {
    //     panic!("MAIN: first generate failed with error: {}", res);
    // }

    // res = drbg.generate(
    //     &mut result,
    //     128,
    //     None
    // );

    // if res != 0 {
    //     panic!("MAIN: second generate failed with error: {}", res);
    // }

    // assert_eq!("4192e569be8f66820d20374efb53d2654f316c1f09c8e4b2a2fb783b0ff8a82c88b24791414b1a1f54bd00c9ce6a981d8d1d445aa55dbc8372e67e440b4d6f96b2e6ac4ee9657672aadab562297fea4c6d0b1ba066362eeb075a9f04da40c31d0dc6d30e3a236bf2c34dccd291eaffd16eae6c1cdb88712a913fc65f979dc742", 
    //     hex::encode(&result));

    // let mut num1: Vec<u8> = [255, 255, 255, 255].to_vec();
    // let num2: Vec<u8> = [0, 0, 0, 1].to_vec();

    // modular_add_vec(&mut num1, num2);

    self_tests::mech_tests::nist_vectors::test_vectors::<HashDrbgMech<Sha512>>("Sha 512", 256);
}