extern crate my_drbg;
#[allow(unused_imports)]
use my_drbg::demos::*;
use my_drbg::self_tests; 
use my_drbg::demos::utility::get_input;
use rand::Rng;

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
    fips_sim();
    //run_demo();
    //gen_vecs();
}