extern crate my_drbg;
#[allow(unused_imports)]
use my_drbg::demos::*;
use my_drbg::self_tests; 

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
    fips_sim();
    //run_demo();
}