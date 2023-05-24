extern crate rust_nist_drbg;

fn main(){  
    // let res = rust_nist_drbg::self_tests::run_tests::run_all();
    // if  res > 0
    // {
    //     panic!("MAIN: FATAL ERROR - {res} self-tests have failed, plese check testing log from more information.")
    // }

    rust_nist_drbg::demos::run_demo();
}