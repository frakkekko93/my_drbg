use crate::drbgs::gen_drbg::{DRBG, DRBG_Functions};
use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::self_tests::constants::*;
use crate::self_tests::formats::*;

/*  Aggregator that runs all the tests in this file. */
pub fn run_tests<T: DRBG_Mechanism_Functions>() -> usize {
    return norm_op::<T>() + 
            double_uninst::<T>();
}

/*  Verifying that the reseed of an invalid internal state is not allowed. */
fn norm_op<T: DRBG_Mechanism_Functions>() -> usize{
    let res = DRBG::<T>::new(SEC_STR, None);
    let mut drbg;

    match res{
        Err(_) => {
            write_to_log(format_message(true, "DRBG_TESTS".to_string(),
                                    "generate_test".to_string(), 
                                    "failed to instantiate DRBG.".to_string()
                                )
            );
            return 1;
        }
        Ok(inst) => {
            drbg = inst;
        }
    }

    let res = drbg.uninstantiate();
    let res2 = drbg.reseed(None);

    return check_res(res, 0, 
        "norm_op".to_string(), 
        "DRBG_TESTS::uninstantiate_test".to_string(), 
        "normal uninstantiation operation failed.".to_string(), 
        "success on uninstantiate normal operation.".to_string()) +
            check_res(res2, 1, 
            "norm_op".to_string(), 
            "DRBG_TESTS::uninstantiate_test".to_string(), 
            "reseeding on invalid internal state succeeded.".to_string(), 
            "reseeding on invalid internal state failed as expected.".to_string());
}

/*  Verifying that a double uninstantiate is not allowed. */
fn double_uninst<T: DRBG_Mechanism_Functions>() -> usize {
    let res = DRBG::<T>::new(SEC_STR, None);
    let mut drbg;

    match res{
        Err(_) => {
            write_to_log(format_message(true, "DRBG_TESTS".to_string(),
                                    "generate_test".to_string(), 
                                    "failed to instantiate DRBG.".to_string()
                                )
            );
            return 1;
        }
        Ok(inst) => {
            drbg = inst;
        }
    }

    let res = drbg.uninstantiate();
    let res2 = drbg.uninstantiate();

    return check_res(res, 0, 
        "double_uninst".to_string(), 
        "DRBG_TESTS::uninstantiate_test".to_string(), 
        "normal uninstantiation operation failed.".to_string(), 
        "success on uninstantiate normal operation.".to_string()) +
            check_res(res2, 1, 
            "double_uninst".to_string(), 
            "DRBG_TESTS::uninstantiate_test".to_string(), 
            "uninstantiate on invalid internal state succeeded.".to_string(), 
            "uninstantiate on invalid internal state failed as expected.".to_string());
}