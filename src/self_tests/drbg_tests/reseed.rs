use crate::drbgs::gen_drbg::{DRBG, DRBG_Functions};
use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::self_tests::formats::*;
use crate::self_tests::constants::*;

/*  Aggregator that runs all the tests in this file. */
pub fn run_tests<T: DRBG_Mechanism_Functions + 'static>(strength: usize) -> usize {
    return norm_op::<T>(strength) +
            internal_state_not_valid::<T>(strength) +
            add_in_too_long::<T>(strength);
}

/*  Verifying normal reseed operation. */
fn norm_op<T: DRBG_Mechanism_Functions + 'static>(strength: usize) -> usize {
    let res = DRBG::<T>::new(strength, None);
    let mut drbg;

    match res{
        Err(_) => {
            write_to_log(format_message(true, "DRBG_TESTS".to_string(),
                                    "reseed_test".to_string(), 
                                    "failed to instantiate DRBG.".to_string()
                                )
            );
            return 1;
        }
        Ok(inst) => {
            drbg = inst;
        }
    }

    let res = drbg.reseed(Some(&ADD_IN_256[..strength/8]));

    return check_res(res, 0, 
        "norm_op".to_string(), 
        "DRBG_TESTS::reseed_test".to_string(), 
        "reseed normal operation failed.".to_string(), 
        "success on reseed normal operation.".to_string());
}

/*  Verifying that the reseed of an invalid internal state is not allowed. */
fn internal_state_not_valid<T: DRBG_Mechanism_Functions + 'static>(strength: usize) -> usize{
    let res = DRBG::<T>::new(strength, None);
    let mut drbg;

    match res{
        Err(_) => {
            write_to_log(format_message(true, "DRBG_TESTS".to_string(),
                                    "reseed_test".to_string(), 
                                    "failed to instantiate DRBG.".to_string()
                                )
            );
            return 1;
        }
        Ok(inst) => {
            drbg = inst;
        }
    }
    
    drbg.uninstantiate();

    let res = drbg.reseed(None);

    return check_res(res, 1, 
        "internal_state_not_valid".to_string(), 
        "DRBG_TESTS::reseed_test".to_string(), 
        "error expected on reseed of empty internal state.".to_string(), 
        "reseed of empty internal state failed es expected.".to_string());
}

/*  Verifying that additional inputs that are too long are rejected. */
fn add_in_too_long<T: DRBG_Mechanism_Functions + 'static>(strength: usize) -> usize {
    let res = DRBG::<T>::new(strength, None);
    let mut drbg;

    match res{
        Err(_) => {
            write_to_log(format_message(true, "DRBG_TESTS".to_string(),
                                    "reseed_test".to_string(), 
                                    "failed to instantiate DRBG.".to_string()
                                )
            );
            return 1;
        }
        Ok(inst) => {
            drbg = inst;
        }
    }

    let res = drbg.reseed(Some(&ADD_IN_TOO_LONG));

    return check_res(res, 2, 
        "add_in_too_long".to_string(), 
        "DRBG_TESTS::reseed_test".to_string(), 
        "error expected on additional input too long.".to_string(), 
        "reseed on additional input too long failed es expected.".to_string());
}