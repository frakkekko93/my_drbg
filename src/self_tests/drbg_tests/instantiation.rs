use crate::drbgs::gen_drbg::{DRBG, DRBG_Functions};
use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::self_tests::formats::*;
use crate::self_tests::constants::*;

/*  Aggregator that runs all the tests in this file. */
pub fn run_tests<T: DRBG_Mechanism_Functions + 'static>(strength: usize) -> usize {
    return norm_op::<T>(strength) +
            test_ss_not_supported::<T>(strength) +
            ps_is_too_long::<T>(strength);
}

/*  Testing that any security strength that is <=MAX_STR is actually accepted by the DRBG. */
fn norm_op<T: DRBG_Mechanism_Functions + 'static>(strength: usize) -> usize{
    let res = DRBG::<T>::new(strength, Some(&PERS_256[..strength]));
    let mut drbg = None;

    match res{
        Err(_) => {}
        Ok(inst) => {
            drbg = Some(inst);
        }
    }

    if check_res(drbg.is_none(), false, 
    "norm_op".to_string(), 
    "DRBG_TESTS::instantiation_test".to_string(), 
    "failed to instantiate DRBG using a supported security strength.".to_string(), 
    "succeeded to instantiate DRBG using a supported security strength as expected.".to_string()) != 0{
        return 1;
    }
    0
}

/*  Testing that not supported security strengths are actually rejected by the DRBG. */
fn test_ss_not_supported<T: DRBG_Mechanism_Functions + 'static>(strength: usize) -> usize{
    let res = DRBG::<T>::new(strength+8, None);
    let mut err= 0;
    let mut drbg = None;

    match res{
        Err(error) => {
            err = error;
        }
        Ok(inst) => {
            drbg = Some(inst);
        }
    }

    if (T::drbg_name() == "CTR-DRBG" || T::drbg_name() == "CTR-DRBG-DF") && strength < 32{
        if check_res((err, true), (3, drbg.is_none()), 
        "test_ss_not_supported".to_string(), 
        "DRBG_TESTS::instantiation_test".to_string(), 
        "succeeded to instantiate DRBG using not supported security strength.".to_string(), 
        "failed to instantiate DRBG using not supported security strength as expected.".to_string()) != 0{
            return 1;
        }
        0
    }
    else {
        if check_res((err, true), (1, drbg.is_none()), 
        "test_ss_not_supported".to_string(), 
        "DRBG_TESTS::instantiation_test".to_string(), 
        "succeeded to instantiate DRBG using not supported security strength.".to_string(), 
        "failed to instantiate DRBG using not supported security strength as expected.".to_string()) != 0{
            return 1;
        }
        0
    }
}

/*  Testing that the limit on the length of the personalization string is actually enforced. */
fn ps_is_too_long<T: DRBG_Mechanism_Functions + 'static>(strength: usize) -> usize{
    let res = DRBG::<T>::new(strength, Some(&PERS_TOO_LONG));
    let mut err= 0;
    let mut drbg = None;

    match res{
        Err(error) => {
            err = error;
        }
        Ok(inst) => {
            drbg = Some(inst);
        }
    }

    if check_res((err, true), (2, drbg.is_none()), 
    "ps_is_too_long".to_string(), 
    "DRBG_TESTS::instantiation_test".to_string(), 
    "succeeded to instantiate DRBG using not supported personalization string.".to_string(), 
    "failed to instantiate DRBG using not supported personalization string as expected.".to_string()) != 0{
        return 1;
    }
    0
}