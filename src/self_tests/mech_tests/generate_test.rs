use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::self_tests::formats::*;

const AL_NAME: &str = "MECH-TESTS::generate_test";

/*  Aggregator that runs all the tests in this file. */
pub fn run_tests<T: DRBG_Mechanism_Functions>() -> usize{
    return norm_op::<T>() +
            generate_on_invalid_state::<T>() +
            generate_on_seed_expired::<T>();
}

/*  TODO: norm_op */
fn norm_op<T: DRBG_Mechanism_Functions>() -> usize{
    let res = T::new("Trail entropy".as_bytes(), "Trial nonce".as_bytes(), "Trial pers".as_bytes());

    let mut drbg;
        match res{
            None => {
                write_to_log(format_message(true, AL_NAME.to_string(),
                                    "norm_op".to_string(), 
                                    "failed to instantiate DRBG mechanism.".to_string()
                                )
                );

                return 1;
            }
            Some(inst) => {
                drbg = inst;
            }
    }

    let mut bits = Vec::<u8>::new();
    let res = drbg.generate(&mut bits, 32, Some("Add-in".as_bytes()));

    if check_res(res == 0 && bits.len() == 32, true, 
            "norm_op".to_string(), 
            AL_NAME.to_string(), 
            "normal generation with DRBG mechanism failed.".to_string(), 
            "normal generation with DRBG mechanism succeeded.".to_string()) != 0{
        return 1;
    }
    0
}

/*  Making generate fail by zeroizing internal state. */
fn generate_on_invalid_state<T: DRBG_Mechanism_Functions>() -> usize{
    let res = T::new("Trail entropy".as_bytes(), "Trial nonce".as_bytes(), "Trial pers".as_bytes());

    let mut drbg;
        match res{
            None => {
                write_to_log(format_message(true, AL_NAME.to_string(),
                                    "generate_on_invalid_state".to_string(), 
                                    "failed to instantiate DRBG mechanism.".to_string()
                                )
                );

                return 1;
            }
            Some(inst) => {
                drbg = inst;
            }
    }

    let mut res = drbg.zeroize();

    if check_res(res, 0, 
            "generate_on_invalid_state".to_string(), 
            AL_NAME.to_string(), 
            "zeroization to make generate fail has failed.".to_string(), 
            "zeroization to make generate fail has succeeded.".to_string()) != 0{
        return 1;
    }

    let mut bits = Vec::<u8>::new();
    res = drbg.generate(&mut bits, 32, Some("Add-in".as_bytes()));

    if check_res(res, 1, 
            "generate_on_invalid_state".to_string(), 
            AL_NAME.to_string(), 
            "generate using zeroized DRBG mechanism succeeded.".to_string(), 
            "generate using zeroized DRBG mechanism failed, as expected.".to_string()) != 0{
        return 1;
    }
    0
}

/*  Reaching the end of seed life and trying a generate after. */
fn generate_on_seed_expired<T: DRBG_Mechanism_Functions>() -> usize{
    let res = T::new("Trail entropy".as_bytes(), "Trial nonce".as_bytes(), "Trial pers".as_bytes());

    let mut drbg;
        match res{
            None => {
                write_to_log(format_message(true, AL_NAME.to_string(),
                                    "generate_on_seed_expired".to_string(), 
                                    "failed to instantiate DRBG mechanism.".to_string()
                                )
                );

                return 1;
            }
            Some(inst) => {
                drbg = inst;
            }
    }

    let mut bits = Vec::<u8>::new();
    let mut res;

    while drbg.count() < T::seed_life() {
        res = drbg.generate(&mut bits, 1, Some("Add-in".as_bytes()));

        if res != 0 {
            write_to_log(format_message(true, AL_NAME.to_string(),
                            "generate_on_seed_expired".to_string(), 
                            "generate failed before reaching end of seed life.".to_string()
                        )
            );

            return 1;
        }

        bits.clear();
    }

    res = drbg.generate(&mut bits, 1, Some("Add-in".as_bytes()));

    if check_res(res, 2, 
            "generate_on_seed_expired".to_string(), 
            AL_NAME.to_string(), 
            "generate on seed expired succeeded.".to_string(), 
            "generate on seed expired failed, as expected.".to_string()) != 0{
        return 1;
    }
    0
}