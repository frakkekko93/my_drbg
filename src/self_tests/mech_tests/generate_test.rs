use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::self_tests::formats::*;
use crate::self_tests::constants::*;

/*  The name of the test module to be printed in the log. */
const AL_NAME: &str = "MECH-TESTS::generate_test";

/*  Aggregator that runs all the tests in this file. */
pub fn run_tests<T: DRBG_Mechanism_Functions>(strength: usize) -> usize{
    return norm_op::<T>(strength) +
            generate_on_invalid_state::<T>(strength) +
            generate_on_seed_expired::<T>(strength);
}

/*  This tests the normal operation of the instantiate function of a generic DRBG mechanism. */
#[allow(const_item_mutation)]
fn norm_op<T: DRBG_Mechanism_Functions>(mut strength: usize) -> usize{
    let res;
    if T::drbg_name() == "CTR-DRBG" {
        res = T::new(&ENTROPY_CTR, "".as_bytes(), &PERS_256[..strength], &mut strength);
    }
    else{
        res = T::new(&ENTROPY[..strength], &NONCE[..strength/2], &PERS_256[..strength], &mut strength);
    }

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

    let mut bytes = Vec::<u8>::new();
    let res = drbg.generate(&mut bytes, MAX_BYTES, Some(&ADD_IN_256[..strength]));

    if check_res(res == 0 && bytes.len() == MAX_BYTES, true, 
            "norm_op".to_string(), 
            AL_NAME.to_string(), 
            "normal generation with DRBG mechanism failed.".to_string(), 
            "normal generation with DRBG mechanism succeeded.".to_string()) != 0{
        return 1;
    }
    0
}

/*  Making generate fail by zeroizing internal state. */
#[allow(const_item_mutation)]
fn generate_on_invalid_state<T: DRBG_Mechanism_Functions>(mut strength: usize) -> usize{
    let res;
    if T::drbg_name() == "CTR-DRBG" {
        res = T::new(&ENTROPY_CTR, "".as_bytes(), &PERS_256[..strength], &mut strength);
    }
    else{
        res = T::new(&ENTROPY[..strength], &NONCE[..strength/2], &PERS_256[..strength], &mut strength);
    }

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

    let mut bytes = Vec::<u8>::new();
    res = drbg.generate(&mut bytes, MAX_BYTES, Some(&ADD_IN_256[..strength]));

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
#[allow(const_item_mutation)]
fn generate_on_seed_expired<T: DRBG_Mechanism_Functions>(mut strength: usize) -> usize{
    let res;
    if T::drbg_name() == "CTR-DRBG" {
        res = T::new(&ENTROPY_CTR, "".as_bytes(), &PERS_256[..strength], &mut strength);
    }
    else{
        res = T::new(&ENTROPY[..strength], &NONCE[..strength/2], &PERS_256[..strength], &mut strength);
    }

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

    let mut bytes = Vec::<u8>::new();
    let mut res;

    while drbg.count() < T::seed_life() {
        res = drbg.generate(&mut bytes, MIN_BYTES, Some(&ADD_IN_256[..strength]));

        if res != 0 {
            write_to_log(format_message(true, AL_NAME.to_string(),
                            "generate_on_seed_expired".to_string(), 
                            "generate failed before reaching end of seed life.".to_string()
                        )
            );

            return 1;
        }

        bytes.clear();
    }

    res = drbg.generate(&mut bytes, MIN_BYTES, Some(&ADD_IN_256[..strength]));

    if check_res(res, 2, 
            "generate_on_seed_expired".to_string(), 
            AL_NAME.to_string(), 
            "generate on seed expired succeeded.".to_string(), 
            "generate on seed expired failed, as expected.".to_string()) != 0{
        return 1;
    }
    0
}