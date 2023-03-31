use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::self_tests::formats::*;
use crate::self_tests::constants::*;

/*  The name of the test module to be printed in the log. */
const AL_NAME: &str = "MECH-TESTS::reseed_test";

/*  Aggregator that runs all the tests in this file. */
pub fn run_tests<T: DRBG_Mechanism_Functions>(strength: usize) -> usize{
    return norm_op::<T>(strength) +
            test_invalid_state::<T>(strength) +
            test_entropy_too_short::<T>(strength);
}

/*  Testing normal reseeding operation. */
#[allow(const_item_mutation)]
fn norm_op<T: DRBG_Mechanism_Functions>(mut strength: usize) -> usize{
    let res;
    if T::drbg_name() == "CTR-DRBG" {
        res = T::new(&ENTROPY_CTR, "".as_bytes(), &PERS_256[..strength/8], &mut strength);
    }
    else{
        res = T::new(&ENTROPY, &NONCE, &PERS_256[..strength/8], &mut strength);
    }

    let mut drbg;
        match res{
            None => {
                write_to_log(format_message(true, AL_NAME.to_string(),
                                    "reseed_test".to_string(), 
                                    "failed to instantiate DRBG mechanism.".to_string()
                                )
                );

                return 1;
            }
            Some(inst) => {
                drbg = inst;
            }
    }

    let res = drbg.reseed(&ENTROPY_CTR, Some(&ADD_IN_256[..strength/8]));

    if check_res(res, 0, 
            "norm_op".to_string(), 
            AL_NAME.to_string(), 
            "normal reseeding of DRBG mechanism failed.".to_string(), 
            "normal reseeding of DRBG mechanism succeeded.".to_string()) != 0{
        return 1;
    }
    0
}

/*  Making reseed failed after trying to reseed zeroized internal state */
#[allow(const_item_mutation)]
fn test_invalid_state<T: DRBG_Mechanism_Functions>(mut strength: usize) -> usize{
    let res;
    if T::drbg_name() == "CTR-DRBG" {
        res = T::new(&ENTROPY_CTR, "".as_bytes(), &PERS_256[..strength/8], &mut strength);
    }
    else{
        res = T::new(&ENTROPY, &NONCE, &PERS_256[..strength/8], &mut strength);
    }

    let mut drbg;
        match res{
            None => {
                write_to_log(format_message(true, AL_NAME.to_string(),
                                    "reseed_test".to_string(), 
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
            "reseed_fail".to_string(), 
            AL_NAME.to_string(), 
            "zeroization to make reseed fail has failed.".to_string(), 
            "zeroization to make reseed fail has succeeded.".to_string()) != 0{
        return 1;
    }

    res = drbg.reseed(&ENTROPY, Some(&ADD_IN_256[..strength/8]));

    if check_res(res, 1, 
            "reseed_fail".to_string(), 
            AL_NAME.to_string(), 
            "reseeding of zeroized DRBG mechanism succeeded.".to_string(), 
            "reseeding of zeroized DRBG mechanism failed, as expected.".to_string()) != 0{
        return 1;
    }
    0
}

/*  Testing that entropy too short is refused by HMAC and Hash mechanisms. */
#[allow(const_item_mutation)]
fn test_entropy_too_short<T: DRBG_Mechanism_Functions>(mut strength: usize) -> usize{
    let res;
    if T::drbg_name() == "CTR-DRBG" {
        res = T::new(&ENTROPY_CTR, "".as_bytes(), &PERS_256[..strength/8], &mut strength);
    }
    else{
        res = T::new(&ENTROPY, &NONCE, &PERS_256[..strength/8], &mut strength);
    }

    let mut drbg;
        match res{
            None => {
                write_to_log(format_message(true, AL_NAME.to_string(),
                                    "reseed_test".to_string(), 
                                    "failed to instantiate DRBG mechanism.".to_string()
                                )
                );

                return 1;
            }
            Some(inst) => {
                drbg = inst;
            }
    }

    let res = drbg.reseed(&ENTROPY_TOO_SHORT, None);
    if check_res(res, 2, 
            "test_entropy_too_short".to_string(), 
            AL_NAME.to_string(), 
            "reseeding with entropy too short of DRBG mechanism succeeded.".to_string(), 
            "reseeding with entropy too short of DRBG mechanism failed, as expected.".to_string()) != 0{
        return 1;
    }

    0
}