use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::self_tests::formats::*;
use rand::Rng;

/*  The name of the test module to be printed in the log. */
const AL_NAME: &str = "MECH-TESTS::reseed_test";

/*  Aggregator that runs all the tests in this file. */
pub fn run_tests<T: DRBG_Mechanism_Functions>() -> usize{
    return norm_op::<T>() +
            reseed_fail::<T>();
}

/*  Testing normal reseeding operation. */
fn norm_op<T: DRBG_Mechanism_Functions>() -> usize{
    let mut entropy = Vec::<u8>::new();
    let entropy_part: [u8; 32] = rand::thread_rng().gen();
    entropy.append(&mut entropy_part.to_vec());

    if T::drbg_name() == "CTR-DRBG" {
        let entropy_part2: [u8; 16] = rand::thread_rng().gen();
        entropy.append(&mut entropy_part2.to_vec());
    }

    let res = T::new(&entropy, "Trial nonce".as_bytes(), "Trial pers".as_bytes(), &mut 256);

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

    let res = drbg.reseed(&entropy, Some("Add-in reseed".as_bytes()));

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
fn reseed_fail<T: DRBG_Mechanism_Functions>() -> usize{
    let mut entropy = Vec::<u8>::new();
    let entropy_part: [u8; 32] = rand::thread_rng().gen();
    entropy.append(&mut entropy_part.to_vec());

    if T::drbg_name() == "CTR-DRBG" {
        let entropy_part2: [u8; 16] = rand::thread_rng().gen();
        entropy.append(&mut entropy_part2.to_vec());
    }

    let res = T::new(&entropy, "Trial nonce".as_bytes(), "Trial pers".as_bytes(), &mut 256);

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

    res = drbg.reseed("Some reseed entropy".as_bytes(), Some("Add-in reseed".as_bytes()));

    if check_res(res, 1, 
            "reseed_fail".to_string(), 
            AL_NAME.to_string(), 
            "reseeding of zeroized DRBG mechanism succeeded.".to_string(), 
            "reseeding of zeroized DRBG mechanism failed, as expected.".to_string()) != 0{
        return 1;
    }
    0
}