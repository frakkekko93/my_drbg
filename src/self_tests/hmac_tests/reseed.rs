use crate::drbgs::gen_drbg::{DRBG, DRBG_Functions};
use crate::mechs::hmac_mech::HmacDrbgMech;
use sha2::*;
use crate::self_tests::formats::*;

/*  Aggregator that runs all the tests in this file. */
pub fn run_tests() -> usize {
    return internal_state_not_valid() +
            add_in_too_long();
}

/*  Verifying that the reseed of an invalid internal state is not allowed. */
fn internal_state_not_valid() -> usize{
    let res = DRBG::<HmacDrbgMech::<Sha256>>::new(256, None);
    let mut drbg;

    match res{
        Err(_) => {
            write_to_log(format_message(true, "HMAC-DRBG".to_string(),
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
        "reseed_test".to_string(), 
        "error expected on reseed of empty internal state.".to_string(), 
        "reseed of empty internal state failed es expected.".to_string());
}

/*  Verifying that additional inputs that are too long are rejected. */
fn add_in_too_long() -> usize {
    let res = DRBG::<HmacDrbgMech::<Sha256>>::new(256, None);
    let mut drbg;
    let add_in: [u8; 33] = [0; 33];

    match res{
        Err(_) => {
            write_to_log(format_message(true, "HMAC-DRBG".to_string(),
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

    let res = drbg.reseed(Some(add_in.as_slice()));

    return check_res(res, 2, 
        "add_in_too_long".to_string(), 
        "reseed_test".to_string(), 
        "error expected on additional input too long.".to_string(), 
        "reseed on additional input too long failed es expected.".to_string());
}