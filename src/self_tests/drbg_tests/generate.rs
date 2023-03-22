use crate::drbgs::gen_drbg::{DRBG, DRBG_Functions};
use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::self_tests::formats::*;

/*  Aggregator that runs all the tests in this file. */
pub fn run_tests<T: DRBG_Mechanism_Functions>() -> usize {
    return norm_op::<T>() +
            non_empty_out_vec::<T>() +
            int_state_not_valid::<T>() +
            req_too_many_bytes::<T>() +
            ss_not_supported::<T>() +
            add_in_too_long::<T>();
}

/*  Verifying that the reseed of an invalid internal state is not allowed. */
fn norm_op<T: DRBG_Mechanism_Functions>() -> usize{
    let res = DRBG::<T>::new(256, None);
    let mut drbg;
    let mut bits = Vec::<u8>::new();
    let add_in: [u8; 32] = [0; 32];

    match res{
        Err(_) => {
            write_to_log(format_message(true, "HMAC-DRBG".to_string(),
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

    let res = drbg.generate(&mut bits, 128, 256, true, Some(add_in.as_slice()));

    return check_res(res, 0, 
        "norm_op".to_string(), 
        "generate_test".to_string(), 
        "generate normal operation failed.".to_string(), 
        "success on generate normal operation.".to_string());
}

/*  Verifying that an intially non-empty output vector is refused. */
fn non_empty_out_vec<T: DRBG_Mechanism_Functions>() -> usize {
    let res = DRBG::<T>::new(256, None);
    let mut drbg;
    let mut bits = Vec::<u8>::new();
    bits.push(0x00);

    match res{
        Err(_) => {
            write_to_log(format_message(true, "HMAC-DRBG".to_string(),
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

    let res = drbg.generate(&mut bits, 128, 256, false, None);

    return check_res(res, 1, 
        "non_empty_out_vec".to_string(), 
        "generate_test".to_string(), 
        "generate on non-empty out vector succeeded.".to_string(), 
        "generate on non-empty out vector failed as expected.".to_string());
}

/*  Verifying that a generate on an invalid internal state is refused. */
fn int_state_not_valid<T: DRBG_Mechanism_Functions>() -> usize {
    let res = DRBG::<T>::new(256, None);
    let mut drbg;
    let mut bits = Vec::<u8>::new();

    match res{
        Err(_) => {
            write_to_log(format_message(true, "HMAC-DRBG".to_string(),
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

    drbg.uninstantiate();
    let res = drbg.generate(&mut bits, 128, 256, false, None);

    return check_res(res, 2, 
        "int_state_not_valid".to_string(), 
        "generate_test".to_string(), 
        "generate on invalid empty state succeeded.".to_string(), 
        "generate on invalid empty state failed as expected.".to_string());
}

/*  Verifying that a request of too many pseudo-random bits is actually refused. */
fn req_too_many_bytes<T: DRBG_Mechanism_Functions>() -> usize {
    let res = DRBG::<T>::new(256, None);
    let mut drbg;
    let mut bits = Vec::<u8>::new();

    match res{
        Err(_) => {
            write_to_log(format_message(true, "HMAC-DRBG".to_string(),
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

    let res = drbg.generate(&mut bits, 129, 256, false, None);

    return check_res(res, 3, 
        "req_too_many_bytes".to_string(), 
        "generate_test".to_string(), 
        "generated too many bytes.".to_string(), 
        "refused to generate too many bytes as expected.".to_string());
}

/*  Verifying that a security strength that is not supported is actually refused. */
fn ss_not_supported<T: DRBG_Mechanism_Functions>() -> usize {
    let res = DRBG::<T>::new(256, None);
    let mut drbg;
    let mut bits = Vec::<u8>::new();

    match res{
        Err(_) => {
            write_to_log(format_message(true, "HMAC-DRBG".to_string(),
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

    let res = drbg.generate(&mut bits, 128, 512, false, None);

    return check_res(res, 4, 
        "ss_not_supported".to_string(), 
        "generate_test".to_string(), 
        "generated bytes with unsufficient security strength.".to_string(), 
        "refused to generate bytes on not supported security strength as expected.".to_string());
}

/*  Verifying that a too long additional input is actually refused. */
fn add_in_too_long<T: DRBG_Mechanism_Functions>() -> usize {
    let res = DRBG::<T>::new(256, None);
    let mut drbg;
    let mut bits = Vec::<u8>::new();
    let add_in: [u8; 33] = [0; 33];

    match res{
        Err(_) => {
            write_to_log(format_message(true, "HMAC-DRBG".to_string(),
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

    let res = drbg.generate(&mut bits, 128, 256, false, Some(add_in.as_slice()));

    return check_res(res, 5, 
        "add_in_too_long".to_string(), 
        "generate_test".to_string(), 
        "generated bytes on additional input too long.".to_string(), 
        "refused to generate bytes on on additional input too long as expected.".to_string());
}