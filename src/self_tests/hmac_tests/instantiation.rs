use crate::drbgs::gen_drbg::{DRBG, DRBG_Functions};
use crate::mechs::hmac_mech::HmacDrbgMech;
use sha2::*;
use crate::self_tests::formats::format_message;

/*  Aggregator that runs all the tests in this file. */
pub fn run_tests() -> usize {
    if test_fun_not_approved_sha224() != 0 {
        return 1;
    }
    else if test_fun_not_approved_sha384() != 0 {
        return 1;
    }
    else if test_fun_not_approved_sha512trunc224() != 0 {
        return 1;
    }
    else if test_fun_not_approved_sha384trunc256() != 0 {
        return 1;
    }
    else if test_ss_not_supported() != 0 {
        return 1;
    }
    else if ps_is_too_long() != 0 {
        return 1;
    }

    0
}

/*  Testing use of unapproved functions. */
fn test_fun_not_approved_sha224() -> usize{
    let res = DRBG::<HmacDrbgMech::<Sha224>>::new(256, None);
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

    if err != 3 || !drbg.is_none() {
        println!("{}", format_message(true, "HMAC-DRBG".to_string(),
                                    "test_fun_not_approved_sha224".to_string(), 
                                    "succeeded to instantiate DRBG using Sha 224, which is not approved.".to_string()
                                )
        );
        return 1;
    }
    else {
        println!("{}", format_message(false, "HMAC-DRBG".to_string(),
                                    "test_fun_not_approved_sha224".to_string(), 
                                    "failed to instantiate DRBG using Sha 224 as expected.".to_string()
                                )
        );
        return 0;
    }
}

fn test_fun_not_approved_sha384() -> usize{
    let res = DRBG::<HmacDrbgMech::<Sha384>>::new(256, None);
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

    if err != 3 || !drbg.is_none() {
        println!("{}", format_message(true, "HMAC-DRBG".to_string(),
                                    "test_fun_not_approved_sha384".to_string(), 
                                    "succeeded to instantiate DRBG using Sha 384, which is not approved.".to_string()
                                )
        );
        return 1;
    }
    else {
        println!("{}", format_message(false, "HMAC-DRBG".to_string(),
                                    "test_fun_not_approved_sha384".to_string(), 
                                    "failed to instantiate DRBG using Sha 384 as expected.".to_string()
                                )
        );
        return 0;
    }
}

fn test_fun_not_approved_sha512trunc224() -> usize{
    let res = DRBG::<HmacDrbgMech::<Sha512Trunc224>>::new(256, None);
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

    if err != 3 || !drbg.is_none() {
        println!("{}", format_message(true, "HMAC-DRBG".to_string(),
                                    "test_fun_not_approved_sha512trunc224".to_string(), 
                                    "succeeded to instantiate DRBG using Sha 512/224, which is not approved.".to_string()
                                )
        );
        return 1;
    }
    else {
        println!("{}", format_message(false, "HMAC-DRBG".to_string(),
                                    "test_fun_not_approved_sha512trunc224".to_string(), 
                                    "failed to instantiate DRBG using Sha 512/224 as expected.".to_string()
                                )
        );
        return 0;
    }
}

fn test_fun_not_approved_sha384trunc256() -> usize{
    let res = DRBG::<HmacDrbgMech::<Sha512Trunc256>>::new(256, None);
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

    if err != 3 || !drbg.is_none() {
        println!("{}", format_message(true, "HMAC-DRBG".to_string(),
                                    "test_fun_not_approved_sha384trunc256".to_string(), 
                                    "succeeded to instantiate DRBG using Sha 384/256, which is not approved.".to_string()
                                )
        );
        return 1;
    }
    else {
        println!("{}", format_message(false, "HMAC-DRBG".to_string(),
                                    "test_fun_not_approved_sha384trunc256".to_string(), 
                                    "failed to instantiate DRBG using Sha 384/256 as expected.".to_string()
                                )
        );
        return 0;
    }
}

/*  Testing that not supported security strengths are actually rejected by the DRBG. */
fn test_ss_not_supported() -> usize{
    let res = DRBG::<HmacDrbgMech::<Sha256>>::new(512, None);
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

    if err != 1 || !drbg.is_none() {
        println!("{}", format_message(true, "HMAC-DRBG".to_string(),
                                    "test_ss_not_supported".to_string(), 
                                    "succeeded to instantiate DRBG using not supported security strength.".to_string()
                                )
        );
        return 1;
    }
    else {
        println!("{}", format_message(false, "HMAC-DRBG".to_string(),
                                    "test_ss_not_supported".to_string(), 
                                    "failed to instantiate DRBG using not supported security strength as expected.".to_string()
                                )
        );
        return 0;
    }
}

/*  Testing that the limit on the length of the personalization string is actually enforced. */
fn ps_is_too_long() -> usize{
    let ps: [u8; 33] = [0; 33];
    let res = DRBG::<HmacDrbgMech::<Sha256>>::new(256, Some(&ps));
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

    if err != 2 || !drbg.is_none() {
        println!("{}", format_message(true, "HMAC-DRBG".to_string(),
                                    "ps_is_too_long".to_string(), 
                                    "succeeded to instantiate DRBG using not supported personalization string.".to_string()
                                )
        );
        return 1;
    }
    else {
        println!("{}", format_message(false, "HMAC-DRBG".to_string(),
                                    "ps_is_too_long".to_string(), 
                                    "failed to instantiate DRBG using not supported personalization string as expected.".to_string()
                                )
        );
        return 0;
    }
}