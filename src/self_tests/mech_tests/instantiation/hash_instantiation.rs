use crate::drbgs::gen_drbg::{DRBG, DRBG_Functions};
use crate::mechs::hash_mech::HashDrbgMech;
use sha2::*;
use crate::self_tests::formats::*;

/*  Aggregator that runs all the tests in this file. */
pub fn run_tests() -> usize {
    return test_fun_not_approved_sha224() + 
            test_fun_not_approved_sha384() + 
            test_fun_not_approved_sha512trunc224() +
            test_fun_not_approved_sha384trunc256();
}

/*  Testing use of unapproved functions. */
fn test_fun_not_approved_sha224() -> usize{
    let res = DRBG::<HashDrbgMech<Sha224>>::new(256, None);
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

    if check_res((err, true), (3, drbg.is_none()), 
            "test_fun_not_approved_sha224".to_string(), 
            "instantiation_test".to_string(), 
            "succeeded to instantiate DRBG using Sha 224, which is not approved.".to_string(), 
            "failed to instantiate DRBG using Sha 224 as expected.".to_string()) != 0{
        return 1;
    }
    0
}

fn test_fun_not_approved_sha384() -> usize{
    let res = DRBG::<HashDrbgMech<Sha384>>::new(256, None);
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

    if check_res((err, true), (3, drbg.is_none()), 
            "test_fun_not_approved_sha384".to_string(), 
            "instantiation_test".to_string(), 
            "succeeded to instantiate DRBG using Sha 384, which is not approved.".to_string(), 
            "failed to instantiate DRBG using Sha 384 as expected.".to_string()) != 0{
        return 1;
    }
    0
}

fn test_fun_not_approved_sha512trunc224() -> usize{
    let res = DRBG::<HashDrbgMech<Sha512Trunc224>>::new(256, None);
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

    if check_res((err, true), (3, drbg.is_none()), 
            "test_fun_not_approved_sha512trunc224".to_string(), 
            "instantiation_test".to_string(), 
            "succeeded to instantiate DRBG using Sha 512/224, which is not approved.".to_string(), 
            "failed to instantiate DRBG using Sha 512/224 as expected.".to_string()) != 0{
        return 1;
    }
    0
}

fn test_fun_not_approved_sha384trunc256() -> usize{
    let res = DRBG::<HashDrbgMech::<Sha512Trunc256>>::new(256, None);
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

    if check_res((err, true), (3, drbg.is_none()), 
    "test_fun_not_approved_sha384trunc256".to_string(), 
    "instantiation_test".to_string(), 
    "succeeded to instantiate DRBG using Sha 384/256, which is not approved.".to_string(), 
    "failed to instantiate DRBG using Sha 384/256 as expected.".to_string()) != 0{
    return 1;
    }
    0
}