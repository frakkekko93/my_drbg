use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::mechs::hash_mech::HashDrbgMech;
use crate::mechs::hmac_mech::HmacDrbgMech;
use sha2::*;
use crate::self_tests::formats::*;

/*  Aggregator that runs all the tests in this file. */
pub fn run_tests<T: DRBG_Mechanism_Functions>() -> usize {
    if T::drbg_name() == "HMAC-DRBG" {
        return test_fun_not_approved::<HmacDrbgMech<Sha224>>("Sha 224") + 
                test_fun_not_approved::<HmacDrbgMech<Sha384>>("Sha 384") + 
                test_fun_not_approved::<HmacDrbgMech<Sha512Trunc224>>("Sha 512/224") +
                test_fun_not_approved::<HmacDrbgMech<Sha512Trunc256>>("Sha 512/256");
    }
    else if T::drbg_name() == "Hash-DRBG" {
        return test_fun_not_approved::<HashDrbgMech<Sha224>>("Sha 224") + 
                test_fun_not_approved::<HashDrbgMech<Sha384>>("Sha 384") + 
                test_fun_not_approved::<HashDrbgMech<Sha512Trunc224>>("Sha 512/224") +
                test_fun_not_approved::<HashDrbgMech<Sha512Trunc256>>("Sha 512/256");
    }
    else {
        return 0;
    }
}

/*  Testing use of unapproved functions. */
fn test_fun_not_approved<T: DRBG_Mechanism_Functions>(fun_id: &str) -> usize{
    let res = T::new("Trail entropy".as_bytes(), "Trial nonce".as_bytes(), "Trial pers".as_bytes());

    let mut test_name = "test_fun_not_approved::".to_string();
    test_name.push_str(fun_id);

    let mut fail_msg = "succeeded to instantiate DRBG mechanism using ".to_string();
    fail_msg.push_str(fun_id);
    fail_msg.push_str(", non approved behavior.");

    let mut succ_msg = "failed to instantiate DRBG mechanism using ".to_string();
    succ_msg.push_str(fun_id);
    succ_msg.push_str(" as expected.");


    if check_res(res.is_none(), true, 
            test_name, 
            "instantiation_test".to_string(), 
            fail_msg, 
            succ_msg) != 0{
        return 1;
    }
    0
}