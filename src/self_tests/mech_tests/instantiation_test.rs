use crate::mechs::ctr_mech::CtrDrbgMech;
use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::mechs::hash_mech::HashDrbgMech;
use crate::mechs::hmac_mech::HmacDrbgMech;
use crate::self_tests::formats::*;
use crate::self_tests::constants::*;
use sha2::*;
use des::*;

/*  The name of the test module to be printed in the log. */
const AL_NAME: &str = "MECH-TESTS::instantiation_test";

/*  Aggregator that runs all the tests in this file. */
pub fn run_tests<T: DRBG_Mechanism_Functions>(strength: usize) -> usize {
    if T::drbg_name() == "HMAC-DRBG" {
        return norm_op::<T>(strength) +
                test_fun_not_approved::<HmacDrbgMech<Sha224>>("Sha 224", strength) + 
                test_fun_not_approved::<HmacDrbgMech<Sha384>>("Sha 384", strength) + 
                test_fun_not_approved::<HmacDrbgMech<Sha512Trunc224>>("Sha 512/224", strength) +
                test_fun_not_approved::<HmacDrbgMech<Sha512Trunc256>>("Sha 512/256", strength) +
                test_empty_entropy::<T>(strength) +
                test_empty_nonce::<T>(strength) +
                test_entropy_too_short::<T>(strength) +
                test_nonce_too_short::<T>(strength);
    }
    else if T::drbg_name() == "Hash-DRBG" {
        return norm_op::<T>(strength) +
                test_fun_not_approved::<HashDrbgMech<Sha224>>("Sha 224", strength) + 
                test_fun_not_approved::<HashDrbgMech<Sha384>>("Sha 384", strength) + 
                test_fun_not_approved::<HashDrbgMech<Sha512Trunc224>>("Sha 512/224", strength) +
                test_fun_not_approved::<HashDrbgMech<Sha512Trunc256>>("Sha 512/256", strength) +
                test_empty_entropy::<T>(strength) +
                test_empty_nonce::<T>(strength) +
                test_entropy_too_short::<T>(strength) +
                test_nonce_too_short::<T>(strength);
    }
    else {
        return norm_op::<T>(strength) +
                test_fun_not_approved::<CtrDrbgMech<TdesEde2>>("3DES-EDE2", strength) + 
                test_fun_not_approved::<CtrDrbgMech<TdesEde3>>("3DES-EDE3", strength) + 
                test_fun_not_approved::<CtrDrbgMech<TdesEee2>>("3DES-EEE2", strength) +
                test_fun_not_approved::<CtrDrbgMech<TdesEee3>>("3DES-EEE3", strength) +
                test_empty_entropy::<T>(strength) +
                test_empty_nonce::<T>(strength) +
                test_entropy_too_short::<T>(strength);
    }
}

/*  Testing normal instantiation of the mechanism. */
#[allow(const_item_mutation)]
fn norm_op<T: DRBG_Mechanism_Functions>(mut strength: usize) -> usize{
    let res;
    if T::drbg_name() == "CTR-DRBG" {
        res = T::new(&ENTROPY_CTR, "".as_bytes(), &PERS_256[..strength/8], &mut strength);
    }
    else{
        res = T::new(&ENTROPY, &NONCE, &PERS_256[..strength/8], &mut strength);
    }

    if check_res(res.is_none(), false, 
            "norm_op".to_string(), 
            AL_NAME.to_string(), 
            "normal instantiation of DRBG mechanism failed.".to_string(), 
            "normal instantiation of DRBG mechanism succeeded.".to_string()) != 0{
        return 1;
    }
    0
}

/*  Testing use of unapproved functions. */
#[allow(const_item_mutation)]
fn test_fun_not_approved<T: DRBG_Mechanism_Functions>(fun_id: &str, mut strength: usize) -> usize{
    let res;
    if T::drbg_name() == "CTR-DRBG" {
        res = T::new(&ENTROPY_CTR, "".as_bytes(), &PERS_256[..strength/8], &mut strength);
    }
    else {
        res = T::new(&ENTROPY, &NONCE, &PERS_256[..strength/8], &mut strength);
    }

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
            AL_NAME.to_string(), 
            fail_msg, 
            succ_msg) != 0{
        return 1;
    }
    0
}

/*  Testing that instantiation with empty entropy input fails */
#[allow(const_item_mutation)]
fn test_empty_entropy<T: DRBG_Mechanism_Functions>(mut strength: usize) -> usize {
    let res;
    if T::drbg_name() == "CTR-DRBG" {
        res = T::new("".as_bytes(), "".as_bytes(), &PERS_256[..strength/8], &mut strength);
    }
    else {
        res = T::new("".as_bytes(), &NONCE, &PERS_256[..strength/8], &mut strength);
    }

    if check_res(res.is_none(), true, 
            "test_empty_entropy".to_string(), 
            AL_NAME.to_string(), 
            "instantiation with empty entropy of DRBG mechanism succeeded.".to_string(), 
            "instantiation with empty entropy of DRBG mechanism failed, as expected.".to_string()) != 0{
        return 1;
    }
    0
}

/*  Testing that instantiation with empty nonce fails */
#[allow(const_item_mutation)]
fn test_empty_nonce<T: DRBG_Mechanism_Functions>(mut strength: usize) -> usize {
    let res;
    if T::drbg_name() == "CTR-DRBG" {
        res = T::new(&ENTROPY_CTR, "".as_bytes(), &PERS_256[..strength/8], &mut strength);
    }
    else {
        res = T::new(&ENTROPY, "".as_bytes(), &PERS_256[..strength/8], &mut strength);
    }

    if T::drbg_name() != "CTR-DRBG" {
        if check_res(res.is_none(), true, 
                "test_empty_nonce".to_string(), 
                AL_NAME.to_string(), 
                "instantiation with empty nonce of DRBG mechanism succeeded.".to_string(), 
                "instantiation with empty nonce of DRBG mechanism failed, as expected.".to_string()) != 0{
            return 1;
        }
    }
    else {
        if check_res(res.is_none(), false, 
                "test_empty_nonce".to_string(), 
                AL_NAME.to_string(), 
                "instantiation with empty nonce of DRBG mechanism failed (empty nonce allowed with CTR with no DF).".to_string(), 
                "instantiation with empty nonce of DRBG mechanism succeeded, as expected (empty nonce allowed with CTR with no DF).".to_string()) != 0{
            return 1;
        }
    }

    0
}

/*  Testing that entropy too short is refused by HMAC and Hash mechanisms. */
#[allow(const_item_mutation)]
fn test_entropy_too_short<T: DRBG_Mechanism_Functions>(mut strength: usize) -> usize{
    let res;
    if T::drbg_name() == "CTR-DRBG" {
        res = T::new(&ENTROPY_TOO_SHORT, "".as_bytes(), &PERS_256[..strength/8], &mut strength);
    }
    else {
        res = T::new(&ENTROPY_TOO_SHORT, &NONCE, &PERS_256[..strength/8], &mut strength);
    }

    if check_res(res.is_none(), true, 
            "test_entropy_too_short".to_string(), 
            AL_NAME.to_string(), 
            "instantiation with entropy too short of DRBG mechanism succeeded.".to_string(), 
            "instantiation with entropy too short of DRBG mechanism failed, as expected.".to_string()) != 0{
        return 1;
    }

    0
}

/*  Testing that entropy too short is refused by HMAC and Hash mechanisms. */
#[allow(const_item_mutation)]
fn test_nonce_too_short<T: DRBG_Mechanism_Functions>(mut strength: usize) -> usize{
    let res = T::new(&ENTROPY, &NONCE_TOO_SHORT, &PERS_256[..strength/8], &mut strength);

    if check_res(res.is_none(), true, 
            "test_entropy_too_short".to_string(), 
            AL_NAME.to_string(), 
            "instantiation with nonce too short of DRBG mechanism succeeded.".to_string(), 
            "instantiation with nonce too short of DRBG mechanism failed, as expected.".to_string()) != 0{
        return 1;
    }

    0
}