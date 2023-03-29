use crate::mechs::ctr_mech::CtrDrbgMech;
use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::mechs::hash_mech::HashDrbgMech;
use crate::mechs::hmac_mech::HmacDrbgMech;
use rand::Rng;
use sha2::*;
use crate::self_tests::formats::*;
use des::*;

const AL_NAME: &str = "MECH-TESTS::instantiation_test";

/*  Aggregator that runs all the tests in this file. */
pub fn run_tests<T: DRBG_Mechanism_Functions>() -> usize {
    if T::drbg_name() == "HMAC-DRBG" {
        return norm_op::<T>() +
                test_fun_not_approved::<HmacDrbgMech<Sha224>>("Sha 224") + 
                test_fun_not_approved::<HmacDrbgMech<Sha384>>("Sha 384") + 
                test_fun_not_approved::<HmacDrbgMech<Sha512Trunc224>>("Sha 512/224") +
                test_fun_not_approved::<HmacDrbgMech<Sha512Trunc256>>("Sha 512/256") +
                test_empty_entropy::<T>() +
                test_empty_nonce::<T>();
    }
    else if T::drbg_name() == "Hash-DRBG" {
        return norm_op::<T>() +
                test_fun_not_approved::<HashDrbgMech<Sha224>>("Sha 224") + 
                test_fun_not_approved::<HashDrbgMech<Sha384>>("Sha 384") + 
                test_fun_not_approved::<HashDrbgMech<Sha512Trunc224>>("Sha 512/224") +
                test_fun_not_approved::<HashDrbgMech<Sha512Trunc256>>("Sha 512/256") +
                test_empty_entropy::<T>() +
                test_empty_nonce::<T>();
    }
    else {
        return norm_op::<T>() +
                test_fun_not_approved::<CtrDrbgMech<TdesEde2>>("TdesEde2") + 
                test_fun_not_approved::<CtrDrbgMech<TdesEde3>>("TdesEde3") + 
                test_fun_not_approved::<CtrDrbgMech<TdesEee2>>("TdesEee2") +
                test_fun_not_approved::<CtrDrbgMech<TdesEee3>>("TdesEee3") +
                test_empty_entropy::<T>() +
                test_empty_nonce::<T>();
    }
}

/*  Testing normal instantiation of the mechanism. */
fn norm_op<T: DRBG_Mechanism_Functions>() -> usize{
    let mut entropy = Vec::<u8>::new();
    let entropy_part: [u8; 32] = rand::thread_rng().gen();
    entropy.append(&mut entropy_part.to_vec());

    if T::drbg_name() == "CTR-DRBG" {
        let entropy_part2: [u8; 16] = rand::thread_rng().gen();
        entropy.append(&mut entropy_part2.to_vec());
    }

    let res = T::new(&entropy, "Trial nonce".as_bytes(), "Trial pers".as_bytes(), &mut 128);

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
fn test_fun_not_approved<T: DRBG_Mechanism_Functions>(fun_id: &str) -> usize{
    let mut entropy = Vec::<u8>::new();
    let entropy_part: [u8; 32] = rand::thread_rng().gen();
    entropy.append(&mut entropy_part.to_vec());

    if T::drbg_name() == "CTR-DRBG" {
        let entropy_part2: [u8; 16] = rand::thread_rng().gen();
        entropy.append(&mut entropy_part2.to_vec());
    }

    let res = T::new(&entropy, "Trial nonce".as_bytes(), "Trial pers".as_bytes(), &mut 128);

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
fn test_empty_entropy<T: DRBG_Mechanism_Functions>() -> usize {
    let res = T::new("".as_bytes(), "Trial nonce".as_bytes(), "Trial pers".as_bytes(), &mut 128);

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
fn test_empty_nonce<T: DRBG_Mechanism_Functions>() -> usize {
    let mut entropy = Vec::<u8>::new();
    let entropy_part: [u8; 32] = rand::thread_rng().gen();
    entropy.append(&mut entropy_part.to_vec());

    if T::drbg_name() == "CTR-DRBG" {
        let entropy_part2: [u8; 16] = rand::thread_rng().gen();
        entropy.append(&mut entropy_part2.to_vec());
    }

    let res = T::new(&entropy, "".as_bytes(), "Trial pers".as_bytes(), &mut 128);

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