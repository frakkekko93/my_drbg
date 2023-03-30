use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::self_tests::formats::*;
use crate::self_tests::constants::*;

/*  The name of the test module to be printed in the log. */
const AL_NAME: &str = "MECH-TESTS::zeroization_test";

/*  Testing that the internal state of a mechanism
    is actually zeroized after a call to the zeroize function. */
#[allow(const_item_mutation)]
pub fn test_zeroization<T: DRBG_Mechanism_Functions>() -> usize {
    let res;
    if T::drbg_name() == "CTR-DRBG" {
        res = T::new(&ENTROPY_CTR, "".as_bytes(), &PERS, &mut SEC_STR);
    }
    else{
        res = T::new(&ENTROPY, &NONCE, &PERS, &mut SEC_STR);
    }

    let mut drbg;
        match res{
            None => {
                write_to_log(format_message(true, AL_NAME.to_string(),
                                    "zeroization_test".to_string(), 
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

    if check_res(res != 0 || !drbg._is_zeroized(), false, 
            "test_zeroization".to_string(), 
            AL_NAME.to_string(), 
            "zeroization failed, DRBG not zeroized.".to_string(), 
            "zeroization succeeded, internal state is now unusable.".to_string()) != 0{
        return 1;
    }

    let mut result = Vec::<u8>::new();

    res = drbg.generate(&mut result, MAX_BYTES, None);
    
    if check_res(res, 1, 
            "test_zeroized_generate".to_string(), 
            AL_NAME.to_string(), 
            "succeeded to generate with zeroized DRBG.".to_string(), 
            "failed to generate with zeroized DRBG, as expected.".to_string()) != 0{
        return 1;
    }

    if T::drbg_name() == "CTR-DRBG" {
        res = drbg.reseed(&ENTROPY_CTR, None);
    }
    else{
        res = drbg.reseed(&ENTROPY, None);
    }
    
    if check_res(res, 1, 
            "test_zeroized_reseed".to_string(), 
            AL_NAME.to_string(), 
            "succeeded to reseed zeroized DRBG.".to_string(), 
            "failed to reseed zeroized DRBG, as expected.".to_string()) != 0{
        
        return 1;
    }
    
    res = drbg.zeroize();

    if check_res(res, 1, 
            "test_double_zeroization".to_string(), 
            AL_NAME.to_string(), 
            "succeeded to zeroize DRBG twice.".to_string(), 
            "failed to zeroize DRBG twice, as expected.".to_string()) != 0{
    
        return 1;
    }
    return 0;
}