use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::self_tests::formats::*;

/*  Testing that the internal state of a mechanism
    is actually zeroized after a call to the zeroize function. */
pub fn test_zeroization<T: DRBG_Mechanism_Functions>() -> usize {
    let al_name;

    if T::drbg_name() == "HMAC-DRBG" {
        al_name = "hmac_zeroization_test".to_string();
    }
    else if T::drbg_name() == "Hash-DRBG"{
        al_name = "hash_zeroization_test".to_string();
    }
    else {
        //al_name = "ctr_zeroization_test".to_string();
        return 0;
    }
    
    let res = T::new(
        "Trial entropy".as_bytes(),
        "Trial nonce".as_bytes(),
        "Trial pers".as_bytes()
    );

    let mut drbg;
        match res{
            None => {
                write_to_log(format_message(true, al_name,
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
            "zeroization_test".to_string(), 
            "zeroization failed, DRBG not zeroized.".to_string(), 
            "zeroization succeeded, internal state is now unusable.".to_string()) != 0{
        return 1;
    }

    let mut result = Vec::<u8>::new();

    res = drbg.generate(&mut result, 32, None);
    
    if check_res(res, 1, 
            "test_zeroized_generate".to_string(), 
            "zeroization_test".to_string(), 
            "succeeded to generate with zeroized DRBG.".to_string(), 
            "failed to generate with zeroized DRBG, as expected.".to_string()) != 0{
        return 1;
    }

    res = drbg.reseed("Trial entropy 2".as_bytes(), None);
    
    if check_res(res, 1, 
            "test_zeroized_reseed".to_string(), 
            "zeroization_test".to_string(), 
            "succeeded to reseed zeroized DRBG.".to_string(), 
            "failed to reseed zeroized DRBG, as expected.".to_string()) != 0{
        
        return 1;
    }
    
    res = drbg.zeroize();

    if check_res(res, 1, 
            "test_double_zeroization".to_string(), 
            "zeroization_test".to_string(), 
            "succeeded to zeroize DRBG twice.".to_string(), 
            "failed to zeroize DRBG twice, as expected.".to_string()) != 0{
    
        return 1;
    }
    return 0;
}