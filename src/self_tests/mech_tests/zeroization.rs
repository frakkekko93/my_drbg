use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::self_tests::formats::*;

/*  Testing that the internal state of an HMAC-DRBG mechanism
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
        al_name = "ctr_zeroization_test".to_string();
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
                                    "test_zeroization".to_string(), 
                                    "failed to instantiate DRBG.".to_string()
                                )
                );

                return 1;
            }
            Some(inst) => {
                drbg = inst;
            }
    }

    let mut res = drbg.zeroize();

    if res != 0 || !drbg._is_zeroized() {
        write_to_log(format_message(true, al_name,
                                    "test_zeroization".to_string(), 
                                    "zeroization failed, DRBG not zeroized.".to_string()
                                )
        );

        return 1;
    }

    let mut result = Vec::<u8>::new();

    res = drbg.generate(&mut result, 32, None);

    if res != 1 && drbg._is_zeroized() {
        write_to_log(format_message(true, al_name,
                                    "test_zeroization".to_string(), 
                                    "succeeded to generate with zeroized DRBG.".to_string()
                                )
        );

        return 1;
    }

    res = drbg.reseed("Trial entropy 2".as_bytes(), None);

    if res != 1 && drbg._is_zeroized() {
        write_to_log(format_message(true, al_name,
                                    "test_zeroization".to_string(), 
                                    "succeeded to reseed with zeroized DRBG.".to_string()
                                )
        );

        return 1;
    }

    write_to_log(format_message(false, al_name,
                                                            "test_zeroization".to_string(), 
                                                            "DRBG has been succesfully zeroized.".to_string())
    );

    return 0;
}