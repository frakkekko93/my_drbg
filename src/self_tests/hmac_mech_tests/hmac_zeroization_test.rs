use crate::mechs::{hmac_mech::HmacDrbgMech, gen_mech::DRBG_Mechanism_Functions};
use sha2::Sha256;
use crate::self_tests::formats::format_message;

/*  Testing that the internal state of an HMAC-DRBG mechanism
    is actually zeroized after a call to the zeroize function. */
pub fn test_zeroization() -> usize {
    let res = HmacDrbgMech::<Sha256>::new(
        "Trial entropy".as_bytes(),
        "Trial nonce".as_bytes(),
        "Trial pers".as_bytes()
    );

    let mut drbg;
        match res{
            None => {
                println!("{}", format_message(true, "HMAC-DRBG-Mech".to_string(),
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
        println!("{}", format_message(true, "HMAC-DRBG-Mech".to_string(),
                                    "test_zeroization".to_string(), 
                                    "zeroization failed, DRBG not zeroized.".to_string()
                                )
        );

        return 1;
    }

    let mut result = Vec::<u8>::new();

    res = drbg.generate(&mut result, 32, None);

    if res != 1 && drbg._is_zeroized() {
        println!("{}", format_message(true, "HMAC-DRBG-Mech".to_string(),
                                    "test_zeroization".to_string(), 
                                    "succeeded to generate with zeroized DRBG.".to_string()
                                )
        );

        return 1;
    }

    res = drbg.reseed("Trial entropy 2".as_bytes(), None);

    if res != 1 && drbg._is_zeroized() {
        println!("{}", format_message(true, "HMAC-DRBG-Mech".to_string(),
                                    "test_zeroization".to_string(), 
                                    "succeeded to reseed with zeroized DRBG.".to_string()
                                )
        );

        return 1;
    }

    println!("{}", format_message(false, "HMAC-DRBG-Mech".to_string(),
                                    "test_zeroization".to_string(), 
                                    "DRBG has been succesfully zeroized.".to_string()
                                )
    );

    return 0;
}