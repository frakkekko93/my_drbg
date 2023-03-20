use my_drbg::drbgs::gen_drbg::{DRBG, DRBG_Functions};
use my_drbg::mechs::hmac_mech::HmacDrbgMech;
use sha2::*;
use my_drbg::self_tests::formats::format_message;

#[test]
fn hmac_drbg_tests () {
    let res = DRBG::<HmacDrbgMech::<Sha256>>::new(256, None);
    let mut drbg;

    match res{
        Err(_) => {
            panic!("{}", format_message(true, "HMAC-DRBG".to_string(),
                                                "self_tests".to_string(), 
                                                "failed to instantiate DRBG.".to_string()
                                            )
            );
        }
        Ok(inst) => {
            drbg = inst;
        }
    }

    println!("{}", format_message(true, "HMAC-DRBG".to_string(),
                                                "self_tests".to_string(), 
                                                "failed to run self tests on HMAC-DRBG.".to_string()
                )
    );

    assert_eq!(0, drbg.run_self_tests());
}