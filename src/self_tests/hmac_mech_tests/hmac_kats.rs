use serde::Deserialize;
use sha2::Sha256;
use crate::{self_tests::formats::*, mechs::{hmac_mech::HmacDrbgMech, gen_mech::DRBG_Mechanism_Functions}};

// Runs all kats.
pub fn run_all() -> usize {
    return test_HMAC_kats() + nist_vectors();
}

// Test KATs for HMAC-DRBG mech.
#[allow(non_snake_case)]
pub fn test_HMAC_kats() -> usize{
    #[derive(Deserialize, Debug)]
    struct Fixture {
        name: String,
        entropy: String,
        nonce: String,
        pers: Option<String>,
        prr: bool,
        reseed_entropy: Option<String>,
        add: [Option<String>; 2],
        double_gen: bool,
        expected: String,
    }

    let tests: Vec<Fixture> = serde_json::from_str(include_str!("fixtures/hmac_kats.json")).unwrap();

    for test in tests {
        let res = HmacDrbgMech::<Sha256>::new(
            &hex::decode(&test.entropy).unwrap(),
            &hex::decode(&test.nonce).unwrap(),
            &hex::decode(&test.pers.unwrap_or("".to_string())).unwrap());

        let mut drbg;

        match res{
            None => {
                write_to_log(format_message(true, "HMAC-DRBG-Mech".to_string(),
                                    "hmac_kats".to_string(), 
                                    "failed to instantiate DRBG.".to_string()
                                )
                );
                return 1;
            }
            Some(inst) => {
                drbg = inst;
            }
        }

        let expected = hex::decode(&test.expected).unwrap();
        let reseed_entropy = match test.reseed_entropy {
            Some(entr) => hex::decode(&entr).unwrap(),
            None => Vec::<u8>::new()};
        let mut result = Vec::new();
        let full_len = expected.len();
        let add0 = match test.add[0] {
            Some(ref add_in) => Some(hex::decode(&add_in).unwrap()),
            None => None};
        let add1 = match test.add[1] {
            Some(ref add_in) => Some(hex::decode(&add_in).unwrap()),
            None => None};
        
        // Testing the use of prediction resistance request on a single generate (reseed is triggered before generating).
        if test.prr {
            drbg.reseed(&reseed_entropy, 
                match add0 {
                    Some(ref add_in) => Some(&add_in.as_slice()),
                    None => None
                });
            
            drbg.generate(&mut result, full_len, None);
            
            if check_res(result, expected, test.name, "hmac_kats".to_string(), 
                            "failed generation using prr.".to_string(),
                            "completed generation using prr.".to_string()) != 0 {
                return 1;
            }
        }
        else {
            // Testing double consecutive generation using possibly two additional inputs.
            if test.double_gen {
                drbg.generate(&mut result, full_len, 
                    match add0 {
                    Some(ref add_in) => Some(&add_in.as_slice()),
                    None => None
                });
                
                result.clear();
                drbg.generate(&mut result, full_len, 
                    match add1 {
                        Some(ref add_in) => Some(&add_in.as_slice()),
                        None => None
                    });
                
                if check_res(result, expected, test.name, "hmac_kats".to_string(), 
                    "failed double generation without prr.".to_string(),
                    "completed double generation without prr.".to_string()) != 0 {
                    return 1;
                }
            }
            else {
                // Testing generate with no prediction resistance request and optional additional input.
                drbg.generate(&mut result, full_len, 
                    match add0 {
                        Some(ref add_in) => Some(&add_in.as_slice()),
                        None => None
                    });
                
                if check_res(result, expected, test.name, "hmac_kats".to_string(), 
                    "failed generation without prr.".to_string(),
                    "completed generation without prr.".to_string()) != 0 {
                    return 1;
                }
            }
        }
    }

    0
}

/*  This test is designed to perform KATs over some predefined vectors taken directly from NIST. */
pub fn nist_vectors() -> usize{
    #[derive(Deserialize, Debug)]
    struct Fixture {
        name: String,
        entropy: String,
        nonce: String,
        pers: Option<String>,
        add: [Option<String>; 2],
        expected: String,
    }

    let tests: Vec<Fixture> = serde_json::from_str(include_str!("fixtures/hmac_nist_vectors.json")).unwrap();

    for test in tests {
        let mut name = "nist_vectors::".to_string();
        name.push_str(&test.name);

        let res = HmacDrbgMech::<Sha256>::new(
            &hex::decode(&test.entropy).unwrap(),
            &hex::decode(&test.nonce).unwrap(),
            &hex::decode(&test.pers.unwrap_or("".to_string())).unwrap());
        
        let mut drbg;
        match res{
            None => {
                write_to_log(format_message(true, "hmac_kats".to_string(),
                                    "nist_vectors".to_string(), 
                                    "failed to instantiate DRBG.".to_string()
                                )
                );
                return 1;
            }
            Some(inst) => {
                drbg = inst;
            }
        }

        let expected = hex::decode(&test.expected).unwrap();
        let mut result = Vec::new();
        let full_len = expected.len();
        let add0 = test.add[0].as_ref().map(|v| hex::decode(&v).unwrap());
        let add1 = test.add[1].as_ref().map(|v| hex::decode(&v).unwrap());

        drbg.generate(&mut result, full_len,
                               match add0 {
                                   Some(ref add0) => Some(add0.as_ref()),
                                   None => None,
                               });

        result.clear();
        drbg.generate(&mut result, full_len,
                               match add1 {
                                   Some(ref add1) => Some(add1.as_ref()),
                                   None => None,
                               });
        
        if check_res(result, expected, name, "hmac_kats".to_string(), 
            "failed nist vector generation.".to_string(),
            "completed nist vector generation.".to_string()) != 0 {
            return 1;
        }
    }

    write_to_log(format_message(false, "hmac_kats".to_string(),
                                                            "nist_vectors".to_string(), 
                                                            "all nist vectors have passed.".to_string())
    );

    return 0;
}