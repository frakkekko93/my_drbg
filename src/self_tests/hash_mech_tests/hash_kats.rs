use serde::Deserialize;
use sha2::Sha256;
use crate::{self_tests::formats::*, mechs::{gen_mech::DRBG_Mechanism_Functions, hash_mech::HashDrbgMech}};

// Runs all kats.
pub fn run_all() -> usize {
    return test_Hash_kats();
}

// Test KATs for HMAC-DRBG mech.
#[allow(non_snake_case)]
pub fn test_Hash_kats() -> usize{
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

    let tests: Vec<Fixture> = serde_json::from_str(include_str!("fixtures/hash_kats.json")).unwrap();

    for test in tests {
        let res = HashDrbgMech::<Sha256>::new(
            &hex::decode(&test.entropy).unwrap(),
            &hex::decode(&test.nonce).unwrap(),
            &hex::decode(&test.pers.unwrap_or("".to_string())).unwrap());

        let mut drbg;

        match res{
            None => {
                write_to_log(format_message(true, "Hash-DRBG-Mech".to_string(),
                                    "hash_kats".to_string(), 
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
            
            if check_res(result, expected, test.name, "hash_kats".to_string(), 
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

                if check_res(result, expected, test.name, "hash_kats".to_string(), 
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
                
                if check_res(result, expected, test.name, "hash_kats".to_string(), 
                    "failed generation without prr.".to_string(),
                    "completed generation without prr.".to_string()) != 0 {
                    return 1;
                }
            }
        }
    }

    0
}