use serde::Deserialize;

use crate::{mechs::gen_mech::DRBG_Mechanism_Functions, self_tests::formats::{write_to_log, format_message, check_res}};

/*  This test is designed to perform KATs over some predefined vectors taken directly from NIST. */
pub fn nist_vectors<T: DRBG_Mechanism_Functions>() -> usize{
    #[derive(Deserialize, Debug)]
    struct Fixture {
        name: String,
        entropy: String,
        nonce: String,
        pers: Option<String>,
        add: [Option<String>; 2],
        expected: String,
    }

    let tests: Vec<Fixture>;
    let alg_name;

    if T::drbg_name() == "Hash-DRBG" {
        // tests = serde_json::from_str(include_str!("fixtures/hash_kats.json")).unwrap();
        return 0;
    }
    else if T::drbg_name() == "HMAC-DRBG"{
        tests = serde_json::from_str(include_str!("fixtures/hmac_nist_vectors.json")).unwrap();
        alg_name = "HMAC-DRBG-Mech".to_string();
    }
    else {
        return 0;
    }

    // let tests: Vec<Fixture> = serde_json::from_str(include_str!("fixtures/hmac_nist_vectors.json")).unwrap();

    for test in tests {
        // let mut name = "nist_vectors::".to_string();
        // name.push_str(&test.name);

        let res = T::new(
            &hex::decode(&test.entropy).unwrap(),
            &hex::decode(&test.nonce).unwrap(),
            &hex::decode(&test.pers.unwrap_or("".to_string())).unwrap());
        
        let mut drbg;
        match res{
            None => {
                write_to_log(format_message(true, alg_name.clone(),
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
        
        if check_res(result, expected, test.name, "nist_vectors".to_string(), 
            "failed nist vector generation.".to_string(),
            "completed nist vector generation.".to_string()) != 0 {
            return 1;
        }
    }

    write_to_log(format_message(false, alg_name.clone(),
                                                            "nist_vectors".to_string(), 
                                                            "all nist vectors have passed.".to_string())
    );

    return 0;
}