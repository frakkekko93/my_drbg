use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::self_tests::formats::*;
use serde::Deserialize;

/*  The name of the test module to be printed in the log. */
const AL_NAME: &str = "MECH-TESTS::nist_vectors";

/*  This test is designed to perform KATs over some predefined vectors taken directly from NIST. */
#[allow(const_item_mutation)]
pub fn test_vectors<T: DRBG_Mechanism_Functions>(fun_id: &str, mut strength: usize) -> usize{
    #[derive(Deserialize, Debug)]
    struct Fixture {
        name: String,
        entropy: String,
        nonce: String,
        pers: Option<String>,
        entropy_reseed: String,
        add_in_reseed: Option<String>,
        add_in_gen: Option<String>,
        add_in_gen2: Option<String>,
        expected: String,
    }

    let tests: Vec<Fixture>;

    if T::drbg_name() == "Hash-DRBG" {
        if fun_id == "Sha 256" {
            tests = serde_json::from_str(include_str!("fixtures/nist_vectors/hash/no_prr/HASH_DRBG_SHA256_pr_false.json")).unwrap();
        }
        else {
            tests = serde_json::from_str(include_str!("fixtures/nist_vectors/hash/no_prr/HASH_DRBG_SHA512_pr_false.json")).unwrap();
        }
    }
    else if T::drbg_name() == "HMAC-DRBG"{
        if fun_id == "Sha 256" {
            tests = serde_json::from_str(include_str!("fixtures/nist_vectors/hmac/no_prr/HMAC_DRBG_SHA256_pr_false.json")).unwrap();
        }
        else {
            tests = serde_json::from_str(include_str!("fixtures/nist_vectors/hmac/no_prr/HMAC_DRBG_SHA512_pr_false.json")).unwrap();
        }
    }
    else {
        if fun_id == "AES 128" {
            tests = serde_json::from_str(include_str!("fixtures/nist_vectors/ctr/no_prr/CTR_DRBG_NO_DF_AES128_pr_false.json")).unwrap();
        }
        else if fun_id == "AES 192" {
            tests = serde_json::from_str(include_str!("fixtures/nist_vectors/ctr/no_prr/CTR_DRBG_NO_DF_AES192_pr_false.json")).unwrap();
        }
        else {
            tests = serde_json::from_str(include_str!("fixtures/nist_vectors/ctr/no_prr/CTR_DRBG_NO_DF_AES256_pr_false.json")).unwrap();
        }
    }

    for test in tests {
        let res = T::new(
            &hex::decode(&test.entropy).unwrap(),
            &hex::decode(&test.nonce).unwrap(),
            &hex::decode(&test.pers.unwrap_or("".to_string())).unwrap(),
            &mut strength
        );
        
        let mut drbg;
        match res{
            None => {
                write_to_log(format_message(true, AL_NAME.to_string(),
                                    "test_vectors".to_string(), 
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
        let ent_reseed = hex::decode(&test.entropy_reseed).unwrap();
        let add_reseed = test.add_in_reseed.as_ref().map(|v| hex::decode(&v).unwrap());
        let add0 = test.add_in_gen.as_ref().map(|v| hex::decode(&v).unwrap());
        let add1 = test.add_in_gen2.as_ref().map(|v| hex::decode(&v).unwrap());

        drbg.reseed(&ent_reseed, match add_reseed {
                                    Some(ref add) => Some(add.as_ref()),
                                    None => None,
                                });
        drbg.generate(&mut result, full_len,
                               match add0 {
                                   Some(ref add0) => Some(add0.as_ref()),
                                   None => None,
                               });

        drbg.generate(&mut result, full_len,
                               match add1 {
                                   Some(ref add1) => Some(add1.as_ref()),
                                   None => None,
                               });
        
        if result != expected {
            let mut message = "nist vector ".to_string();
            message.push_str(&test.name);
            message.push_str(" failed unexpectedly.");
            write_to_log(format_message(false, AL_NAME.to_string(),
                                                            "test_vectors".to_string(), 
                                                            message)
            );
            return 1;
        }
        // if check_res(result.clone(), expected.clone(), test.name, AL_NAME.to_string(), 
        //     "failed nist vector generation.".to_string(),
        //     "completed nist vector generation.".to_string()) != 0 {
            
        //     println!("NIST-VECTORS: expected:\n{}\n\ngot:\n{}", hex::encode(&expected), hex::encode(&result));
        //     return 1;
        // }
    }

    write_to_log(format_message(false, AL_NAME.to_string(),
                                                            "test_vectors".to_string(), 
                                                            "all nist vectors have passed.".to_string())
    );

    return 0;
}