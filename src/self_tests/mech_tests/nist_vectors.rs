use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::self_tests::formats::*;
use serde::Deserialize;

/*  The name of the test module to be printed in the log. */
const AL_NAME: &str = "MECH-TESTS::nist_vectors";

/*  This test is designed to perform KATs over some predefined vectors taken directly from NIST. */
#[allow(const_item_mutation)]
pub fn test_vectors<T: DRBG_Mechanism_Functions>(fun_id: &str, strength: usize) -> usize{
    let (prr_file, no_prr_file) = get_files::<T>(fun_id);

    return test_vectors_no_prr::<T>(no_prr_file, strength) +
            test_vectors_prr::<T>(prr_file, strength);
}

fn get_files<T: DRBG_Mechanism_Functions>(fun_id: &str) -> (&str, &str) {
    let prr_file;
    let no_prr_file;
    if T::drbg_name() == "Hash-DRBG" {
        if fun_id == "Sha 256" {
            no_prr_file = include_str!("fixtures/nist_vectors/hash/no_prr/HASH_DRBG_SHA256_pr_false.json");
            prr_file = include_str!("fixtures/nist_vectors/hash/prr/HASH_DRBG_SHA256_pr_true.json");
        }
        else {
            no_prr_file = include_str!("fixtures/nist_vectors/hash/no_prr/HASH_DRBG_SHA512_pr_false.json");
            prr_file = include_str!("fixtures/nist_vectors/hash/prr/HASH_DRBG_SHA512_pr_true.json");
        }
    }
    else if T::drbg_name() == "HMAC-DRBG"{
        if fun_id == "Sha 256" {
            no_prr_file = include_str!("fixtures/nist_vectors/hmac/no_prr/HMAC_DRBG_SHA256_pr_false.json");
            prr_file = include_str!("fixtures/nist_vectors/hmac/prr/HMAC_DRBG_SHA256_pr_true.json");
        }
        else {
            no_prr_file = include_str!("fixtures/nist_vectors/hmac/no_prr/HMAC_DRBG_SHA512_pr_false.json");
            prr_file = include_str!("fixtures/nist_vectors/hmac/prr/HMAC_DRBG_SHA512_pr_true.json");
        }
    }
    else if T::drbg_name() == "CTR-DRBG" {
        if fun_id == "AES 128" {
            no_prr_file = include_str!("fixtures/nist_vectors/ctr_no_df/no_prr/CTR_DRBG_NO_DF_AES128_pr_false.json");
            prr_file = include_str!("fixtures/nist_vectors/ctr_no_df/prr/CTR_DRBG_NO_DF_AES128_pr_true.json");
        }
        else if fun_id == "AES 192" {
            no_prr_file = include_str!("fixtures/nist_vectors/ctr_no_df/no_prr/CTR_DRBG_NO_DF_AES192_pr_false.json");
            prr_file = include_str!("fixtures/nist_vectors/ctr_no_df/prr/CTR_DRBG_NO_DF_AES192_pr_true.json");
        }
        else {
            no_prr_file = include_str!("fixtures/nist_vectors/ctr_no_df/no_prr/CTR_DRBG_NO_DF_AES256_pr_false.json");
            prr_file = include_str!("fixtures/nist_vectors/ctr_no_df/prr/CTR_DRBG_NO_DF_AES256_pr_true.json");
        }
    }
    else {
        if fun_id == "AES 128" {
            no_prr_file = include_str!("fixtures/nist_vectors/ctr_df/no_prr/CTR_DRBG_DF_AES128_pr_false.json");
            prr_file = include_str!("fixtures/nist_vectors/ctr_df/prr/CTR_DRBG_DF_AES128_pr_true.json");
        }
        else if fun_id == "AES 192" {
            no_prr_file = include_str!("fixtures/nist_vectors/ctr_df/no_prr/CTR_DRBG_DF_AES192_pr_false.json");
            prr_file = include_str!("fixtures/nist_vectors/ctr_df/prr/CTR_DRBG_DF_AES192_pr_true.json");
        }
        else {
            no_prr_file = include_str!("fixtures/nist_vectors/ctr_df/no_prr/CTR_DRBG_DF_AES256_pr_false.json");
            prr_file = include_str!("fixtures/nist_vectors/ctr_df/prr/CTR_DRBG_DF_AES256_pr_true.json");
        }
    }

    (prr_file, no_prr_file)
}

#[allow(dead_code)]
fn test_vectors_prr<T: DRBG_Mechanism_Functions>(prr_file: &str, mut strength: usize) -> usize{
    #[derive(Deserialize, Debug)]
    struct Fixture {
        name: String,
        entropy: String,
        nonce: String,
        pers: Option<String>,
        add_in_gen: Option<String>,
        entropy_pr: String,
        add_in_gen2: Option<String>,
        entropy_pr2: String,
        expected: String,
    }

    let tests: Vec<Fixture> = serde_json::from_str(prr_file).unwrap();

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
                                    "test_vectors_prr".to_string(), 
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
        let ent_pr = hex::decode(&test.entropy_pr).unwrap();
        let ent_pr2 = hex::decode(&test.entropy_pr2).unwrap();
        let add0 = test.add_in_gen.as_ref().map(|v| hex::decode(&v).unwrap());
        let add1 = test.add_in_gen2.as_ref().map(|v| hex::decode(&v).unwrap());

        drbg.reseed(&ent_pr, match add0 {
                                    Some(ref add) => Some(add.as_ref()),
                                    None => None,
                                });
        drbg.generate(&mut result, full_len, None);
        
        drbg.reseed(&ent_pr2, match add1 {
                                    Some(ref add) => Some(add.as_ref()),
                                    None => None,
                                });
        drbg.generate(&mut result, full_len, None);
        
        if result != expected {
            let mut message = "nist vector ".to_string();
            message.push_str(&test.name);
            message.push_str(" failed unexpectedly.");
            write_to_log(format_message(true, AL_NAME.to_string(),
                                                            "test_vectors_prr".to_string(), 
                                                            message)
            );
            return 1;
        }
    }

    write_to_log(format_message(false, AL_NAME.to_string(),
                                                            "test_vectors_prr".to_string(), 
                                                            "all nist vectors have passed.".to_string())
    );

    return 0;
}

fn test_vectors_no_prr<T: DRBG_Mechanism_Functions>(no_prr_file: &str, mut strength: usize) -> usize{
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

    let tests: Vec<Fixture> = serde_json::from_str(no_prr_file).unwrap();

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
                                    "test_vectors_no_prr".to_string(), 
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
            write_to_log(format_message(true, AL_NAME.to_string(),
                                                            "test_vectors_no_prr".to_string(), 
                                                            message)
            );
            return 1;
        }
    }

    write_to_log(format_message(false, AL_NAME.to_string(),
                                                            "test_vectors_no_prr".to_string(), 
                                                            "all nist vectors have passed.".to_string())
    );

    return 0;
}
