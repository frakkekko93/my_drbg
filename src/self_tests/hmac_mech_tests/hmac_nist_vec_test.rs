use crate::mechs::{hmac_mech::HmacDrbgMech, gen_mech::DRBG_Mechanism_Functions};
use sha2::Sha256;
use serde::Deserialize;
use crate::self_tests::formats::format_message;

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
        let res = HmacDrbgMech::<Sha256>::new(
            &hex::decode(&test.entropy).unwrap(),
            &hex::decode(&test.nonce).unwrap(),
            &hex::decode(&test.pers.unwrap_or("".to_string())).unwrap());
        
        let mut drbg;
        match res{
            None => {
                println!("{}", format_message(true, "HMAC-DRBG-Mech".to_string(),
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
        
        if result != expected {
            let mut failed_test = "nist_vectors:".to_string();
            failed_test.push_str(&test.name);

            println!("{}", format_message(true, "HMAC-DRBG-Mech".to_string(),
                                    failed_test, 
                                    "succeeded to instantiate DRBG using Sha 224, which is not approved.".to_string()
                                )
            );

            return 1;
        }
    }

    println!("{}", format_message(false, "HMAC-DRBG-Mech".to_string(),
                                    "nist_vectors".to_string(), 
                                    "all nist vectors have passed.".to_string()
                                )
    );

    return 0;
}