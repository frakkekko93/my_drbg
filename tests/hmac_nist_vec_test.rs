use my_drbg::mechs::hmac_mech::HmacDrbgMech;
use sha2::Sha256;
use serde::Deserialize;

#[test]
fn nist_vectors(){
    #[derive(Deserialize, Debug)]
    struct Fixture {
        name: String,
        entropy: String,
        nonce: String,
        pers: Option<String>,
        add: [Option<String>; 2],
        expected: String,
    }

    let tests: Vec<Fixture> = serde_json::from_str(include_str!("./fixtures/hmac_nist_vectors.json")).unwrap();

    for test in tests {
        let res = HmacDrbgMech::<Sha256>::new(
            &hex::decode(&test.entropy).unwrap(),
            &hex::decode(&test.nonce).unwrap(),
            &hex::decode(&test.pers.unwrap_or("".to_string())).unwrap());
        
        let mut drbg;
        match res{
            None => {
                panic!("NIST VECTORS: drbg instantiation failed.")
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

        println!("TEST {}\n", test.name);
        assert_eq!(result, expected);
    }
}