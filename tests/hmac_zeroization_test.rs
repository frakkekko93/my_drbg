use my_drbg::mechs::hmac::HmacDrbgMech;
use sha2::Sha256;

/*  Testing that the internal state of an HMAC-DRBG mechanism
    is actually zeroized after a call to the zeroize function. */
#[test]
fn test_zeroization(){
    let mut drbg = HmacDrbgMech::<Sha256>::new(
        "Trial entropy".as_bytes(),
        "Trial nonce".as_bytes(),
        "Trial pers".as_bytes()
    );

    let mut res = drbg.zeroize();

    assert_eq!(res, 0);
    assert!(drbg._is_zeroized());

    let mut result = Vec::<u8>::new();

    res = drbg.generate(&mut result, 32, None);

    assert!(result.is_empty());
    assert_eq!(res, 1);

    res = drbg.reseed("Trial entropy 2".as_bytes(), None);

    assert_eq!(res, 1);

    res = drbg.zeroize();

    assert_eq!(res, 1);
}