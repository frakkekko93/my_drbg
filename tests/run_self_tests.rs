use rust_nist_drbg::self_tests;

#[test]
fn self_tests () {
    let res = self_tests::run_tests::run_all();

    assert_eq!(res, 0);
}