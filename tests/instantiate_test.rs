/*  Testing that non supported security strengths are actually regected by the DRBG. */
#[test]
fn test_ss_not_supported(){
    let res = my_drbg::DRBG::new(512, None);
    let mut err= 0;
    let mut drbg = None;

    match res{
        Err(error) => {
            err = error
        }
        Ok(inst) => {
            drbg = Some(inst);
        }
    }

    assert_eq!(err, 1);
    assert!(drbg.is_none());
}

/*  Testing that the limit on the length of the personalization string is actually enforced. */
#[test]
fn ps_is_too_long(){
    let ps: [u8; 33] = [0; 33];
    let res = my_drbg::DRBG::new(256, Some(&ps));
    let mut err= 0;
    let mut drbg = None;

    match res{
        Err(error) => {
            err = error
        }
        Ok(inst) => {
            drbg = Some(inst);
        }
    }

    assert_eq!(err, 2);
    assert!(drbg.is_none());
}

/*  Testing that the appropriate security strength is set when 128 bits are needed. */
#[test]
fn set_appropriate_ss_128(){
    let mut res;
    let mut err= 0;
    let mut drbg = None;

    let mut req_str: usize = 0;
    while req_str <= 128 {
        res = my_drbg::DRBG::new(req_str, None);

        match res{
            Err(error) => {
                err = error
            }
            Ok(inst) => {
                drbg = Some(inst);
            }
        }

        assert_eq!(err, 0);
        assert!(drbg.is_some());
        assert_eq!(drbg.as_mut().unwrap().get_sec_str(), 128);

        err = 0;
        drbg = None;
        req_str += 64;
    }
}

/*  Testing that the appropriate security strength is set when 192 bits are needed. */
#[test]
fn set_appropriate_ss_192(){
    let mut res;
    let mut err= 0;
    let mut drbg = None;

    let mut req_str: usize = 160;
    while req_str <= 192 {
        res = my_drbg::DRBG::new(req_str, None);

        match res{
            Err(error) => {
                err = error
            }
            Ok(inst) => {
                drbg = Some(inst);
            }
        }

        assert_eq!(err, 0);
        assert!(drbg.is_some());
        assert_eq!(drbg.as_mut().unwrap().get_sec_str(), 192);

        err = 0;
        drbg = None;
        req_str += 32;
    }
}

/*  Testing that the appropriate security strength is set when 256 bits are needed. */
#[test]
fn set_appropriate_ss_256(){
    let mut res;
    let mut err= 0;
    let mut drbg = None;

    let mut req_str: usize = 224;
    while req_str <= 256 {
        res = my_drbg::DRBG::new(req_str, None);

        match res{
            Err(error) => {
                err = error
            }
            Ok(inst) => {
                drbg = Some(inst);
            }
        }

        assert_eq!(err, 0);
        assert!(drbg.is_some());
        assert_eq!(drbg.as_mut().unwrap().get_sec_str(),256);

        err = 0;
        drbg = None;
        req_str += 32;
    }
}