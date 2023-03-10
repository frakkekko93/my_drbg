use std::ascii::escape_default;
use std::str;

extern crate my_drbg;
use my_drbg::drbgs::gen_drbg::DRBG;
use my_drbg::mechs::hmac_mech::HmacDrbgMech;
use sha2::Sha256;

//  Function that converts a byte array into a string in order to be printed
fn show(bs: &[u8]) -> String {
    let mut visible = String::new();
    for &b in bs {
        let part: Vec<u8> = escape_default(b).collect();
        visible.push_str(str::from_utf8(&part).unwrap());
    }
    visible
}

fn main(){
    let inst_res = DRBG::<HmacDrbgMech::<Sha256>>::new(256, Some("Pers string".as_bytes()));
    let add_in: [u8; 256] = [0; 256];
    let mut drbg;

    match inst_res{
        Ok(inst) => {
            println!("\nMAIN: Instantiated DRBG instance with security strength: {}.\n", inst.get_sec_str());
            drbg = inst;
        }
        Err(err) => {
            println!("\nMAIN: Instantiation failed with error code: {}.\n", err);
            return
        }
    }

    let res_res = drbg.reseed(Some("Additional input".as_bytes()));
    match res_res {
        0 => {
            println!("MAIN: Reseeded DRBG instance.");
        }
        _ => {
            println!("MAIN: Reseeded failed with error code {}.", res_res);
            return
        }
    }

    let mut bits: Vec<u8> = Vec::<u8>::new();
    let mut gen_res = drbg.generate(&mut bits, 128, 256, true, Some(&add_in));

    if gen_res > 0{
        println!("MAIN: first generate failed with error code {}.", gen_res);
    }
    else {
        println!("MAIN: first generate produced bits {}.\t (Len: {})", show(bits.as_slice()), bits.len() * 8);
    }

    drbg.uninstantiate();
    gen_res = drbg.generate(&mut bits, 128, 256, true, Some(&add_in));

    if gen_res > 0{
        println!("MAIN: second generate failed with error code {}.", gen_res);
    }
    else {
        println!("MAIN: second generate produced bits {}.\t (Len: {})", show(bits.as_slice()), bits.len() * 8);
    }
}