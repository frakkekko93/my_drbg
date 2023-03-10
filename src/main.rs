use std::ascii::escape_default;
use std::str;

extern crate my_drbg;
use my_drbg::drbgs::gen_drbg::{DRBG, DRBG_Functions};
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
    let gen_res = DRBG::<HmacDrbgMech::<Sha256>>::new(256, Some("Pers string".as_bytes()));

    let mut drbg;
    match gen_res{
        Err(err) => {
            panic!("\nMAIN: instantiation failed with error: {}", err);
        }
        Ok(inst) => {
            println!("\nMAIN: instantiated a new HMAC-DRBG.");
            drbg = inst;
        }
    }

    let mut bits= Vec::<u8>::new();
    let mut res = drbg.generate(&mut bits, 128, 256, true, Some("Some additional input".as_bytes()));

    if res > 0 {
        panic!("MAIN: generation failed with error: {}", res);
    }
    else{
        println!("MAIN: generated {} bits: {}", bits.len()*8, hex::encode(show(&bits)));
    }

    res = drbg.reseed(Some("Another very interisting additional input.".as_bytes()));

    if res > 0 {
        panic!("MAIN: reseeding failed with error: {}", res);
    }
    else{
        println!("MAIN: reseeded DRBG.");
    }

    res = drbg.uninstantiate();

    if res > 0 {
        panic!("MAIN: uninstantiation failed with error: {}", res);
    }
    else{
        println!("MAIN: uninstantiated DRBG.");
    }
}