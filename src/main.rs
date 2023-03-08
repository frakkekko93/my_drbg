use std::ascii::escape_default;
use std::str;

use typenum::*;

extern crate my_drbg;


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
    let inst_res = my_drbg::DRBG::new(256, Some("Pers string".as_bytes()));
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

    let gen_res = drbg.generate::<U128>(256, true, Some(&add_in));

    match gen_res {
        Err(err) => {
            println!("MAIN: Generate failed with error code {}.", err);
        }
        Ok(bits) => {
            println!("MAIN: generated bits {}.\t (Len: {})", show(bits.as_slice()), bits.len() * 8);
        }
    }
    
}