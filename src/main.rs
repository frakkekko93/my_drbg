use typenum::*;
use std::ascii::escape_default;
use std::str;

extern crate my_drbg;


// Function that converts a byte array into a string in order to be printed
fn show(bs: &[u8]) -> String {
    let mut visible = String::new();
    for &b in bs {
        let part: Vec<u8> = escape_default(b).collect();
        visible.push_str(str::from_utf8(&part).unwrap());
    }
    visible
}

fn main(){
    let drbg = my_drbg::DRBG::new(512, true, Some("Pers string".as_bytes()), 0);

    match drbg{
        Ok(drbg) => {
            println!("\nInstantiated DRBG instance with security strength: {}.\n", drbg.get_sec_str());
        }
        Err(err) => {
            println!("\nInstantiation failed with error code: {}.\n", err);
        }
    }
}