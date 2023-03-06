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
    let bits =  my_drbg::get_entropy_input::<U16>();
    let sliced_bits = bits.as_slice();

    println!("\nEntropy source returned: \n{}", show(&sliced_bits));
    println!("Size: {}\n", sliced_bits.len());
}