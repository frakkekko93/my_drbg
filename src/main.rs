// use std::ascii::escape_default;
// use std::str;

extern crate my_drbg;


// Function that converts a byte array into a string in order to be printed
// fn show(bs: &[u8]) -> String {
//     let mut visible = String::new();
//     for &b in bs {
//         let part: Vec<u8> = escape_default(b).collect();
//         visible.push_str(str::from_utf8(&part).unwrap());
//     }
//     visible
// }

fn main(){
    let inst_res = my_drbg::DRBG::new(256, Some("Pers string".as_bytes()));
    
    match inst_res{
        Ok(inst) => {
            println!("\nMAIN: Instantiated DRBG instance with security strength: {}.\n", inst.get_sec_str());
            let mut drbg = inst;
            drbg.reseed(Some("Additional input".as_bytes()));
            println!("MAIN: Reseeded DRBG instance.");
        }
        Err(err) => {
            println!("\nMAIN: Instantiation failed with error code: {}.\n", err);
        }
    }
}