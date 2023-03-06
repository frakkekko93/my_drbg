pub mod drbg_mech;
use generic_array::{ArrayLength, GenericArray};
use sha2::Sha256;
use rand::*;

use drbg_mech::hmac::*;

pub fn instantiate(ps: Option<&[u8]>) {

}

pub fn reseed(){

}

pub fn generate(){

}

pub fn uninstantiate(){

}

/*  This function is used to retrieve entropy bits directly from the underlying entropy source that is available. 
    For the moment we are assuming that the underlying source of entropy returns FULL ENTROPY bits.

    T: number of random BYTES to be generated.
*/
pub fn get_entropy_input<T: ArrayLength<u8>>() -> GenericArray::<u8, T>{
    const CHUNK_DIM: usize = 16;                        //Bytes are generated at a CHUNK_DIM-wide chunk ratio (CHUNK_DIM*8 bits at a time)
    let mut tmp: [u8; CHUNK_DIM] = [0; CHUNK_DIM];
    
    let mut result:GenericArray<u8, T> = GenericArray::default();

    /* Generate CHUNK_DIM bytes at a type and copy into result */
    let mut count = 0;
    let mut end = false;
    while count < result.len() && !end {
        rand::thread_rng().fill(&mut tmp);
        for j in 0..tmp.len() {

            /* The requested number of bytes has been reached, stop generation */
            if count+j >= result.len(){
                end = true;
                break;
            }
            result[count + j] = tmp[j];
        }
        count += CHUNK_DIM;
    }

    result
}