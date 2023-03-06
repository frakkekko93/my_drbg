pub mod drbg_mech;
use generic_array::{ArrayLength, GenericArray};
use hmac::Hmac;
use sha2::Sha256;
use rand::*;
use drbg_mech::hmac::*;

use digest::{BlockInput, FixedOutput, Reset, Update};

/* Configuration of the DRBG */
const MAX_SEC_STR: usize = 256;
const PR_SUPPORTED: bool = true;
const MAX_PS_LEN: usize = 256;

pub struct DRBG
{
    security_strength: usize,
    internal_state: HmacDRBG<Sha256>,
}

impl DRBG
{
    /*  This function instantiates a DRBG mechanism. The DRBG mechanism to be instantiated is given by the mech parameter:

        mec:
            0: Hash-DRBG
            1: HMAC-DRBG
            2: CTR-DRBG

        Error codes:
            1: security strength not supported
            2: prediction resistance not supported
            3: personalization string is too long
    */
    pub fn new(req_sec_str: usize, pred_res_flag: bool, ps: Option<&[u8]>, mech: u8) -> Result<Self, u8>{
        if req_sec_str > MAX_SEC_STR{   //Inappropriate security strength
            return Err(1);
        }

        if pred_res_flag && !PR_SUPPORTED{   //Prediction resistance requested and not supported
            return Err(2);
        }

        if ps.is_some() && ps.unwrap().len() > MAX_PS_LEN{   //Personalization string is too long
            return Err(3);
        }

        /*  Retrieve the required entropy input and nonce */
        let mut entropy= Vec::<u8>::new();
        let mut nonce= Vec::<u8>::new();
        let security_strength = DRBG::set_sec_str(req_sec_str);
        DRBG::get_entropy_input(&mut entropy, security_strength);
        DRBG::get_entropy_input(&mut nonce, security_strength/2);

        /*  Instantiate the DRBG mechanism */   
        let drbg_mech = HmacDRBG::new(&entropy.as_slice(), &nonce.as_slice(), &ps.unwrap());

        /*  Returning a pointer to this instance */
        Ok(this = Self{security_strength, internal_state: drbg_mech})
    }

    /* Sets the appropriate security strength with respect to the one requested */
    fn set_sec_str(sec_str: usize)-> usize{
        if sec_str <= 128{
            return 128;
        }
        else if sec_str <= 192{
            return 192;
        }
        else {
            return 256;
        }
    }

    pub fn get_sec_str(&self) -> usize{
        self.security_strength
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
    pub fn get_entropy_input(vec: &mut Vec<u8>, bytes: usize){
        const CHUNK_DIM: usize = 16;                        //Bytes are generated at a CHUNK_DIM-wide chunk ratio (CHUNK_DIM*8 bits at a time)
        let mut tmp: [u8; CHUNK_DIM] = [0; CHUNK_DIM];

        /* Generate CHUNK_DIM bytes at a type and copy into result */
        let mut count = 0;
        let mut end = false;
        while vec.len() < bytes && !end {
            rand::thread_rng().fill(&mut tmp);
            for j in 0..tmp.len() {

                /* The requested number of bytes has been reached, stop generation */
                if count+j >= bytes{
                    end = true;
                    break;
                }
                vec.push(tmp[j]);
            }
            count += CHUNK_DIM;
        }
    }
}
