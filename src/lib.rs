pub mod drbg_mech;
use sha2::Sha256;
use rand::*;
use drbg_mech::hmac::*;
use generic_array::{ArrayLength, GenericArray};

/* Configuration of the DRBG */
const MAX_SEC_STR: usize = 256;
const MAX_PS_LEN: usize = 256;
const MAX_AI_LEN: usize = 256;
const MAX_PRB: usize = 1024;

pub struct DRBG
{
    security_strength: usize,
    internal_state: Option<HmacDRBG<Sha256>>,
}

impl DRBG
{
    /*  This function serves as an evelope to the instantiate algorithm of the underlying DRBG mechanism.
        At the moment, it can only instantiate an HMAC-DRBG mechanism that uses Sha256 supporting a security strength up to 256.
        Note that this function does not have the 'prediction_resistance_flag' parameter as specified in SP 800-90A section 9.1. This is allowed as long as the DRBG
        always provides or do not support prediction resistance. In this particular implementation, the DRBG is implemented to always support prediction resistance.
        This means that calling application may request prediction resistance at any time during bit generation.

        Error codes:
            1 - inappropriate security strength
            2 - personalization string is too long
    */
    pub fn new(req_sec_str: usize, ps: Option<&[u8]>) -> Result<Self, u8>{
        if req_sec_str > MAX_SEC_STR{
            return Err(1);
        }

        if ps.is_some() && ps.unwrap().len() > MAX_PS_LEN{
            return Err(2);
        }

        //let mut this = Self{security_strength: 0, internal_state: None};

        /*  Retrieve the required entropy input and nonce */
        let mut entropy= Vec::<u8>::new();
        let mut nonce= Vec::<u8>::new();
        let security_strength = DRBG::set_sec_str(req_sec_str);
        DRBG::get_entropy_input(&mut entropy, security_strength);
        DRBG::get_entropy_input(&mut nonce, security_strength/2);

        /*  Instantiate the DRBG mechanism */   
        let drbg_mech = HmacDRBG::new(&entropy.as_slice(), &nonce.as_slice(), &ps.unwrap());

        /*  Returning a pointer to this instance */
        Ok(Self{security_strength, internal_state: Some(drbg_mech)})
    }

    /*  Sets the appropriate security strength with respect to the one requested */
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

    /*  Utility function that returns the supported security strength of the DRBG */
    pub fn get_sec_str(&self) -> usize{
        self.security_strength
    }

    /*  This function serves as an envelope to the reseed algorithm of the underlying DRBG mechanism.
        Note that this function does not have the 'prediction_resistance_request' parameter as specified in SP 800-90A section 9.2. This is allowed as long as the DRBG
        always/never uses fresh entropy for the reseed process. In this particular implementation, the DRBG mechanism is provided with fresh entropy at each reseed
        request.

        Error codes:
            1 - internal state is not valid (uninstantiated or never instantiated)
            2 - additional input is too long
     */
    pub fn reseed(&mut self, add: Option<&[u8]>) -> usize{
        let working_state;

        match self.internal_state.as_mut(){
            None => {
                return 1;
            }
            Some(value) => {
                working_state = value;
            }
        }

        match add{
            None => {

            }
            Some(value) => {
                if value.len() > MAX_AI_LEN {
                    return 2;
                }
            }
        }

        let mut entropy_input = Vec::<u8>::new();
        DRBG::get_entropy_input(&mut entropy_input, self.security_strength);
        working_state.reseed(&entropy_input, add);
        return 0;
    }

    /*  This function serves as an envelope to the generate algorithm of the underlying DRBG mechanism.
        For the moment, bits can only be generated using the HMAC mechanism with Sha256.

        Parameters:
            -req_bits: the number of requested bits for generation (max = MAX_PRB)
            -req_str: the requested security strength for the generated bits
            -pred_res_req: whether prediction resistance is to be served on this call
            -add: optional additional input for the generation
        
        Error codes:
            1 - internal state is not valid (uninstantiated or never instantiated)
            2 - requested too many pseudo-random bits (max = MAX_PRB)
            3 - security strenght not supported
            4 - additional input is too long (see MAX_AI_LEN)
            5 - bit generation failed unexpectedly
     */
    pub fn generate<T: ArrayLength<u8>>(&mut self, req_str: usize, pred_res_req: bool, mut add: Option<&[u8]>) -> Result<GenericArray<u8, T>, u8>{
        if self.internal_state.is_none(){
                return Err(1)
        }

        if T::to_usize() * 8 > MAX_PRB {
            return Err(2)
        }

        if req_str > self.security_strength {
            return Err(3)
        }

        match add{
            None => {

            }
            Some(value) => {
                if value.len() > MAX_AI_LEN {
                    return Err(4)
                }
            }
        }

        let working_state = self.internal_state.as_mut().unwrap();
        if pred_res_req || working_state.reseed_needed() {
            let mut entropy_input = Vec::<u8>::new();
            DRBG::get_entropy_input(&mut entropy_input, self.security_strength);
            working_state.reseed(&entropy_input, add);
            add = None;
        }

        let gen_res = working_state.generate::<T>(add);

        match gen_res{
            Err(err) => {
                println!("DRBG_ERROR: mechanim's generate returned error code {}", err);
                return Err(5)
            }
            Ok(bits) => {
                return Ok(bits)
            }
        }
    }

    pub fn uninstantiate(){

    }

    /*  This function is used to retrieve entropy bits directly from the underlying entropy source that is available. 
        For the moment we are assuming that the underlying source of entropy returns FULL ENTROPY bits.

        vec: target vector fo the generated bytes
        bytes: number of bytes to be generated
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
