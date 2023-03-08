pub mod drbg_mech;

use sha2::Sha256;
use rand::*;
use drbg_mech::hmac::*;

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

        Parameters:
            - req_sec_str: the security strength needed by the calling application
            - ps: optional personalization string to be used for instantiation of the DRBG mechanism

        Return values:
            Self - SUCCESS, a pointer to the newly created DRBG instance
            1 - ERROR, inappropriate security strength
            2 - ERROR, personalization string is too long
    */
    pub fn new(req_sec_str: usize, ps: Option<&[u8]>) -> Result<Self, u8>{
        if req_sec_str > MAX_SEC_STR{
            return Err(1);
        }

        if ps.is_some() && ps.unwrap().len() > MAX_PS_LEN{
            return Err(2);
        }

        let mut entropy= Vec::<u8>::new();
        let mut nonce= Vec::<u8>::new();
        let security_strength = DRBG::set_sec_str(req_sec_str);
        DRBG::get_entropy_input(&mut entropy, security_strength);
        DRBG::get_entropy_input(&mut nonce, security_strength/2);
        
        let drbg_mech;
        match ps {
            None => {
                drbg_mech = HmacDRBG::<Sha256>::new(&entropy.as_slice(), &nonce.as_slice(), "".as_bytes());
            }
            Some(pers) => {
                drbg_mech = HmacDRBG::<Sha256>::new(&entropy.as_slice(), &nonce.as_slice(), &pers);
            }
        }

        Ok(Self{security_strength, internal_state: Some(drbg_mech)})
    }

    /*  Sets the appropriate security strength with respect to the one requested.

        Parameters:
            - sec_str: the security strength that is requested

        Return values:
            - the security strength to be adopted by the DRBG
     */
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

    /*  Utility function that returns the supported security strength of the DRBG.
    
        Return values:
            - the security strength supported by the DRBG
     */
    pub fn get_sec_str(&self) -> usize{
        self.security_strength
    }

    /*  This function serves as an envelope to the reseed algorithm of the underlying DRBG mechanism.
        Note that this function does not have the 'prediction_resistance_request' parameter as specified in SP 800-90A section 9.2. This is allowed as long as the DRBG
        always/never uses fresh entropy for the reseed process. In this particular implementation, the DRBG mechanism is provided with fresh entropy at each reseed
        request.

        Parameters:
            - add: optional additional input to be used for reseeding

        Return Values:
            0 - SUCCESS, internal state has been succesfully reseeded
            1 - ERROR, internal state is not valid (uninstantiated or never instantiated)
            2 - ERROR, additional input is too long
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
            - bits: a reference to the resulting byte vector
            - req_bytes: the number of requested bytes for generation (max = MAX_PRB)
            - req_str: the requested security strength for the generated bits
            - pred_res_req: whether prediction resistance is to be served on this call
            - add: optional additional input for the generation
        
        Return values:
            0 - SUCCESS, bits have been generated succesfully and can be used for the desired purpose
            1 - ERROR, return vector must be intitally empty
            2 - ERROR, internal state is not valid (uninstantiated or never instantiated)
            3 - ERROR, requested too many pseudo-random bits (max = MAX_PRB)
            4 - ERROR, security strenght not supported
            5 - ERROR, additional input is too long (see MAX_AI_LEN)
            6 - ERROR, bit generation failed unexpectedly
     */
    pub fn generate(&mut self, bits: &mut Vec<u8>, req_bytes: usize, req_str: usize, pred_res_req: bool, add: Option<&[u8]>) -> usize {
        if !bits.is_empty(){
            return 1;
        }
        
        if self.internal_state.is_none(){
                return 2;
        }

        if req_bytes > MAX_PRB {
            return 3;
        }

        if req_str > self.security_strength {
            return 4;
        }

        match add{
            None => {

            }
            Some(value) => {
                if value.len() > MAX_AI_LEN {
                    return 5;
                }
            }
        }

        let working_state = self.internal_state.as_mut().unwrap();
        if pred_res_req || working_state.reseed_needed() {
            let mut entropy_input = Vec::<u8>::new();
            DRBG::get_entropy_input(&mut entropy_input, self.security_strength);
            working_state.reseed(&entropy_input, add);
        }

        let gen_res = working_state.generate(bits, 128, None);

        if gen_res == 0 {
            return 0;
        }
        else {
            return 6;
        }
    }

    /*  This function is used to zeroize the internal state and make it unavailable to the calling application.

        Return values:
            - 0: SUCCESS, the internal state has been succesfully zeroized
            - 1: ERROR, invalid internal state (maybe already zeroized?)
     */
    pub fn uninstantiate(&mut self) -> usize{
        if self.internal_state.is_none(){
            return 1;
        }
        
        self.internal_state.as_mut().unwrap().zeroize();
        self.internal_state = None;
        
        return 0;
    }

    /*  This function is used to retrieve entropy bits directly from the underlying entropy source that is available. 
        For the moment we are assuming that the underlying source of entropy returns FULL ENTROPY bits.

        Parameters:
            - vec: target vector for entropy bytes
            - bytes: number of entropy bytes to be generated
    */
    fn get_entropy_input(vec: &mut Vec<u8>, bytes: usize){
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
