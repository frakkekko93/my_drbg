use rand::Rng;
use crate::mechs::gen_mech::DRBG_Mechanism_Functions;

/*  Configuration of the DRBG.
    
    This DRBG relies on the HMAC mechanism which supports a maximum of 256 bits of security strength (MAX_SEC_STR).
    It is configured to generate a maximum of 1024 bits per-request (MAX_PRB). This option may actually be changed but be 
    aware of the limits imposed in table 10.1 of NIST SP 800-90A. */
    const MAX_SEC_STR: usize = 256;
    const MAX_PRB: usize = 1024;

/*  The mechanism that the DRBG is using. */
pub struct DRBG<T>
{
    pub internal_state: Option<T>,
    pub security_strength: usize,
}

#[allow(non_camel_case_types)]
pub trait DRBG_Functions{
    /*  This function serves as an evelope to the instantiate algorithm of the underlying DRBG mechanism.
        Note that this function does not have the 'prediction_resistance_flag' parameter as specified in SP 800-90A section 9.1.
        This is allowed as long as the DRBG always provides or do not support prediction resistance. In this particular
        implementation, the DRBG is implemented to always support prediction resistance. This means that calling application may
        request prediction resistance at any time during bit generation.

        Parameters:
            - req_sec_str: the security strength needed by the calling application
            - ps: optional personalization string to be used for instantiation of the DRBG mechanism

        Return values:
            Self - SUCCESS, a pointer to the newly created DRBG instance
            1 - ERROR, inappropriate security strength
            2 - ERROR, personalization string is too long (max security_strength bits)
            3 - ERROR, the instantiation of the underlying mechanism failed
    */
    fn new(req_sec_str: usize, ps: Option<&[u8]>) -> Result<Self, u8> where Self: Sized;

    /*  This function serves as an envelope to the reseed algorithm of the underlying DRBG mechanism.
        Note that this function does not have the 'prediction_resistance_request' parameter as specified in SP 800-90A section 9.2.
        This is allowed as long as the DRBG always/never uses fresh entropy for the reseed process. In this particular
        implementation, the DRBG mechanism is provided with fresh entropy at each reseed request.

        Parameters:
            - add: optional additional input to be used for reseeding

        Return Values:
            0 - SUCCESS, internal state has been succesfully reseeded
            1 - ERROR, internal state is not valid (uninstantiated or never instantiated)
            2 - ERROR, additional input is too long (max security_strength bits)
            3 - ERROR, internal state reseeding failed unexpectedly
    */
    fn reseed(&mut self, add: Option<&[u8]>) -> usize;

    /*  This function serves as an envelope to the generate algorithm of the underlying DRBG mechanism.

        Parameters:
            - bits: a reference to the resulting byte vector
            - req_bytes: the number of requested bytes for generation
            - req_str: the requested security strength for the generated bits
            - pred_res_req: whether prediction resistance is to be served on this call
            - add: optional additional input for the generation
        
        Return values:
            0 - SUCCESS, bits have been generated succesfully and can be used for the desired purpose
            1 - ERROR, return vector must be intitally empty
            2 - ERROR, internal state is not valid (uninstantiated or never instantiated)
            3 - ERROR, requested too many pseudo-random bits
            4 - ERROR, security strenght not supported
            5 - ERROR, additional input is too long (max security_strength bits)
            6 - ERROR, bit generation failed unexpectedly
    */
    fn generate(&mut self, bits: &mut Vec<u8>, req_bytes: usize, req_str: usize, pred_res_req: bool, add: Option<&[u8]>) -> usize;

    /*  This function is used to zeroize the internal state and make it unavailable to the calling application.

        Return values:
            - 0: SUCCESS, the internal state has been succesfully zeroized
            - 1: ERROR, invalid internal state (maybe already zeroized?)
    */
    fn uninstantiate(&mut self) -> usize;

    /*  This function is used to retrieve entropy bits directly from the underlying entropy source that is available. 
        For the moment we are assuming that the underlying source of entropy returns FULL ENTROPY bits. It entropy retrieved is
        always fresh as it is always taken from the entropy source directly.

        Parameters:
            - vec: target vector for entropy bytes
            - bytes: number of entropy bytes to be generated
    */
    fn get_entropy_input(vec: &mut Vec<u8>, bytes: usize);

    /*  Utility function that returns the supported security strength of the DRBG.
    
        Return values:
            - the security strength supported by the DRBG. */
    fn get_sec_str(&self) -> usize;
}

impl<T> DRBG_Functions for DRBG<T> 
where
    T: DRBG_Mechanism_Functions
{
    fn new(req_sec_str: usize, ps: Option<&[u8]>) -> Result<Self, u8>{
        // Checking requirements on the validity of the requested security strength and the personalization string.
        if req_sec_str > MAX_SEC_STR{
            return Err(1);
        }
        if ps.is_some() && ps.unwrap().len() * 8 > MAX_SEC_STR{
            return Err(2);
        }

        // Acquiring the entropy input and nonce parameters from the entropy source.
        let mut entropy= Vec::<u8>::new();
        let mut nonce= Vec::<u8>::new();      
        DRBG::<T>::get_entropy_input(&mut entropy, MAX_SEC_STR/8);
        DRBG::<T>::get_entropy_input(&mut nonce, MAX_SEC_STR/16);

        // println!("DRBG - (instantiate): used entropy: {} - len: {}.", hex::encode(&entropy), entropy.len());
        // println!("DRBG - (instantiate): used nonce: {} - len: {}.", hex::encode(&nonce), nonce.len());
        
        // Trying to allocate the DRBG's internal state.
        let drbg_mech;
        match ps {
            None => {
                drbg_mech = T::new(&entropy.as_slice(), &nonce.as_slice(), "".as_bytes());
            }
            Some(pers) => {

                // println!("DRBG - (instantiate): received pers: {} - len: {}.", hex::encode(pers), pers.len());

                drbg_mech = T::new(&entropy.as_slice(), &nonce.as_slice(), &pers);
            }
        }

        // Checking the validity of the allocated state.
        match drbg_mech{
            None => {
                return Err(3);
            }
            Some(_) => {
                Ok(Self{security_strength: MAX_SEC_STR, internal_state: drbg_mech})
            }
        }
    }

    fn reseed(&mut self, add: Option<&[u8]>) -> usize{
        // Retrieving the actual internal state if available and valid.
        let working_state;
        match self.internal_state.as_mut(){
            None => {
                return 1;
            }
            Some(value) => {
                working_state = value;
            }
        }

        // Checking the validity of the passed additional input.
        match add{
            None => {}
            Some(value) => {

                // println!("DRBG - (reseed): received add-in: {} - len: {}.", hex::encode(value), value.len());

                if value.len() * 8 > self.security_strength {
                    return 2;
                }
            }
        }

        // Retrieving new entropy and reseeding the internal state.
        let mut entropy_input = Vec::<u8>::new();
        DRBG::<T>::get_entropy_input(&mut entropy_input, self.security_strength/8);

        // println!("DRBG - (reseed): used entropy: {} - len: {}.", hex::encode(&entropy_input), entropy_input.len());
        
        let res = working_state.reseed(&entropy_input, add);

        // Internal state reseed failure.
        if res > 0 {
            return 3;
        }

        return 0;
    }

    fn generate(&mut self, bits: &mut Vec<u8>, req_bytes: usize, req_str: usize, pred_res_req: bool, add: Option<&[u8]>) -> usize {
        // Checking the validity of all the obtained parameters.
        if !bits.is_empty(){
            return 1;
        }
        if self.internal_state.is_none(){
                return 2;
        }
        if req_bytes * 8 > MAX_PRB {
            return 3;
        }
        if req_str > self.security_strength {
            return 4;
        }
        match add{
            None => {

            }
            Some(value) => {

                // println!("DRBG - (generate): received add-in: {} - len: {}.", hex::encode(value), value.len());

                if value.len() * 8 > self.security_strength {
                    return 5;
                }
            }
        }

        // Eventually reseeding the internal state if needed.
        let working_state = self.internal_state.as_mut().unwrap();
        let gen_res;
        if pred_res_req || working_state.reseed_needed() {

            // println!("DRBG - (generate): received prr.");

            let mut entropy_input = Vec::<u8>::new();
            DRBG::<T>::get_entropy_input(&mut entropy_input, self.security_strength/8);

            // println!("DRBG - (generate): used entropy for reseed: {} - len: {}.", hex::encode(&entropy_input), entropy_input.len());

            working_state.reseed(&entropy_input, add);

            // Generating the requested bits.
            gen_res = working_state.generate(bits, req_bytes, None);
        }
        else {
            // Generating the requested bits.
            gen_res = working_state.generate(bits, req_bytes, add);
        }

        // Checking the result of the generation.
        if gen_res == 0 {
            return 0;
        }
        else {
            return 6;
        }
    }

    fn uninstantiate(&mut self) -> usize{
        // Internal state already gone.
        if self.internal_state.is_none(){
            return 1;
        }
        
        // Zeroizing the internal state of the DRBG.
        self.internal_state.as_mut().unwrap().zeroize();
        self.internal_state = None;
        
        return 0;
    }

    fn get_entropy_input(result: &mut Vec<u8>, bytes: usize){
        //Bytes are generated at a CHUNK_DIM-wide chunk ratio (CHUNK_DIM*8 bits at a time).
        const CHUNK_DIM: usize = 16;
        let mut chunk: [u8; CHUNK_DIM] = [0; CHUNK_DIM];

        // Generate CHUNK_DIM bytes at a time and copy the generated chunk into result.
        let mut count = 0;
        let mut end = false;
        while result.len() < bytes && !end {
            rand::thread_rng().fill(&mut chunk);
            for j in 0..chunk.len() {

                // The requested number of bytes has been reached, stop generation
                if count+j >= bytes{
                    end = true;
                    break;
                }
                result.push(chunk[j]);
            }
            // Next chunk.
            count += CHUNK_DIM;
        }
    }

    /*  Utility function that returns the supported security strength of the DRBG.
    
        Return values:
            - the security strength supported by the DRBG. */
    fn get_sec_str(&self) -> usize{
        self.security_strength
    }
}