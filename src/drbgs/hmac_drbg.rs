use crate::drbgs::gen_drbg::*;
use crate::mechs::{gen_mech::DRBG_Mechanism_Functions, hmac_mech::HmacDrbgMech};
use digest::{BlockInput, FixedOutput, Reset, Update};
use generic_array::ArrayLength;
use rand::*;
use crate::self_tests::{hmac_tests, hmac_mech_tests};

/*  Configuration of the DRBG.
    
    This DRBG relies on the HMAC mechanism which supports a maximum of 256 bits of security strength (MAX_SEC_STR).
    It is configured to generate a maximum of 1024 per-request (MAX_PRB). This option may actually be changed but be 
    aware of the limits imposed in table 10.1 of NIST SP 800-90A. */
const MAX_SEC_STR: usize = 256;
const MAX_PRB: usize = 1024;

/*  Implementing common DRBG functions for the HMAC-DRBG. */
impl<T> DRBG_Functions for DRBG<HmacDrbgMech<T>>
where
    T: Update + FixedOutput + BlockInput + Reset + Clone + Default,
    T::BlockSize: ArrayLength<u8>,
    T::OutputSize: ArrayLength<u8>,
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
        DRBG::<HmacDrbgMech::<T>>::get_entropy_input(&mut entropy, MAX_SEC_STR);
        DRBG::<HmacDrbgMech::<T>>::get_entropy_input(&mut nonce, MAX_SEC_STR/2);
        
        // Trying to allocate the DRBG's internal state.
        let drbg_mech;
        match ps {
            None => {
                drbg_mech = HmacDrbgMech::<T>::new(&entropy.as_slice(), &nonce.as_slice(), "".as_bytes());
            }
            Some(pers) => {
                drbg_mech = HmacDrbgMech::<T>::new(&entropy.as_slice(), &nonce.as_slice(), &pers);
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
                if value.len() > self.security_strength {
                    return 2;
                }
            }
        }

        // Retrieving new entropy and reseeding the internal state.
        let mut entropy_input = Vec::<u8>::new();
        DRBG::<HmacDrbgMech::<T>>::get_entropy_input(&mut entropy_input, self.security_strength);
        
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
                if value.len() > self.security_strength {
                    return 5;
                }
            }
        }

        // Eventually reseeding the internal state if needed.
        let working_state = self.internal_state.as_mut().unwrap();
        if pred_res_req || working_state.reseed_needed() {
            let mut entropy_input = Vec::<u8>::new();
            DRBG::<HmacDrbgMech::<T>>::get_entropy_input(&mut entropy_input, self.security_strength);
            working_state.reseed(&entropy_input, add);
        }

        // Generating the requested bits.
        let gen_res = working_state.generate(bits, req_bytes, None);

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

    /*  This function is an API that can be used by external entities (even an eventual FIPS provider) to run
        the self tests associated with this DRBG. */
    fn run_self_tests(&self) -> usize {
        if hmac_tests::instantiation::run_tests() != 0 {
            return 1;
        }
        else if hmac_mech_tests::hmac_nist_vec_test::nist_vectors() != 0{
            return 1;
        }
        else if hmac_mech_tests::hmac_zeroization_test::test_zeroization() != 0{
            return 1;
        }

        return 0;
    }
}

/*  Implementing additional specific functions for this DRBG. */
impl<T> DRBG<HmacDrbgMech<T>>
where
    T: Update + FixedOutput + BlockInput + Reset + Clone + Default,
    T::BlockSize: ArrayLength<u8>,
    T::OutputSize: ArrayLength<u8>,
{
    /*  Utility function that returns the supported security strength of the DRBG.
    
        Return values:
            - the security strength supported by the DRBG. */
    pub fn get_sec_str(&self) -> usize{
        self.security_strength
    }
}