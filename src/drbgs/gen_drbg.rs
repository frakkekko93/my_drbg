use std::any::TypeId;

use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::mechs::hash_mech::HashDrbgMech;
use crate::mechs::hmac_mech::HmacDrbgMech;
use crate::self_tests::{self, formats};
use crate::self_tests::drbg_tests;
use rand::Rng;
use sha2::Sha512;

/*  Configuration of the DRBG.
    
    This DRBG can be instantiated using anyone of the mechanisms defined in the 'mechs' module. These mechanisms support 
    a maximum of 256 bits of security strength (MAX_SEC_STR).
    The DRBG is configured to generate a maximum of 2048 bits per-request (MAX_PRB). This option may actually be changed but be 
    aware of the limits imposed in tables 2 and 3 of NIST SP 800-90A. */
const MAX_SEC_STR: usize = 256;
const MAX_PRB: usize = 2048;

/*  This is the general structure of the DRBG. We have:
        - internal_state: an handle to the state of the underlying mechanism
        - security_strength: indicates the security strength that a particular instance can support. This parameter is passed
                             by the application using the DRBG but is always kept <= MAX_SEC_STR by this crate.
        - error_state: indicates whether the DRBG entered an error state following a failure during normal operation and/or a failure
                       of on-demand self-tests. If set, this instance has to be deleted and recreated by the user.
    
    In this design, the prediction_resistance_flag is not used. This has been done because we are assuming that the DRBG is accessing
    an entropy source that always provides fresh full-entropy bits. This means that is always possible for the DRBG to provide prediction
    resistance when needed. 
    For the same reason, the reseed function defined below does not use the prediction_resistance_request parameter, as fresh entropy is
    provided on every reseed request by default. */
pub struct DRBG<T>
{
    pub internal_state: Option<T>,
    pub security_strength: usize,
    pub error_state: bool,
}

#[allow(non_camel_case_types)]
pub trait DRBG_Functions{
    /*  This function serves as an evelope to the instantiate algorithm of the underlying DRBG mechanism and is defined in section 9.1 of the SP. 
        It instantiates a new DRBG that supports the requested security strength returning a handle to the new instance.
        In case the instantiation is not possible, this function returns an error flag to the calling application.

        Parameters:
            - req_sec_str: the security strength needed by the calling application. This number should be a multiple of 8 bits <=MAX_SEC_STR.
            - ps: optional personalization string to be used for instantiation of the DRBG mechanism. Its length must be kept under 256 bits to be
                  protected by this DRBG.

        Return values:
            Self - SUCCESS, a pointer to the newly created DRBG instance
            1 - ERROR, inappropriate security strength
            2 - ERROR, personalization string is too long (max security_strength bits)
            3 - ERROR, the instantiation of the underlying mechanism failed
    */
    fn new(req_sec_str: usize, ps: Option<&[u8]>) -> Result<Self, usize> where Self: Sized;

    /*  This function serves as an envelope to the reseed algorithm of the underlying DRBG mechanism and is defined in section 9.2 of the SP.
        It reseeds the internal state of the DRBG by acquiring fresh entropy from the entropy source.
        If the reseeding fails, an error state >0 is returned to the application that is using the DRBG.
        If the reseeding succeeds, 0 is returned.

        Parameters:
            - add: optional additional input to be used for reseeding

        Return Values:
            0 - SUCCESS, internal state has been succesfully reseeded
            1 - ERROR, internal state is not valid (uninstantiated or in error state)
            2 - ERROR, additional input is too long (max MAX_SEC_STR bits)
            3 - ERROR, internal state reseeding failed unexpectedly
    */
    fn reseed(&mut self, add: Option<&[u8]>) -> usize;

    /*  This function serves as an envelope to the generate algorithm of the underlying DRBG mechanism and is specified in section 9.3 of the SP.
        Its goal is to use the underlying mechanism to generate the requested number of pseudo-random bits needed by
        the calling application (within the limits imposed by MAX_PBR).
        On success this function returns 0 and the requested number of pseudo-random bits.
        On failure this function returns an error flag >0 and a null vector.

        Parameters:
            - bits: a reference to the resulting byte vector. It is cleared before use.
            - req_bits: the number of requested bits for generation. This number should be a multiple of 8.
            - req_str: the requested security strength for the generated bits
            - pred_res_req: whether prediction resistance is to be served on this call
            - add: optional additional input for the generation
        
        Return values:
            0 - SUCCESS, bits have been generated succesfully and can be used for the desired purpose
            1 - ERROR, internal state is not valid (uninstantiated or in error state)
            2 - ERROR, requested too many pseudo-random bits
            3 - ERROR, security strenght not supported
            4 - ERROR, additional input is too long (max security_strength bits)
            5 - ERROR, bit generation failed unexpectedly
    */
    fn generate(&mut self, bits: &mut Vec<u8>, req_bits: usize, req_str: usize, pred_res_req: bool, add: Option<&[u8]>) -> usize;

    /*  This function is used to zeroize the internal state and make it unavailable to the calling application and is defined in section 9.4 of the SP.
        It overwrites the internal state of the DRBG mechanism and sets the 'zeroized' flag, rendering the internal state unusable.
        After a call to this function a new instance of the DRBG must be used.

        Return values:
            - 0: SUCCESS, the internal state has been succesfully zeroized
            - 1: ERROR, invalid internal state (already zeroize or in error state)
    */
    fn uninstantiate(&mut self) -> usize;

    /*  This function is used to retrieve entropy bits directly from the underlying entropy source that is available. 
        For the moment we are assuming that the underlying source of entropy returns FULL ENTROPY bits. The entropy retrieved is
        always fresh as it is always taken from the entropy source directly.

        Parameters:
            - vec: target vector for entropy bytes
            - bytes: number of entropy bytes to be generated
    */
    fn get_entropy_input(vec: &mut Vec<u8>, bytes: usize);

    /*  FROM HERE WE HAVE UTILITY FUNCTIONS THAT ARE NOT SPECIFICALLY TIED TO THE SP REQUIREMENTS. */

    /*  Utility function that returns the supported security strength of the DRBG.
    
        Return values:
            - the security strength supported by the DRBG instance. */
    fn get_sec_str(&self) -> usize;

    /*  Utility function that returns the value of the reseed counter of the DRBG.
        Eventually returns 0 if the DRBG is zeroized or in error state.
    
        Return values:
            - the security strength supported by the DRBG instance. */
    fn get_count(&self) -> usize;

    /*  Utility function that returns the value seed life of the DRBG.
        Eventually returns 0 if the DRBG is zeroized or in error state.
    
        Return values:
            - the seed life used by the DRBG instance. */
    fn get_seed_life(&self) -> usize;

    /*  Utility function that returns maximum number of pseudo-random bits that the DRBG can produce for each generate call.
        Eventually returns 0 if the DRBG is zeroized or in error state.
    
        Return values:
            - the seed life used by the DRBG instance. */
    fn get_max_pbr(&self) -> usize;

    /*  This function runs on-demand self-tests through a particular instance that is already in use. If self-tests fail an
        error state is set and that particular instance is zeorized and can no longer be used.
        
        Return values:
            - 0: all tests passed, no error state set
            - 1: some test falied, error state set
    */
    fn run_self_tests(&mut self) -> usize;
}

/*  This is the implementation of the generic DRBG_Functions trait for a DRBG using one of the mechanisms defined in the 'mechs' module. */
impl<T> DRBG_Functions for DRBG<T> 
where
    T: DRBG_Mechanism_Functions + 'static
{
    /*  Step 4 of this process (as specified in the SP) is handled directly by the mechanisms by allowing then to modify the security strength accordingly. */
    fn new(mut req_sec_str: usize, ps: Option<&[u8]>) -> Result<Self, usize>{
        // Checking the validity of the security strength (step 1).
        if req_sec_str > MAX_SEC_STR{
            return Err(1);
        }

        // Extracting the eventual personalization string.
        let mut actual_pers = Vec::<u8>::new();
        if ps.is_some() {
            actual_pers.append(&mut ps.unwrap().to_vec());

            // Checking the validity of the personalization string (step 3).
            if actual_pers.len() * 8 > req_sec_str {
                return Err(2);
            }

            // Eventually padding the personalization string with random bytes in case of CTR mechanism with no DF.
            if T::drbg_name() == "CTR-DRBG" {
                let mut padding = Vec::<u8>::new();
                DRBG::<T>::get_entropy_input(&mut padding, 48 - ps.unwrap().len());
                actual_pers.append(&mut ps.unwrap().to_vec());
                actual_pers.append(&mut padding);
            }
        }

        // Acquiring the entropy input according to mechanisms' specifics (step 6).
        let mut entropy= Vec::<u8>::new();
        if T::drbg_name() != "CTR-DRBG" {
            DRBG::<T>::get_entropy_input(&mut entropy, MAX_SEC_STR/8);
        }
        else {
            DRBG::<T>::get_entropy_input(&mut entropy, 48);
        }

        // Acquiring the nonce for mechanisms that are different from CTR-DRBG withouth derivation function (step 8).
        let mut nonce= Vec::<u8>::new();
        if T::drbg_name() != "CTR-DRBG" {      
            DRBG::<T>::get_entropy_input(&mut nonce, MAX_SEC_STR/16);
        }
        
        // Trying to allocate the DRBG's internal state (step 9).
        let drbg_mech = T::new(&entropy.as_slice(), &nonce.as_slice(), &actual_pers.as_slice(), &mut req_sec_str);

        // Checking the validity of the allocated state (step 10,11,12).
        match drbg_mech{
            None => {
                return Err(3);
            }
            Some(_) => {
                Ok(Self{security_strength: req_sec_str, internal_state: drbg_mech, error_state: false})
            }
        }
    }

    fn reseed(&mut self, add: Option<&[u8]>) -> usize{
        // Retrieving the actual internal state if available and valid (step 1).
        let working_state;
        match self.internal_state.as_mut(){
            None => {
                return 1;
            }
            Some(value) => {
                working_state = value;
            }
        }

        // Retrieving the additional input if present.
        let mut actual_add_in = Vec::<u8>::new();
        match add{
            None => {}
            Some(value) => {
                // Checking the validity of the additional input (step 3).
                if value.len() * 8 > self.security_strength {
                    return 2;
                }

                actual_add_in.append(&mut value.to_vec());

                // Eventually padding the additional input with random bytes if the mechanism is CTR with no DF.
                if T::drbg_name() == "CTR-DRBG" {
                    let mut padding = Vec::<u8>::new();
                    DRBG::<T>::get_entropy_input(&mut padding, 48 - actual_add_in.len());
                    actual_add_in.append(&mut padding);
                }
            }
        }

        // Acquiring the entropy input according to mechanisms' specifics (step 4).
        let mut entropy_input= Vec::<u8>::new();
        if T::drbg_name() != "CTR-DRBG" {
            DRBG::<T>::get_entropy_input(&mut entropy_input, self.security_strength/8);
        }
        else {
            DRBG::<T>::get_entropy_input(&mut entropy_input, 48);
        }

        // Reseeding the internal state (step 6).
        let res;
        if actual_add_in.len() != 0 {
            res = working_state.reseed(&entropy_input, Some(&actual_add_in));
        }
        else {
            res = working_state.reseed(&entropy_input, None);
        }

        // Internal state reseed failure (step 5).
        if res > 0 {
            return 3;
        }

        return 0;
    }

    fn generate(&mut self, bits: &mut Vec<u8>, req_bits: usize, req_str: usize, pred_res_req: bool, add: Option<&[u8]>) -> usize {
        // Eventually clearing existing data from the return vector.
        if !bits.is_empty(){
            bits.clear();
        }

        // Checking the validity of the internal state (step 1).
        if self.internal_state.is_none() || self.error_state{
                return 1;
        }

        // Checking the validity of the requested number of bits (step 2).
        if req_bits > MAX_PRB {
            return 2;
        }

        // Checking that the requested strength is supported by this instance (step 3).
        if req_str > self.security_strength {
            return 3;
        }

        // Retrieving the eventual additional input.
        let mut actual_add_in = Vec::<u8>::new();
        match add{
            None => {}
            Some(value) => {
                // Checking the validity of the additional input (step 4).
                if value.len() * 8 > self.security_strength {
                    return 4;
                }

                actual_add_in.append(&mut value.to_vec());

                // Eventually padding the additional input if the CTR mechanism with no DF is used.
                if T::drbg_name() == "CTR-DRBG" {
                    let mut padding = Vec::<u8>::new();
                    DRBG::<T>::get_entropy_input(&mut padding, 48 - actual_add_in.len());
                    actual_add_in.append(&mut padding);
                }
            }
        }
        
        // Eventually reseeding the internal state if needed (step 7).
        let working_state = self.internal_state.as_mut().unwrap();
        let gen_res;
        if pred_res_req || working_state.reseed_needed() {
            let mut entropy_input= Vec::<u8>::new();
            // Retreiving entropy for the reseed.
            if T::drbg_name() != "CTR-DRBG" {
                DRBG::<T>::get_entropy_input(&mut entropy_input, self.security_strength/8);
            }
            else {
                DRBG::<T>::get_entropy_input(&mut entropy_input, 48);
            }

            // Reseeding the internal state (step 7.1).
            if actual_add_in.len() != 0 {
                working_state.reseed(&entropy_input, Some(&actual_add_in));
            }
            else {
                working_state.reseed(&entropy_input, None);
            }

            // Generating the requested bits (step 8, prr).
            gen_res = working_state.generate(bits, req_bits/8, None);
        }
        else {
            // Generating the requested bits (step 8, no prr).
            if actual_add_in.len() != 0 {
                gen_res = working_state.generate(bits, req_bits/8, Some(&actual_add_in));
            }
            else {
                gen_res = working_state.generate(bits, req_bits/8, None);
            }
        }

        // Checking the result of the generation (step 10,11).
        if gen_res == 0 {
            return 0;
        }
        else {
            bits.clear();
            return 5;
        }
    }

    fn uninstantiate(&mut self) -> usize{
        // Internal state already gone.
        if self.internal_state.is_none() || self.error_state{
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

    fn get_sec_str(&self) -> usize{
        if self.error_state || self.internal_state.is_none() {
            return 0;
        }

        self.security_strength
    }

    fn get_count(&self) -> usize{
        // Internal state already gone.
        if self.internal_state.is_none(){
            return 0;
        }

        self.internal_state.as_ref().unwrap().count()
    }

    fn get_seed_life(&self) -> usize {
        if self.error_state || self.internal_state.is_none() {
            return 0;
        }

        return T::seed_life();
    }

    fn get_max_pbr(&self) -> usize {
        if self.error_state || self.internal_state.is_none() {
            return 0;
        }

        return MAX_PRB;
    }

    fn run_self_tests(&mut self) -> usize {
        let this_id = TypeId::of::<T>();

        // Building the log message based on the mechanism that is being tested.
        let mut log_message = "\n*** STARTING ".to_string();
        log_message.push_str(T::drbg_name().as_str());

        if T::drbg_name() == "CTR-DRBG" {
            log_message.push_str(" AES-");
            log_message.push_str(&self.security_strength.to_string());
            log_message.push_str(" (no DF)");
        }
        else {
            log_message.push_str(" Sha ");

            if this_id == TypeId::of::<HashDrbgMech<Sha512>>() 
                || this_id == TypeId::of::<HmacDrbgMech<Sha512>>() {
                log_message.push_str("512");
            }
            else {
                log_message.push_str(&self.security_strength.to_string());
            }
        }
        
        log_message.push_str(" on-demand self-tests ***\n");
        formats::write_to_log(log_message);

        // Running tests
        let res = drbg_tests::run_all::run_tests::<T>(self.security_strength) +
                self_tests::mech_tests::run_all::run_tests::<T>(self.security_strength);

        // If tests have failed we set the error state and uninstantiate the DRBG.
        if res != 0 {
            self.error_state = true;
            self.uninstantiate();
            return 1;
        }

        0
    }
}