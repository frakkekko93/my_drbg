/*  This public trait defines the functions that are common to all implemented DRBG mechanisms. 
    The functions declared in this trait are not supposed to be directly used by external applications. Instead,
    they are designed to be used by the DRBG functions defined by the DRBG_Functions trait (see module 'gen_drbg').
    The functions defined in such trait serve as evelops to the ones defined here. Those evelopes check the validity
    of the parameters that the functions of this trait receive from external applications. Other parameters (such as
    entropy inputs, nonces, and others) are directly derived by the function envelopes according to the needs of the
    specific mechanism. */
#[allow(non_camel_case_types)]
pub trait DRBG_Mechanism_Functions: {
    /*  Allocates a new instance of the DRBG mechanism using the passed entropy, nonce and personalization string.
        This function is called by DRBG_Functions::new envelope. The evelope is resposible for deriving the entropy
        and nonce parameter as well as checking the validity of the personalization string passed by the calling
        application.
        On success, this function returns the handle to the newly created internal state of the mechanism.
        On failure, this function returns no handle.

        Parameters:
            - entropy: the entropy to be used for the instantiation
            - nonce: the nonce to be used for the instantiation
            - pers: the optional personalization string to be used for the instantiation
        
        Return value:
            - Some(inst): where 'inst' pointer to the newly created instance
            - None: instantiation failed
    */
    fn new(entropy: &[u8], nonce: &[u8], pers: &[u8]) -> Option<Self> where Self: Sized;
    
    /*  Generates a vector of pseudorandom bytes.
        This function is called by DRBG_Functions::generate envelope. This envelope is responsible for checking
        the validity of all parameters passed to this function.
        On success, this function returns 0 and the number of pseudo-random bits requested.
        On failure, this function returns an error flag >0 and a null vector.

        Parameters:
            - result: a reference to the output vector
            - req_bytes: the number of bytes to be generated
            - add: optional additional inputs to the generation

        Return values:
            - 0: SUCCESS, result is valid and can be used
            - 1: ERROR, this instantiation has been previously zeroized, new instantiation needed
            - 2: ERROR, reseed interval has been reached and reseeding is necessary
    */
    fn generate(&mut self, result: &mut Vec<u8>, req_bytes: usize, add: Option<&[u8]>) -> usize;

    /*  Reseeds the instance using fresh entropy and an eventual additional input.
        This function is called by DRBG_Functions::reseed envelope. This envelope is responsible for deriving the
        entropy parameter and checking the validity of the additional input received from the calling application.
        On success, this function returns 0.
        On failure, this function returns 1.
        
        Parameters:
            - entropy: the new entropy to be used for reseeding
            - add: optional additional inputs to the reseeding process

        Return values:
            - 0: SUCCESS, instantiation successfully reseeded
            - 1: ERROR, instantiation cannot be reseeded
    */
    fn reseed(&mut self, entropy: &[u8], add: Option<&[u8]>) -> usize;

    /*  Function needed to zeroize the content of this instance and make it unusable.
        This function is called by DRBG_Functions::uninstantiate envelope.
        This function sets all the values of the internal state to 0 by overwriting their values. It also sets the
        'zeroized' flag, rendering the instance completely unusable.
        On success, this function returns 0.
        On failure, this function returns 1.

        Return values:
            - 0: SUCCESS, instantiation has been successfully zeroized
            - 1: ERROR, instantiation is already zeroized    
    */
    fn zeroize(&mut self) -> usize;

    /*** FROM HERE WE HAVE UTILITY FUNCTIONS DEFINED FOR ALL MECHANISMS THAT COULD BE ALSO CALLED FROM OUTSIDE DRBG ENVELOPES */

    /*  Returns the reseed counter of this instance.

        Return value:
            - the reseed counter */
    fn count(&self) -> usize;

    /*  Indicates whether a forced reseed is needed for this instance.
    
        Return values:
            - boolean statement */
    fn reseed_needed(&self) -> bool;

    /*  Function needed to check if the current instance is zeroized.
    
        Return values:
            - boolean statement */
    fn _is_zeroized(&self) -> bool;

    /*  Function that retrieves the name of the DRBG implementation. */
    fn drbg_name() -> String;
}