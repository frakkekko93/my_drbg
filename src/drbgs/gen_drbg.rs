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

    fn run_self_tests(&self) -> usize;
}