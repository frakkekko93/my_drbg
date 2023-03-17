#[allow(non_camel_case_types)]
pub trait DRBG_Mechanism_Functions: {
    /*  Allocates a new instance of the DRBG using the passed entropy, nonce and personalization string.

        Parameters:
            - entropy: the desired entropy to be used for the instantiation
            - nonce: the desired nonce to be used for the instantiation
            - pers: the optional personalization string to be used for the instantiation
        
        Return value:
            - Some(inst): where 'inst' pointer to the newly created instance
            - None: instantiation failed
    */
    fn new(entropy: &[u8], nonce: &[u8], pers: &[u8]) -> Option<Self> where Self: Sized;
    
    /*  Generates a vector of pseudorandom bytes.

        Parameters:
            - result: a reference to the output vector
            - req_bytes: the number of bytes to be generated
            - add: optional additional inputs to the generation

        Return values:
            - 0: SUCCESS, result is valid and can be used
            - 1: ERROR, this instantiation has been previously zeroized, new instantiation needed
            - 2: ERROR, reseed interval has been reached and reseeding is necessary
    */
    fn generate(&mut self,result: &mut Vec<u8>, req_bytes: usize, add: Option<&[u8]>) -> usize;

    /*  Reseeds the instance using fresh entropy and an eventual additional input.
        
        Parameters:
            - the new entropy to be used for reseeding
            - optional additional inputs to the reseeding process

        Return values:
            - 0: SUCCESS, instantiation succesfully reseeded
            - 1: ERROR, instantiation cannot be reseeded
    */
    fn reseed(&mut self, entropy: &[u8], add: Option<&[u8]>) -> usize;

    /*  Function needed to zeroize the content of this instance and macke it unusable. 

        Return values:
            - 0: SUCCESS, instantiation has been successfully zeroized
            - 1: ERROR, instantiation is already zeroized    
    */
    fn zeroize(&mut self) -> usize;
}