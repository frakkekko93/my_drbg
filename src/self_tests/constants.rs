/*  Number of bytes to be generated per request during testing. */
pub const MIN_BYTES: usize = 1;                 // Minimum number of bytes per generate request
pub const MAX_BYTES: usize = 256;               // Maximum number of bytes per generate request
pub const NS_BYTES: usize = MAX_BYTES+1;        // Number of bytes not supported for a single generate

/*  Entropy constants 

    For each mechanism requests a maximum of 32 bytes of entropy is sufficient to instantiate. 
    The CTR-DRBG with no DF is an exception to this rule since it needs seedlen bytes of entropy. This
    measure varies depending on the AES function used and the maximum requested is 48 bytes. The CTR mechanism
    is actually automatically trucating the received entropy to the needed length.
*/
pub const ENTROPY: [u8; 32] = 
    [156, 186, 175, 146, 33, 53, 148, 237,
     178, 239, 255, 10, 79, 212, 99, 33, 
     26, 251, 9, 222, 11, 1, 191, 101, 
     255, 249, 146, 254, 26, 210, 183, 235];
pub const ENTROPY_CTR: [u8; 48] = 
    [156, 186, 175, 146, 33, 53, 148, 237,
     178, 239, 255, 10, 79, 212, 99, 33, 
     26, 251, 9, 222, 11, 1, 191, 101, 
     255, 249, 146, 254, 26, 210, 183, 235,
     239, 43, 103, 243, 3, 22, 168, 150,
     198, 204, 150, 174, 202, 171, 114, 14];
pub const ENTROPY_TOO_SHORT: [u8; 8] =  
    [156, 186, 175, 146, 33, 53, 148, 237];

/*  Nonce constants 

    For each mechanism requests a maximum of 16 bytes of nonce is sufficient to instantiate. 
    The CTR-DRBG with no DF is an exception to this rule since it does not need a nonce for
    the instantiation.
*/
pub const NONCE: [u8; 16] = 
    [16, 155, 36, 155, 57, 142, 88, 2,
     19, 20, 33, 231, 8, 252, 103, 171];
pub const NONCE_TOO_SHORT: [u8; 6] = 
    [16, 155, 36, 155, 57, 142];

/*  Personalization string constants

    The length of the personalization string that can be handled by a specific instance depends on the
    security strength of that instance. SP 800-90A enforces the personalization string to be at most
    sec_str bytes long. 
*/
pub const PERS_256: [u8; 32] = 
    [82, 141, 239, 218, 116, 11, 127, 185,
     92, 37, 138, 5, 154, 36, 172, 19,
     101, 18, 206, 96, 7, 76, 3, 241,
     254, 172, 253, 166, 182, 26, 167, 169];
pub const PERS_TOO_LONG: [u8; 33] = 
    [82, 141, 239, 218, 116, 11, 127, 185,
     92, 37, 138, 5, 154, 36, 172, 19,
     101, 18, 206, 96, 7, 76, 3, 241,
     254, 172, 253, 166, 182, 26, 167, 169,
     2];

/*  Additional input constants

    The length of the additional input that can be handled by a specific instance depends on the
    security strength of that instance. SP 800-90A enforces the additional input to be at most
    sec_str bytes long.
*/
pub const ADD_IN_256: [u8; 32] = 
    [7, 105, 103, 193, 196, 157, 39, 168,
     95, 112, 93, 23, 64, 111, 15, 106,
     93, 45, 44, 55, 59, 216, 6, 99,
     65, 216, 220, 211, 198, 7, 221, 132];
pub const ADD_IN_TOO_LONG: [u8; 33] = 
    [7, 105, 103, 193, 196, 157, 39, 168,
     95, 112, 93, 23, 64, 111, 15, 106,
     93, 45, 44, 55, 59, 216, 6, 99,
     65, 216, 220, 211, 198, 7, 221, 132,
     247];