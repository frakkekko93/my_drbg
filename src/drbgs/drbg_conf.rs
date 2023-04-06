/*  Configuration of the DRBG.
    
    This DRBG can be instantiated using anyone of the mechanisms defined in the 'mechs' module. These mechanisms support 
    a maximum of 256 bits of security strength (MAX_SEC_STR).
    The DRBG is configured to generate a maximum of 2048 bits per-request (MAX_PRB). This option may actually be changed but be 
    aware of the limits imposed in tables 2 and 3 of NIST SP 800-90A. */
pub const MAX_SEC_STR: usize = 256;     // Maximum security strength supported by all the available mechanisms
pub const MAX_PRB: usize = 2048;        // Maximum number of bits that can be requested at each generate call

/*  These constants are used to determine whether each mechanism has been already used or not. If not, self-tests for that
    mechanism must be run and passed before operating the DRGB. */
pub static mut FIRST_USE_HASH_SHA_256: bool = true;         // true => first time the HASH-DRBG with Sha-256 has been instantiated
pub static mut FIRST_USE_HASH_SHA_512: bool = true;         // true => first time the HASH-DRBG with Sha-512 has been instantiated
pub static mut FIRST_USE_HMAC_SHA_256: bool = true;         // true => first time the HMAC-DRBG with Sha-256 has been instantiated
pub static mut FIRST_USE_HMAC_SHA_512: bool = true;         // true => first time the HMAC-DRBG with Sha-512 has been instantiated
pub static mut FIRST_USE_CTR_NO_DF_AES_128: bool = true;    // true => first time the CTR-DRBG with AES-128 has been instantiated
pub static mut FIRST_USE_CTR_NO_DF_AES_192: bool = true;    // true => first time the CTR-DRBG with AES-192 has been instantiated
pub static mut FIRST_USE_CTR_NO_DF_AES_256: bool = true;    // true => first time the CTR-DRBG with AES-256 has been instantiated
