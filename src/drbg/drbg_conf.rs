/*  Configuration of the DRBG.
    
    This DRBG can be instantiated using anyone of the mechanisms defined in the 'mechs' module. These mechanisms support 
    a maximum of 256 bits (32 bytes) of security strength (MAX_SEC_STR).

    A summary of the available mechanisms is the following:
        MECHANISM                                   SUPPORTED STRENGTH                              RELATED FILE
        HMAC-DRBG with Sha 256                      256 (32 bytes)                                  mechs/hmac_mech.rs
        HMAC-DRBG with Sha 512                      256 (32 bytes)                                  mechs/hmac_mech.rs
        Hash-DRBG with Sha 256                      256 (32 bytes)                                  mechs/hash_mech.rs
        Hash-DRBG with Sha 512                      256 (32 bytes)                                  mechs/hash_mech.rs
        CTR-DRBG with AES 128 (no DF)               128 (16 bytes)                                  mechs/ctr_mech.rs
        CTR-DRBG with AES 192 (no DF)               192 (24 bytes)                                  mechs/ctr_mech.rs
        CTR-DRBG with AES 256 (no DF)               256 (32 bytes)                                  mechs/ctr_mech.rs
        CTR-DRBG with AES 128 (DF)                  128 (16 bytes)                                  mechs/ctr_mech_with_df.rs
        CTR-DRBG with AES 192 (DF)                  192 (24 bytes)                                  mechs/ctr_mech_with_df.rs
        CTR-DRBG with AES 256 (DF)                  256 (32 bytes)                                  mechs/ctr_mech_with_df.rs

    The DRBG is configured to generate a maximum of 2048 bits (256 bytes) per-request (MAX_PRB). This option may actually be changed but be 
    aware of the limits imposed in tables 2 and 3 of NIST SP 800-90A. */
pub const MAX_SEC_STR: usize = 32;      // Maximum security strength supported by any of the available mechanisms
pub const MAX_PRB: usize = 256;         // Maximum number of bytes that can be requested at each generate call

/*  These constants are used to determine whether each mechanism has been already used or not. If not, self-tests for that
    mechanism must be run and passed before instantiating and operating the DRGB and with that specific mechanism. */
pub static mut FIRST_USE_HASH_SHA_256: bool = true;         // true => first time the HASH-DRBG with Sha-256 has been instantiated
pub static mut FIRST_USE_HASH_SHA_512: bool = true;         // true => first time the HASH-DRBG with Sha-512 has been instantiated
pub static mut FIRST_USE_HMAC_SHA_256: bool = true;         // true => first time the HMAC-DRBG with Sha-256 has been instantiated
pub static mut FIRST_USE_HMAC_SHA_512: bool = true;         // true => first time the HMAC-DRBG with Sha-512 has been instantiated
pub static mut FIRST_USE_CTR_NO_DF_AES_128: bool = true;    // true => first time the CTR-DRBG (no DF) with AES-128 has been instantiated
pub static mut FIRST_USE_CTR_NO_DF_AES_192: bool = true;    // true => first time the CTR-DRBG (no DF) with AES-192 has been instantiated
pub static mut FIRST_USE_CTR_NO_DF_AES_256: bool = true;    // true => first time the CTR-DRBG (no DF) with AES-256 has been instantiated
pub static mut FIRST_USE_CTR_DF_AES_128: bool = true;       // true => first time the CTR-DRBG (DF) with AES-128 has been instantiated
pub static mut FIRST_USE_CTR_DF_AES_192: bool = true;       // true => first time the CTR-DRBG (DF) with AES-192 has been instantiated
pub static mut FIRST_USE_CTR_DF_AES_256: bool = true;       // true => first time the CTR-DRBG (DF) with AES-256 has been instantiated

/*  This constant is set when overall self-tests are run over all available algorithms to avoid running tests twice. */
pub static mut OVERALL_TEST_RUN: bool = false;