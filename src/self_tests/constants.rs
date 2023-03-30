/*  Entropy constants */
pub const ENTROPY: [u8; 32] = [0; 32];
pub const ENTROPY_CTR: [u8; 48] = [0; 48];
pub const ENTROPY_TOO_SHORT: [u8; 16] = [0; 16];

/*  Nonce constants */
pub const NONCE: [u8; 16] = ENTROPY_TOO_SHORT;
pub const NONCE_TOO_SHORT: [u8; 8] = [0; 8];

/*  Personalization string constants */
pub const PERS: [u8; 32] = ENTROPY;
pub const PERS_TOO_LONG: [u8; 33] = [0; 33];

/* Additional input constants */
pub const ADD_IN: [u8; 32] = ENTROPY;
pub const ADD_IN_TOO_LONG: [u8; 33] = PERS_TOO_LONG;