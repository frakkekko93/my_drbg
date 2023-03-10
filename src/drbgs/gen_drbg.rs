/*  The mechanism that the DRBG is using. */

pub struct DRBG<T>
{
    pub internal_state: Option<T>,
    pub security_strength: usize,
}