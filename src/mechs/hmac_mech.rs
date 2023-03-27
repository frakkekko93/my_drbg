use std::any::TypeId;
use digest::{BlockInput, FixedOutput, Reset, Update};
use generic_array::{ArrayLength, GenericArray};
use hmac::{Hmac, Mac, NewMac};

use super::gen_mech::DRBG_Mechanism_Functions;

/*  The life of each generated seed of this DRBG. */
const SEED_LIFE: usize = 1000;

/*  Implementation of the HMAC-DRBG mechanism. This mechanism can be instantiated only using Sha256 or Sha512
    (see FIPS 140-3 IG section D.R). Since both hashing algorithms support a security strength of 256 bits
    (see NIST SP 800-57pt1r5), this mechanism offers a security strength of max 256 bits.

    - k,v: internal state secret value that are used for he generation of pseudorandombits
    - count: the reseed counter
    - reseed_interval: the maximum number of generate requests that can be served between reseedings
    - zeroized: boolean flag indicating whether the particular instance has been zeroized */
pub struct HmacDrbgMech<D: 'static>
where
    D: Update + BlockInput + FixedOutput + Default,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    k: GenericArray<u8, D::OutputSize>,
    v: GenericArray<u8, D::OutputSize>,
    count: usize,
    reseed_interval: usize,
    zeroized: bool,
}

/*  Implementing functions that are specific of the HMAC-DRBG mechanism. */
impl<D> HmacDrbgMech<D>
where
    D: Update + FixedOutput + BlockInput + Reset + Clone + Default,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    /*  Updates the internal status of the DRBG using eventual additional seeds as inputs.

        Parameters:
            - seeds: additional inputs to be used for the update of the internal state */
    fn update(&mut self, seeds: Option<&[&[u8]]>) {
        // Using the hmac primitive to update the internal state.
        let mut kmac = self.hmac();
        kmac.update(&self.v);
        kmac.update(&[0x00]);
        
        if let Some(seeds) = seeds {
            for seed in seeds {
                kmac.update(seed);
            }
        }
        self.k = kmac.finalize().into_bytes();

        let mut vmac = self.hmac();
        vmac.update(&self.v);
        self.v = vmac.finalize().into_bytes();

        // If no additional seeds are given, we have done everything needed.
        if seeds.is_none() {
            return;
        }

        // Additional update of the internal state using optional seeds
        let seeds = seeds.unwrap();

        let mut kmac = self.hmac();
        kmac.update(&self.v);
        kmac.update(&[0x01]);

        for seed in seeds {
            kmac.update(seed);
        }
        self.k = kmac.finalize().into_bytes();
        
        let mut vmac = self.hmac();
        vmac.update(&self.v);
        self.v = vmac.finalize().into_bytes();
    }

    /*  Retrieves and instance of the hmac primitive that uses self.k as a key.
    
        Return values:
            - a pointer to an hmac primitive */
    fn hmac(&self) -> Hmac<D> {
        Hmac::new_varkey(&self.k).expect("Smaller and larger key size are handled by default")
    }
}

/*  Implementing common DRBG mechanism functions taken from the DRBG_Mechanism_Functions trait (see 'gen_mech'). */
impl<D> DRBG_Mechanism_Functions for HmacDrbgMech<D>
where
    D: Update + FixedOutput + BlockInput + Reset + Clone + Default,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    fn new(entropy: &[u8], nonce: &[u8], pers: &[u8]) -> Option<Self> {
        // Runtime check on the use of any unallowed hash function.
        let this_id = TypeId::of::<D>();
        let sha256_id = TypeId::of::<sha2::Sha256>();
        let sha512_id = TypeId::of::<sha2::Sha512>();
        if this_id != sha256_id && this_id != sha512_id{
            return None;
        }

        // Entropy and nonce parameters must be present.
        if entropy.len() == 0 || nonce.len() == 0 {
            return None
        }

        // Setting initial values for the internal state.
        let mut k = GenericArray::<u8, D::OutputSize>::default();
        let mut v = GenericArray::<u8, D::OutputSize>::default();
        
        for i in 0..k.as_slice().len() {
            k[i] = 0x0;
        }

        for i in 0..v.as_slice().len() {
            v[i] = 0x01;
        }

        let mut this = Self { k, v, count: 0 , reseed_interval: 0, zeroized: false};

        // Updating the internal state using the passed parameters.
        this.update(Some(&[entropy, nonce, pers]));
        this.count = 1;
        this.reseed_interval = SEED_LIFE;

        Some(this)
    }

    fn generate(&mut self, result: &mut Vec<u8>, req_bytes: usize, add: Option<&[u8]>) -> usize {
        // No generate on a zeroized status (ERROR_FLAG=1)
        if self.zeroized {
            return 1;
        }
        
        // Reached reseed interval (ERROR_FLAG=2)
        if self.count >= self.reseed_interval{
            return 2;
        }

        // Updating internal state using additional input
        if let Some(add) = add {
            self.update(Some(&[add]));
        }

        // Using hmac primitive to generate the required bytes
        let mut i = 0;
        while i < req_bytes {
            let mut vmac = self.hmac();
            vmac.update(&self.v);
            self.v = vmac.finalize().into_bytes();

            for j in 0..self.v.len() {
                if i+j >= req_bytes{
                    break;
                }
                result.push(self.v[j]);
            }
            i += self.v.len();
        }
        
        // Updating the internal state one final time
        match add {
            Some(add) => {
                self.update(Some(&[add]));
            }
            None => {
                self.update(None);
            }
        }
        // Update the reseed counter
        self.count += 1;
        return 0;
    }

    fn reseed(&mut self, entropy: &[u8], add: Option<&[u8]>) -> usize {
        // Nothing to be done if zeroized (ERROR_FLAG returned to the application).
        if self.zeroized {
            return 1;
        }
        else{
            // Updating the internal state using the passed parameters.
            self.update(Some(&[entropy, add.unwrap_or(&[])]));
            self.count = 1;
            return 0;
        }
    }

    fn zeroize(&mut self) -> usize{
        // Instance is already zeroized (ERROR_FLAG=1)
        if self.zeroized {
            return 1;
        }
        
        // Zeroizing internal state values
        for i in 0..self.k.as_slice().len() {
            self.k[i] = 0x0;
        }

        for i in 0..self.v.as_slice().len() {
            self.v[i] = 0x0;
        }

        self.count = 0;
        self.reseed_interval = 0;
        self.zeroized = true;

        return 0;
    }

    fn count(&self) -> usize {
        self.count
    }

    fn reseed_needed(&self) -> bool{
        self.count >= self.reseed_interval
    }

    fn _is_zeroized(&self) -> bool{
        self.zeroized
    }

    fn drbg_name() -> String {
        return "HMAC-DRBG".to_string();
    }

    fn seed_life() -> usize {
        return SEED_LIFE;
    }
}