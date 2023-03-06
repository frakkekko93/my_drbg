use digest::{BlockInput, FixedOutput, Reset, Update};
use generic_array::{ArrayLength, GenericArray};

use hmac::{Hmac, Mac, NewMac};

/* Missing fields for the internal state:
        - security_strength: optional if the DRBG only support one security strength
        - prediction_resistance_flag: optional if the DRBG always/never grants predictions resistance
*/
pub struct HmacDRBG<D>
where
    D: Update + BlockInput + FixedOutput + Default,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    k: GenericArray<u8, D::OutputSize>,
    v: GenericArray<u8, D::OutputSize>,
    count: usize,
    reseed_interval: usize,
}

impl<D> HmacDRBG<D>
where
    D: Update + FixedOutput + BlockInput + Reset + Clone + Default,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    /*  Allocates a new instance of the DRBG using the passed entropy, nonce and personalization string.

        Gaps wrt to the instantiate_algorithm:
            - missing security_strength: optional since it is not used
        
        Other gaps:
            - requires a call to the instantiate_function
    */
    pub fn new(entropy: &[u8], nonce: &[u8], pers: &[u8]) -> Self {
        let mut k = GenericArray::<u8, D::OutputSize>::default();
        let mut v = GenericArray::<u8, D::OutputSize>::default();
        
        // Init K to an all 0 bytes array
        for i in 0..k.as_slice().len() {
            k[i] = 0x0;
        }

        // Init V to an all 01 bytes array
        for i in 0..v.as_slice().len() {
            v[i] = 0x01;
        }

        // Init the current instance with the initial values
        let mut this = Self { k, v, count: 0 , reseed_interval: 0};

        // Update the internal state using the parameters received
        this.update(Some(&[entropy, nonce, pers]));
        this.count = 1;
        this.reseed_interval = 10;

        // Returning a reference to this instance
        this
    }

    /* Returns the reseed counter of this instance */
    pub fn count(&self) -> usize {
        self.count
    }

    /*  Reseeds the instace using fresh entropy and an eventual additional input
        
        Gaps wrt the reseed_algorithm:
            + not setting reseed_counter=1
        
        Other gaps:
            - requires a call to the reseed_function
    */
    pub fn reseed(&mut self, entropy: &[u8], add: Option<&[u8]>) {
        self.update(Some(&[entropy, add.unwrap_or(&[])]));
        self.count = 1;
    }

    /*  Generates T pseudorandom bytes

        Gaps wrt the generate_algorithm:
            - missing status return
            - missing a check on the reseed_interval

        Other gaps:
            - requires a call to the generate_function
    */
    pub fn generate<T: ArrayLength<u8>>(&mut self, add: Option<&[u8]>) -> Result<GenericArray<u8, T>, u8> {
        let mut result = GenericArray::default();
        //self.generate_to_slice(result.as_mut_slice(), add);
        
        //Check to see if reseed interval has been reached.
        if self.count >= self.reseed_interval{
            return Err(1);
        }

        // If there is additional input, update the internal state of the DRBG
        if let Some(add) = add {
            self.update(Some(&[add]));
        }

        // For each byte in result
        let mut i = 0;
        while i < result.len() {
            let mut vmac = self.hmac();         // Retrive an hmac instance
            vmac.update(&self.v);                   // Update hmac internal state using V  
            self.v = vmac.finalize().into_bytes();       // Update the value of V

            // Write self.v bytes in the n-th block of result
            for j in 0..self.v.len() {
                result[i + j] = self.v[j];
            }
            i += self.v.len();
        }
        
        // Update internal status using additional input
        match add {
            Some(add) => {
                self.update(Some(&[add]));
            }
            None => {
                self.update(None);
            }
        }
        self.count += 1;    // Increase reseed counter
        Ok(result)
    }

    /*  Generates len(result) pseudo-random bytes

        Gaps wrt the generate_algorithm:
            - missing check on reseed_interval, reseed_counter is never actually used

        TESTS:
            - the function is generating only bytes that are mutiple of v.len(). What if I request something different?
    */
    // pub fn generate_to_slice(&mut self, result: &mut [u8], add: Option<&[u8]>) -> GenericArray<u8, T>{
    //     //Check to see if reseed interval has been reached.
    //     if self.count >= self.reseed_interval{
    //         return None;
    //     }

    //     // If there is additional input, update the internal state of the DRBG
    //     if let Some(add) = add {
    //         self.update(Some(&[add]));
    //     }

    //     // For each byte in result
    //     let mut i = 0;
    //     while i < result.len() {
    //         let mut vmac = self.hmac();         // Retrive an hmac instance
    //         vmac.update(&self.v);                   // Update hmac internal state using V  
    //         self.v = vmac.finalize().into_bytes();       // Update the value of V

    //         // Write self.v bytes in the n-th block of result
    //         for j in 0..self.v.len() {
    //             result[i + j] = self.v[j];
    //         }
    //         i += self.v.len();
    //     }
        
    //     // Update internal status using additional input
    //     match add {
    //         Some(add) => {
    //             self.update(Some(&[add]));
    //         }
    //         None => {
    //             self.update(None);
    //         }
    //     }
    //     self.count += 1;    // Increase reseed counter
    // }

    /* Retrieves and instance of the hmac primitive that uses self.k as a key */
    fn hmac(&self) -> Hmac<D> {
        Hmac::new_varkey(&self.k).expect("Smaller and larger key size are handled by default")
    }

    /* Update the internal status of the DRBG using eventual additional seeds as inputs */
    fn update(&mut self, seeds: Option<&[&[u8]]>) {
        let mut kmac = self.hmac();         // Retrieve an instance of kmac
        kmac.update(&self.v);                   // Update the internal state of HMAC using self.v
        kmac.update(&[0x00]);                   // Update the internal state of HMAC using a 0 byte
        
        // If there are one or more seeds, update the internal state of the HMAC using each of the seeds
        if let Some(seeds) = seeds {
            for seed in seeds {
                kmac.update(seed);
            }
        }
        self.k = kmac.finalize().into_bytes();      // Update the value of K using HMAC

        let mut vmac = self.hmac();         // Retrieving a new instance of HMAC using the fresh K
        vmac.update(&self.v);                   // Updating the state of HMAC using V
        self.v = vmac.finalize().into_bytes();         // Updating the value of V using HMAC

        // If there are no additional seeds, stop here
        if seeds.is_none() {
            return;
        }

        let seeds = seeds.unwrap();         // Retrieving additional seeds

        let mut kmac = self.hmac();         // Retrieving a new instance of HMAC
        kmac.update(&self.v);                   // Update the internal state of HMAC using V
        kmac.update(&[0x01]);                   // Update the internal state of HMAC using a 01 byte

        // Update the internal state of the HMAC using each of the additional seeds
        for seed in seeds {
            kmac.update(seed);
        }
        self.k = kmac.finalize().into_bytes();      // Update the K value using HMAC
        
        // Retrieving a new HMAC instance using the fresh K and updating V value.
        let mut vmac = self.hmac();
        vmac.update(&self.v);
        self.v = vmac.finalize().into_bytes();
    }
}
