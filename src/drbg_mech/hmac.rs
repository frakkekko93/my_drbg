use digest::{BlockInput, FixedOutput, Reset, Update};
use generic_array::{ArrayLength, GenericArray};
use hmac::{Hmac, Mac, NewMac};

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
    zeroized: bool,
}

impl<D> HmacDRBG<D>
where
    D: Update + FixedOutput + BlockInput + Reset + Clone + Default,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    /*  Allocates a new instance of the DRBG using the passed entropy, nonce and personalization string.

        Parameters:
            - entropy: the desired entropy to be used for the instantiation
            - nonce: the desired nonce to be used for the instantiation
            - pers: the optional personalization string to be used for the instantiation
        
        Return value:
            - pointer to the newly created instance
    */
    pub fn new(entropy: &[u8], nonce: &[u8], pers: &[u8]) -> Self {
        let mut k = GenericArray::<u8, D::OutputSize>::default();
        let mut v = GenericArray::<u8, D::OutputSize>::default();
        
        for i in 0..k.as_slice().len() {
            k[i] = 0x0;
        }

        for i in 0..v.as_slice().len() {
            v[i] = 0x01;
        }

        let mut this = Self { k, v, count: 0 , reseed_interval: 0, zeroized: false};

        this.update(Some(&[entropy, nonce, pers]));
        this.count = 1;
        this.reseed_interval = 10;

        this
    }

    /*  Returns the reseed counter of this instance.

        Return value:
            - the reseed counter
    */
    pub fn count(&self) -> usize {
        self.count
    }

    /*  Reseeds the instance using fresh entropy and an eventual additional input.
        
        Parameters:
            - the new entropy to be used for reseeding
            - optional additional inputs to the reseeding process
    */
    pub fn reseed(&mut self, entropy: &[u8], add: Option<&[u8]>) {
        self.update(Some(&[entropy, add.unwrap_or(&[])]));
        self.count = 1;
    }

    /*  Generates a vector of pseudorandom bytes.

        Parameters:
            - result: a reference to the output vector
            - req_bytes: the number of bytes to be generated
            - add: optional additional inputs to the generation

        Return values:
            - 0: SUCCESS, result is valid and can be used
            - 1: ERROR, reseed interval has been reached and reseeding is necessary
    */
    pub fn generate(&mut self,result: &mut Vec<u8>, req_bytes: usize, add: Option<&[u8]>) -> usize {
        if self.count >= self.reseed_interval{
            return 1;
        }

        if let Some(add) = add {
            self.update(Some(&[add]));
        }

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
        
        match add {
            Some(add) => {
                self.update(Some(&[add]));
            }
            None => {
                self.update(None);
            }
        }
        self.count += 1;
        return 0;
    }

    /*  Retrieves and instance of the hmac primitive that uses self.k as a key.
    
        Return values:
            - a pointer to an hmac primitive
     */
    fn hmac(&self) -> Hmac<D> {
        Hmac::new_varkey(&self.k).expect("Smaller and larger key size are handled by default")
    }

    /*  Updates the internal status of the DRBG using eventual additional seeds as inputs.

        Parameters:
            - seeds: additional inputs to be used for the update of the internal state
     */
    fn update(&mut self, seeds: Option<&[&[u8]]>) {
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

        if seeds.is_none() {
            return;
        }

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

    /*  Indicates whether a forced reseed is needed for this instance.
    
        Return values:
            - boolean statement
     */
    pub fn reseed_needed(&self) -> bool{
        self.count >= self.reseed_interval
    }

    /*  Function needed to zeroize the content of this instance and macke it unusable. */
    pub fn zeroize(&mut self){
        for i in 0..self.k.as_slice().len() {
            self.k[i] = 0x0;
        }

        for i in 0..self.v.as_slice().len() {
            self.v[i] = 0x0;
        }

        self.count = 0;
        self.reseed_interval = 0;
        self.zeroized = true;
    }

    /*  Function needed to check if the current instance is zeroized.
    
        Return values:
            - boolean statement
    */
    pub fn _is_zeroized(&mut self) -> bool{
        self.zeroized
    }
}
