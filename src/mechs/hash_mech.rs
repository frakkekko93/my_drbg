
use std::{any::TypeId, ops::Add};
use digest::{BlockInput, FixedOutput, Reset, Update, Digest};
use generic_array::ArrayLength;
use super::gen_mech::DRBG_Mechanism_Functions;

/*  Properties of the Hash-DRBG mechanism. This mechanism can be intantiated only using Sha256 or Sha512
    (see FIPS 140-3 IG section D.R). Since both hashing algorithms support a security strength of 256 bits
    (see NIST SP 800-57pt1r5), this mechanism offers a security strength of max 256 bits.

    - v,c: internal state secret value that are used for he generation of pseudorandombits
    - count: the reseed counter
    - reseed_interval: the maximum number of generate requests that can be served between reseedings
    - zeroized: boolean flag indicating whether the particular instance has been zeroized
    - seed_len: lengths of the internal state values that depends on the hash function that is used
    - hash_fun: the hash function that is used.
*/
pub struct HashDrbgMech<D: 'static>
where
    D: Update + BlockInput + FixedOutput + Default,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    v: Vec<u8>,
    c: Vec<u8>,
    count: usize,
    reseed_interval: usize,
    zeroized: bool,
    seedlen: usize,
    hash_fun: D,
}

/*  Implementing funtion that are specific of the HMAC-DRBG mechanism. */
impl<D> HashDrbgMech<D>
where
    D: Update + FixedOutput + BlockInput + Reset + Clone + Default,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    /*  This function performs a modular addition between two numbers represented as byte vectors.
        The reference module is of num1. We expect num1 to be longer or equal to num2. */
    fn modular_add_vec(&mut self, num1: &mut Vec<u8>, num2: Vec<u8>) {
        if num1.is_empty() || num2.is_empty() {
            return;
        }

        let len1 = num1.len();
        let len2 = num2.len();
        let mut global_carry= false;
        
        if len2 > len1 {
            return;
        }

        let mut i = len2-1;
        let mut j = len1-1;
        while i > 0 {
            let (res, carry) = num1[j].overflowing_add(num2[i]);
            num1[j] = res;

            if carry {
                let mut num1_copy = num1[..j-1].to_vec();
                let mut num1_rem = num1[j-1..].to_vec();
                HashDrbgMech::<D>::modular_add(&mut num1_copy, 1);
                num1.clear();
                num1.append(&mut num1_copy);
                num1.append(&mut num1_rem);
            }

            i -= 1;
            j -= 1;
            global_carry = carry;
        }

        if global_carry {
            let res = num1[0].wrapping_add(num2[0]);
            num1[0] = res;
        }
    }

    /*  Performs a modular addition between a vector of bytes and a single byte. */
    fn modular_add(num: &mut Vec<u8>, rhs: u8) {
        if num.is_empty() {
            return;
        }

        let len = num.len();
        let mut j = len-1;
        let (mut res, mut carry) = num[j].overflowing_add(rhs);
        num[j] = res;

        if j>=1 {
            j -= 1;
            while carry && j>0 {
                (res, carry) = num[j].overflowing_add(1);
                num[j] = res;
                j -= 1;
            }
        }

        if carry {
            res= num[0].wrapping_add(1);
            num[0] = res;
        }        
    }

    /*  This is a generation function used by the mechanism to generate bits from the underlying Hash function.
    
        Parameters:
            - result: the output vector for the generated bits
            - input: string to be hashed by the df
            - num_bytes: the number of bytes to be produced by the df.
        
        Return values:
            - 0: SUCCESS, the generation was completed smoothly
            - 1: ERROR, output vector was not empty when received
    */
    fn hash_df(&mut self, result: &mut Vec<u8>, input: Vec<u8>, num_bytes: usize) -> usize {
        if !result.is_empty() {
            return 1;
        }

        let mut counter: u8 = 0x01;
        let string_bytes = num_bytes.to_string();

        let mut i: usize = 0;
        while i < num_bytes {
            self.hash_fun.update(counter.to_string());
            self.hash_fun.update(&string_bytes);
            self.hash_fun.update(&input);
            let hash = self.hash_fun.finalize_reset().to_vec();
            let hash_len = hash.len();

            for j in 0..hash_len {
                if j+i >= num_bytes {
                    return 0;
                }

                result.push(hash[j]);
            }

            i += hash_len;
            counter = counter.add(0x01);
        }
        0
    }

    /*  This function is used by the generation algorithm to generate pseudo-random bytes from the underlying hash function. */
    fn hashgen(&mut self, result: &mut Vec<u8>, num_bytes: usize) {
        let mut data = self.v.clone();

        let mut i: usize = 0;
        while i < num_bytes {
            self.hash_fun.update(&data);
            let w = self.hash_fun.finalize_reset().to_vec();
            let hash_len = w.len();

            for j in 0..hash_len {
                if j+i >= num_bytes {
                    return;
                }

                result.push(w[j]);
            }

            HashDrbgMech::<D>::modular_add(&mut data, 1);

            i += hash_len;
        }
    }

    /*  Returns the reseed counter of this instance.

        Return value:
            - the reseed counter */
    pub fn count(&self) -> usize {
        self.count
    }

    /*  Indicates whether a forced reseed is needed for this instance.
    
        Return values:
            - boolean statement */
    pub fn reseed_needed(&self) -> bool{
        self.count >= self.reseed_interval
    }

    /*  Function needed to check if the current instance is zeroized.
    
        Return values:
            - boolean statement */
    pub fn _is_zeroized(&self) -> bool{
        self.zeroized
    }
}

/*  Implementing common DRBG mechanism functions taken from the DRBG_Mechanism_Functions trait. */
impl<D> DRBG_Mechanism_Functions for HashDrbgMech<D>
where
    D: Update + FixedOutput + BlockInput + Reset + Clone + Default,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    fn new(entropy: &[u8], nonce: &[u8], pers: &[u8]) -> Option<Self> {
        // Runtime check on the use of any unallowed hash function.
        let seedlen;
        let this_id = TypeId::of::<D>();
        let sha256_id = TypeId::of::<sha2::Sha256>();
        let sha512_id = TypeId::of::<sha2::Sha512>();
        if this_id != sha256_id && this_id != sha512_id{
            return None;
        }
        else if this_id == sha256_id {
            seedlen = 440;
        }
        else {
            seedlen = 888;
        }

        // Init internal state.
        let mut this = Self{ 
            v: Vec::<u8>::new(), 
            c: Vec::<u8>::new(), 
            count: 1, 
            reseed_interval: 1000, 
            zeroized: false, 
            seedlen, 
            hash_fun: D::new(),
        };

        // Derive V.
        let mut res = Vec::<u8>::new();
        let mut seed_material = entropy.clone().to_vec();
        seed_material.append(&mut nonce.to_vec());
        seed_material.append(&mut pers.to_vec());
        if this.hash_df(&mut res, seed_material, seedlen/8) != 0 {return None}


        this.v.append(&mut res);

        println!("Hash-DRBG-Mech: generated V: {}\nLen: {}", hex::encode(&this.v), this.v.len());

        // Derive C.
        let mut seed_material = this.v.clone();
        seed_material.insert(0, 0x00);
        if this.hash_df(&mut res, seed_material, seedlen/8) != 0 {return None}
        this.c.append(&mut res);

        println!("Hash-DRBG-Mech: generated C: {}\nLen: {}", hex::encode(&this.c), this.c.len());

        // Return instance
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
            let mut seed_material = self.v.clone();
            seed_material.insert(0, 0x02);
            seed_material.append(&mut add.to_vec());
            self.hash_fun.update(seed_material);
            let w = self.hash_fun.finalize_reset().to_vec();

            let mut v_clone = self.v.clone();
            self.modular_add_vec(&mut v_clone, w);
            self.v.clear();
            self.v.append(&mut v_clone);
        }

        self.hashgen(result, req_bytes);

        let mut seed_material = self.v.clone();
        seed_material.insert(0, 0x03);
        self.hash_fun.update(seed_material);
        let w = self.hash_fun.finalize_reset().to_vec();

        let mut v_clone = self.v.clone();
        self.modular_add_vec(&mut v_clone, w);
        self.v.clear();
        self.v.append(&mut v_clone);

        let mut v_clone = self.v.clone();
        self.modular_add_vec(&mut v_clone, self.c.clone());
        self.v.clear();
        self.v.append(&mut v_clone);

        self.count += 1;

        0
    }

    /*  Introduces an additional ERROR wrt the generic DRBG mechanism functions:    
            - 2: ERROR, the hash_df failed
    */
    fn reseed(&mut self, entropy: &[u8], add: Option<&[u8]>) -> usize {
        // Nothing to be done if zeroized (ERROR_FLAG returned to the application).
        if self.zeroized {
            return 1;
        }
        
        // Derive V.
        let mut res = Vec::<u8>::new();
        let mut seed_material = self.v.clone();
        seed_material.insert(0, 0x01);
        seed_material.append(&mut entropy.to_vec());
        match add {
            None => {}
            Some(add_in) => {
                seed_material.append(&mut add_in.to_vec());
            }
        }
        if self.hash_df(&mut res, seed_material, self.seedlen/8) != 0 {return 2}
        self.v.clear();
        self.v.append(&mut res);

        // Derive C.
        res.clear();
        let mut seed_material = Vec::<u8>::new();
        seed_material.push(0x00);
        seed_material.append(&mut self.v.clone());
        if self.hash_df(&mut res, seed_material, self.seedlen/8) != 0 {return 2}
        self.c.clear();
        self.c.append(&mut res);

        println!("Hash-DRBG-Mech: reseeded V: {}\nLen: {}", hex::encode(&self.v), self.v.len());
        println!("Hash-DRBG-Mech: reseeded C: {}\nLen: {}", hex::encode(&self.c), self.c.len());

        0
    }

    fn zeroize(&mut self) -> usize{
        // Instance is already zeroized (ERROR_FLAG=1)
        if self.zeroized {
            return 1;
        }
        
        // Zeroizing internal state values
        for i in 0..self.v.as_slice().len() {
            self.v[i] = 0x0;
        }

        for i in 0..self.c.as_slice().len() {
            self.c[i] = 0x0;
        }

        self.count = 0;
        self.reseed_interval = 0;
        self.zeroized = true;
        self.seedlen = 0;
        self.hash_fun.reset();

        0
    }
}