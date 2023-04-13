use super::gen_mech::DRBG_Mechanism_Functions;
use generic_array::ArrayLength;
use std::any::TypeId;
use super::utility::*;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};

/*  The life of each generated seed of this DRBG. */
const SEED_LIFE: usize = 1000;

/*  The length of the counter used by the block cipher in bits. */
const CTR_LEN: usize = 16;

/*  Implementation of the CTR-DRBG mechanisms using a DF as specified in section 10.2.1 of NIST SP 800-90A.
    According to NIST SP 800-57 AES 128/192/256 support security strengths of respectively 128/192/256 bits. Thus, since this
    implementation supports every one of these block ciphers, it also can support any security strength in the range [128, 256].
    
    - k: key of the underlying block cipher
    - v: vector used for block encryptions
    - count: reseed counter
    - zeroized: indicates whether the instance has been zeroized (a new instance is needed)
    - seedlen: length of the parameters used by this mechanism (=> blocklen + keylen)
    - blocklen: length of the input/output blocks of the block cipher
    - keylen: length of the key of the blockcipher */

#[allow(non_camel_case_types)]
pub struct CtrDrbgMech_DF<D: 'static>
where
    D: BlockCipher + BlockEncrypt + BlockDecrypt + KeyInit,
    D::BlockSize: ArrayLength<u8>,
    D::KeySize: ArrayLength<u8>,
{
    k: GenericArray<u8, D::KeySize>,
    v: GenericArray<u8, D::BlockSize>,
    count: usize,
    zeroized: bool,
    seedlen: usize,
    blocklen: usize,
    keylen: usize,
}

/*  Implementing functions that are specific of the CTR-DRBG mechanism with DF. */
impl<D> CtrDrbgMech_DF<D>
where
    D: BlockCipher + BlockEncrypt + BlockDecrypt + KeyInit,
    D::BlockSize: ArrayLength<u8>,
    D::KeySize: ArrayLength<u8>,
{   
    /*  This function is used to produce an output block by encrypting input data as a chain of input blocks.
        (see NIST SP 800-90A, section 10.3.3)
        
        Parameters:
            - data: the input data to be encrypted
            
        Outputs:
            - output_block: the returned encrypted block. */
    fn bcc(&self, key: &GenericArray::<u8, D::KeySize>, data: &Vec<u8> ) -> Option<GenericArray::<u8, D::BlockSize>>{
        // Initializing the first chaining value to a 0 vector (step 1)
        let mut chaining_value = GenericArray::<u8, D::BlockSize>::default();
        chaining_value.fill(0);
        let test_block = chaining_value.clone();

        // Number of blocks to be processed (step 2)
        let n = data.len() / (self.blocklen/8);
        let cipher = D::new(key);

        // Processing data block by block (step 3,4)
        for i in 0..n {
            // XORing the chaining value with the n-th block of the received data (step 4.1)
            xor_vecs(&mut chaining_value.to_vec(), &data[0+self.blocklen*i..self.blocklen*(i+1)].to_vec());

            // Encrypting the chaining value (step 4.2)
            let mut block = chaining_value.clone();
            cipher.encrypt_block(&mut block);
            chaining_value.clone_from_slice(block.as_slice());
        }

        // Input data is too short and no block could be encrypted
        if test_block == chaining_value {
            None
        }
        else {
            // Returning the chaining value as an output block (step 5,6)
            Some(chaining_value)
        }
    }

    /*  This function is used by a CTR-DRBG to derive the seed material used for each operation it is supposed to do.
        (see NIST SP 800-90A, section 10.3.3) 
        
        Parameters:
            - input: the input data to be used by the derivation function
            - num_bytes: the nnumber of bytes to be produced by the derivation function
        
        Return values:
            - output_bytes: eventual bytes produced by the DF (None if error happened) */
    fn block_cipher_df(&mut self, input: Vec<u8>, num_bytes: usize) -> Option<Vec<u8>>{
        const MAX_BITS: usize = 512;

        // Requested too many bits (step 1)
        if num_bytes > MAX_BITS/8 {return None;}

        // Initializing variables for the DF (steps 2,3,4,5).
        let l = &input.len().to_be_bytes()[3..];
        let n = &num_bytes.to_be_bytes()[3..];
        let mut s = Vec::<u8>::new();
        s.append(&mut l.to_vec());
        s.append(&mut n.to_vec());
        s.append(&mut input.clone());
        s.push(0x80);
        while s.len() < self.blocklen/8 {
            s.push(0x00);
        }

        // Steps 6-7-8
        let mut temp = Vec::<u8>::new();
        let mut k = GenericArray::<u8, D::KeySize>::default();
        let mut counter:u8 = 0x00;
        let mut i: usize =0;
        while i < self.keylen/8 {
            k[i]= counter;
            counter += 1;
            i += 1;
        }

        // Generating bits using the data derived before (step 9)
        let mut i: u32 = 0;
        let mut iv = Vec::<u8>::new();
        while temp.len() < (self.keylen + self.blocklen)/8 {
            // Inizialization of the IV (step 9.1)
            iv.clear();
            iv.append(&mut i.to_be_bytes().to_vec());
            while iv.len() < self.blocklen/8 {
                iv.push(0x00);
            }

            // Encrypting the IV using the BCC function (step 9.2)
            iv.append(&mut s.clone());
            let res_bcc = self.bcc(&k,&iv);
            let out_block;
            match res_bcc {
                None => {
                    return None;
                }
                Some(inst) => {
                    out_block = inst;
                }
            }
            temp.append(&mut out_block.to_vec());

            // Incrementing the counter (step 9.3)
            i += 1;
        }

        // Saving temp bytes (steps 10-11)
        let k = GenericArray::<u8, D::KeySize>::from_slice(&temp[..self.keylen/8]);
        let mut x = temp[self.keylen/8..].to_vec();

        // Clearing temp and starting a block_encrypt cicle (steps 12-13)
        let mut temp = Vec::<u8>::new();
        let cipher = D::new(k);
        while temp.len() < num_bytes {
            // Encrypting x and updating its value (step 13.1)
            let mut x_copy = GenericArray::<u8, D::BlockSize>::default();
            x_copy.clone_from_slice(&x);
            cipher.encrypt_block(&mut x_copy);
            x.clone_from(&x_copy.to_vec());

            // Appending the new value of x to temp (step 13.2)
            temp.append(&mut x.to_vec());
        }

        // Returning the exact number of requested bytes (steps 14-15)
        Some(temp.clone()[..num_bytes].to_vec())
    }

    /*  This function is used to update the internal state of the CTR-DRBG.
        (see NIST SP 800-90A, section 10.2.1.2)
        
        Parameters:
            - provided_data: the data to be used for the update (exaclty seedlen bits) */
    fn update(&mut self, provided_data: &Vec<u8>) {
        // Provided data must not be empty and must be seedlen long
        if provided_data.is_empty() || provided_data.len() != self.seedlen/8 {
            return;
        }

        // Init local variables (step 1)
        let mut temp = Vec::<u8>::new();
        let cipher = self.block_cipher();

        // Fill temporary vector block by block until seedlen is reached (step 2)
        let mut i: usize = 0;
        while i < self.seedlen {
            // Appropriately increment the counter based on his size (step 2.1)
            if CTR_LEN < self.blocklen {
                let mid_point = self.blocklen/8 - CTR_LEN/8;
                
                // Increment the rigth-most CTR_LEN/8 bytes of V (step 2.1.1)
                let mut right_v = self.v[mid_point..].to_vec();
                modular_add(&mut right_v, 0x01);

                // Creating a clone of V with the incremented right-most CTR_LEN/8 bytes
                let mut v_clone = GenericArray::<u8, D::BlockSize>::default();
                let (left, right) = v_clone.split_at_mut(mid_point);
                left.clone_from_slice(&self.v[..mid_point]);
                right.clone_from_slice(&right_v.as_slice());

                // Update V (step 2.1.2)
                self.v.clone_from(&v_clone);
            }
            else {
                // Increment V (step 2.1 alternative)
                let mut v_clone = self.v.to_vec();
                modular_add(&mut v_clone, 0x01);

                // Update V
                self.v.clone_from_slice(&v_clone);
            }

            // Encrypt V (step 2.2)
            let mut block = self.v.clone();
            cipher.encrypt_block(&mut block);

            // Append encrypted block to temporary vector (step 2.3)
            temp.append(&mut block.to_vec());

            // Increment counter
            i += self.blocklen;
        }

        // Taking only seedlen bits (step 3)
        temp.resize(self.seedlen/8, 0x00);

        // Performing temp XOR provided_data (step 4)
        xor_vecs(&mut temp, provided_data);

        // Update K (step 5)
        self.k.clone_from_slice(&temp[..self.keylen/8]);

        // Update V (step 6)
        self.v.clone_from_slice(&temp[self.keylen/8..]);
    }

    /*  Retrieves and instance of the hmac primitive that uses self.k as a key.
    
        Return values:
            - a pointer to an hmac primitive */
    fn block_cipher(&self) -> D {
        D::new(&self.k)
    }
}

/*  Implementing common DRBG mechanism functions taken from the DRBG_Mechanism_Functions trait (see 'gen_mech'). */
impl<D> DRBG_Mechanism_Functions for CtrDrbgMech_DF<D>
where
    D: BlockCipher + BlockEncrypt + BlockDecrypt + KeyInit,
    D::BlockSize: ArrayLength<u8>,
    D::KeySize: ArrayLength<u8>,
{   
    /*  This function is implemented following the algorithm described at 10.2.1.3.2 for a CTR-DRBG that uses a df. */
    fn new(entropy: &[u8], nonce: &[u8], pers: &[u8], req_str: &mut usize) -> Option<Self> {
        let seed_len: usize;
        let key_len: usize;
        let block_len: usize = 128;

        // Runtime check on the use of any unallowed hash function and according parameter setup.
        let this_id = TypeId::of::<D>();
        let aes128_id = TypeId::of::<aes::Aes128>();
        let aes192_id = TypeId::of::<aes::Aes192>();
        let aes256_id = TypeId::of::<aes::Aes256>();

        if this_id == aes128_id {
            if *req_str > 128 {return None}
            key_len = 128;
            *req_str = 128;
        }
        else if this_id == aes192_id {
            if *req_str > 192 {return None}
            key_len = 192;
            *req_str = 192;
        }
        else if this_id == aes256_id {
            if *req_str > 256 {return None}
            key_len = 256;
            *req_str = 256;
        }
        else {return None;}
        seed_len = block_len + key_len;

        // Entropy input is too short.
        if entropy.len() < seed_len/8 {return None;}

        // Nonce is too short.
        if nonce.len() < seed_len/16 {return None;}

        // Initializing seed material (step 1)
        let mut seed_material = entropy.clone().to_vec();
        seed_material.append(&mut nonce.to_vec());
        seed_material.append(&mut pers.to_vec());

        // Setting initial values for the internal state (step 3,4,6).
        let mut k = GenericArray::<u8, D::KeySize>::default();
        let mut v = GenericArray::<u8, D::BlockSize>::default();

        for i in 0..k.as_slice().len() {
            k[i] = 0x0;
        }

        for i in 0..v.as_slice().len() {
            v[i] = 0x0;
        }

        let mut this = Self{
            k,
            v,
            count: 1,       // step 6
            zeroized: false,
            seedlen: seed_len,
            blocklen: block_len,
            keylen: key_len,
        };

        // Deriving the actual seedlen seed from the DF (step 2)
        let res_seed = this.block_cipher_df(seed_material, seed_len/8);
        match res_seed {
            None => {
                // Derivation function failed unexpectedly
                return None;
            }
            Some(inst) => {
                seed_material = inst;
            }
        }

        // Updating the internal state using the newly derived seed (step 5)
        this.update(&seed_material);

        // Returning a reference to this instance (step 7)
        Some(this)
    }

    /*  This function is implemented following the algorithm described at 10.2.1.5.2 for a CTR-DRBG that uses a df. */
    fn generate(&mut self, result: &mut Vec<u8>, req_bytes: usize, add: Option<&[u8]>) -> usize {
        // Eventually deleting data in result
        if !result.is_empty() {
            result.clear();
        }
        
        // No generate on a zeroized status (ERROR_FLAG=1)
        if self.zeroized {
            return 1;
        }
        
        // Reached reseed interval (ERROR_FLAG=2, step 1)
        if self.count >= SEED_LIFE{
            return 2;
        }

        /*  Extracting the actual additional input and eventually updating the internal state (step 2) */
        let mut new_add_in = Vec::<u8>::new();
        match add {
            None => {
                for _i in 0..self.seedlen/8 {
                    new_add_in.push(0x00);
                }
            }
            Some(add_in) => {
                let res_df = self.block_cipher_df(add_in.to_vec(), self.seedlen/8);

                match res_df {
                    None => {
                        return 3;
                    }
                    Some(inst) => {
                        new_add_in = inst;
                    }
                }

                self.update(&new_add_in);
            }
        }

        // Generating blocklen bits at a time using the underlying block cipher (step 3,4).
        let cipher = self.block_cipher();
        let mut i: usize = 0;
        while i < req_bytes {
            // Appropriately increment the counter based on his size (step 4.1)
            if CTR_LEN < self.blocklen {
                let mid_point = self.blocklen/8 - CTR_LEN/8;

                // Increment the rigth-most CTR_LEN/8 bytes of V (step 4.1.1)
                let mut right_v = self.v[mid_point..].to_vec();
                modular_add(&mut right_v, 0x01);

                // Creating a clone of V with the incremented right-most CTR_LEN/8 bytes
                let mut v_clone = GenericArray::<u8, D::BlockSize>::default();
                let (left, right) = v_clone.split_at_mut(mid_point);
                left.clone_from_slice(&self.v[..mid_point]);
                right.clone_from_slice(&right_v.as_slice());

                // Update V (step 4.1.2)
                self.v.clone_from(&v_clone);
            }
            else {
                // Increment V (step 4.1.2 alternative)
                let mut v_clone = self.v.to_vec();
                modular_add(&mut v_clone, 0x01);

                // Update V
                self.v.clone_from_slice(&v_clone);
            }

            // Encrypt V (step 4.2)
            let mut block = self.v.clone();
            cipher.encrypt_block(&mut block);

            // Append encrypted block to temporary vector (step 4.3)
            result.append(&mut block.to_vec());

            // Increment counter
            i += self.blocklen/8;
        }

        // Taking only req_bytes (step 5)
        result.resize(req_bytes, 0x00);

        // Updating internal state (step 6)
        self.update(&new_add_in);

        // Incrementing reseed counter (step 7)
        self.count += 1;

        0
    }

    /*  This function is implemented following the algorithm described at 10.2.1.4.2 for a CTR-DRBG that uses a df. */
    fn reseed(&mut self, entropy: &[u8], add: Option<&[u8]>) -> usize {
        // Nothing to be done if zeroized (ERROR_FLAG returned to the application).
        if self.zeroized {
            return 1;
        }

        // Entropy input is too short.
        if entropy.len() < self.seedlen/8 {
            return 2;
        }

        // Deriving seed material from input received (step 1)
        let mut seed_material = entropy.to_vec();
        match add {
            None => {}
            Some(add_in) => {
                seed_material.append(&mut add_in.to_vec());
            }
        }    

        // Deriving the actual seedlen seed from the DF (step 2)
        let res_seed = self.block_cipher_df(seed_material, self.seedlen/8);
        match res_seed {
            None => {
                // Derivation function failed unexpectedly
                return 3;
            }
            Some(inst) => {
                seed_material = inst;
            }
        }

        // Updating the internal state using the derived seed (step 3)
        self.update(&seed_material);

        // Resetting the reseed counter (step 4)
        self.count = 1;

        0
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
        self.seedlen = 0;
        self.keylen = 0;
        self.blocklen = 0;
        self.zeroized = true;
        0
    }

    fn count(&self) -> usize {
        self.count
    }

    fn reseed_needed(&self) -> bool{
        self.count >= SEED_LIFE
    }

    fn _is_zeroized(&self) -> bool{
        self.zeroized
    }

    fn drbg_name() -> String {
        return "CTR-DRBG-DF".to_string();
    }

    fn seed_life() -> usize {
        return SEED_LIFE;
    }
}