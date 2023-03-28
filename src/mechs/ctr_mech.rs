use std::any::TypeId;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use generic_array::ArrayLength;

use super::gen_mech::DRBG_Mechanism_Functions;

/*  The life of each generated seed of this DRBG. */
const SEED_LIFE: usize = 1000;

const CTR_LEN: usize = 16;

/*   */
pub struct CtrDrbgMech<D: 'static>
where
    D: BlockCipher + BlockEncrypt + BlockDecrypt + KeyInit,
    D::BlockSize: ArrayLength<u8>,
    D::KeySize: ArrayLength<u8>,
{
    k: GenericArray<u8, D::KeySize>,
    v: GenericArray<u8, D::BlockSize>,
    count: usize,
    reseed_interval: usize,
    zeroized: bool,
    seedlen: usize,
    blocklen: usize,
    keylen: usize,
}

/*  Implementing functions that are specific of the HMAC-DRBG mechanism. */
impl<D> CtrDrbgMech<D>
where
    D: BlockCipher + BlockEncrypt + BlockDecrypt + KeyInit,
    D::BlockSize: ArrayLength<u8>,
    D::KeySize: ArrayLength<u8>,
{
    /*  Performs bit a bit XOR between two vectors of the same size. */
    fn xor_vecs(vec1: &mut Vec<u8>, vec2: Vec<u8>) {
        if vec1.len() != vec2.len() {
            return;
        }

        for i in 0..vec1.len() {
            vec1[i] = vec1[i] ^ vec2[i];
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

    /*  This function is used to update the internal state of the CTR-DRBG.
        (see NIST SP 800-90A, section 10.2.1.2)
        
        Parameters:
            - provided_data: the data to be used for the update (exaclty seedlen bits) */
    fn update(&mut self, provided_data: Vec<u8>) {
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
                CtrDrbgMech::<D>::modular_add(&mut right_v, 0x01);

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
                CtrDrbgMech::<D>::modular_add(&mut v_clone, 0x01);

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
        CtrDrbgMech::<D>::xor_vecs(&mut temp, provided_data);

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
impl<D> DRBG_Mechanism_Functions for CtrDrbgMech<D>
where
    D: BlockCipher + BlockEncrypt + BlockDecrypt + KeyInit,
    D::BlockSize: ArrayLength<u8>,
    D::KeySize: ArrayLength<u8>,
{   
    /*  This function is implemented following the algorithm described at 10.2.1.3.2 for a CTR-DRBG that doesn't use a df. */
    fn new(entropy: &[u8], _nonce: &[u8], pers: &[u8]) -> Option<Self> {
        let seed_len: usize;
        let key_len: usize;
        let block_len: usize = 128;

        // Runtime check on the use of any unallowed hash function and according parameter setup.
        let this_id = TypeId::of::<D>();
        let aes128_id = TypeId::of::<aes::Aes128>();
        let aes192_id = TypeId::of::<aes::Aes192>();
        let aes256_id = TypeId::of::<aes::Aes256>();

        if this_id == aes128_id {key_len = 128;}
        else if this_id == aes192_id {key_len = 192;}
        else if this_id == aes256_id {key_len = 256;}
        else {return None;}
        seed_len = block_len + key_len;
        
        // Entropy parameter must be present and of seedlen bits.
        if entropy.len() != seed_len/8 {
            return None
        }

        // Taking exactly seedlen bits from the PS that has been passed (step 1,2).
        // If an empty pers is received we will use 0^seedlen as pers.
        let mut new_pers = Vec::<u8>::new();
        if pers.len() < seed_len/8 {
            new_pers.append(&mut pers.to_vec());

            for _i in 0..seed_len/8-pers.len() {
                new_pers.push(0x00);
            }
        }
        else if pers.len() == seed_len/8 {
            new_pers.clone_from_slice(&pers);
        }
        else {
            new_pers.clone_from_slice(&pers[..seed_len/8]);
        }

        // Setting initial values for the internal state (step 4,5,7).
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
            count: 1,
            reseed_interval: SEED_LIFE,
            zeroized: false,
            seedlen: seed_len,
            blocklen: block_len,
            keylen: key_len,
        };

        // Updating the internal state using the entropy and given personalization string (step 3,6)
        let mut seed_material = entropy.to_vec();
        CtrDrbgMech::<D>::xor_vecs(&mut seed_material, new_pers);
        this.update(seed_material);

        println!("NEW: initial V: {}, len {}.", hex::encode(&this.v), this.v.len());
        println!("NEW: initial K: {}, len {}.", hex::encode(&this.k), this.k.len());

        // Returning a reference to this instance (step 8)
        Some(this)
    }

    fn generate(&mut self, _result: &mut Vec<u8>, _req_bytes: usize, _add: Option<&[u8]>) -> usize {
        // No generate on a zeroized status (ERROR_FLAG=1)
        if self.zeroized {
            return 1;
        }
        
        // Reached reseed interval (ERROR_FLAG=2)
        if self.count >= self.reseed_interval{
            return 2;
        }

        0
    }

    fn reseed(&mut self, entropy: &[u8], add: Option<&[u8]>) -> usize {
        // Nothing to be done if zeroized (ERROR_FLAG returned to the application).
        if self.zeroized {
            return 1;
        }

        // Taking exactly seedlen bits from the AI that has been passed (step 1,2).
        // If an empty add is received we will use 0^seedlen as additional input.
        let mut new_add_in = Vec::<u8>::new();
        match add {
            None => {
                for _i in 0..self.seedlen/8 {
                    new_add_in.push(0x00);
                }
            }
            Some(add_in) => {
                if add_in.len() < self.seedlen/8 {
                    new_add_in.append(&mut add_in.to_vec());
        
                    for _i in 0..self.seedlen/8-add_in.len() {
                        new_add_in.push(0x00);
                    }
                }
                else if add_in.len() == self.seedlen/8 {
                    new_add_in.clone_from_slice(&add_in);
                }
                else {
                    new_add_in.clone_from_slice(&add_in[..self.seedlen/8]);
                }
            }
        }

        println!("RESEED: using entropy: {}, len {}.", hex::encode(&entropy), entropy.len());
        println!("RESEED: using add_in: {}, len {}.", hex::encode(&new_add_in), new_add_in.len());

        // Updating the internal state using the entropy and given additional input (step 3,4)
        let mut seed_material = entropy.to_vec();
        CtrDrbgMech::<D>::xor_vecs(&mut seed_material, new_add_in);
        self.update(seed_material);

        // Resetting the reseed counter (step 5)
        self.count = 1;

        println!("RESEED: V after reseed: {}, len {}.", hex::encode(&self.v), self.v.len());
        println!("RESEED: K after reseed: {}, len {}.", hex::encode(&self.k), self.k.len());

        0
    }

    fn zeroize(&mut self) -> usize{
        // Instance is already zeroized (ERROR_FLAG=1)
        if self.zeroized {
            return 1;
        }

        0
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
        return "CTR-DRBG".to_string();
    }

    fn seed_life() -> usize {
        return SEED_LIFE;
    }
}