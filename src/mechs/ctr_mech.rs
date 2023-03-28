use std::any::TypeId;
use aes::*;
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

        vec1.iter_mut()
        .zip(vec2.iter())
        .for_each(|(x1, x2)| *x1 ^= *x2);
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
        temp.resize(self.seedlen, 0x00);

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

        None
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

        0
    }

    fn reseed(&mut self, entropy: &[u8], add: Option<&[u8]>) -> usize {
        // Nothing to be done if zeroized (ERROR_FLAG returned to the application).
        if self.zeroized {
            return 1;
        }

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
        return "HMAC-DRBG".to_string();
    }

    fn seed_life() -> usize {
        return SEED_LIFE;
    }
}