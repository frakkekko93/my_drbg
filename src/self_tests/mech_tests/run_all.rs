use crate::mechs::gen_mech::DRBG_Mechanism_Functions;
use crate::self_tests::mech_tests::*;
use std::any::TypeId;
use crate::mechs;
use aes::*;
use sha2::*;

pub fn run_tests<T: DRBG_Mechanism_Functions + 'static>(strength: usize) -> usize{
    let this_id = TypeId::of::<T>();
    let hash_sha_256 = TypeId::of::<mechs::hash_mech::HashDrbgMech<Sha256>>();
    let hash_sha_512 = TypeId::of::<mechs::hash_mech::HashDrbgMech<Sha512>>();
    let hmac_sha_256 = TypeId::of::<mechs::hmac_mech::HmacDrbgMech<Sha256>>();
    let hmac_sha_512 = TypeId::of::<mechs::hmac_mech::HmacDrbgMech<Sha512>>();
    let ctr_no_df_aes_128 = TypeId::of::<mechs::ctr_mech::CtrDrbgMech<Aes128>>();
    let ctr_no_df_aes_192 = TypeId::of::<mechs::ctr_mech::CtrDrbgMech<Aes192>>();
    let ctr_no_df_aes_256 = TypeId::of::<mechs::ctr_mech::CtrDrbgMech<Aes256>>();
    let ctr_df_aes_128 = TypeId::of::<mechs::ctr_mech_with_df::CtrDrbgMech_DF<Aes128>>();
    let ctr_df_aes_192 = TypeId::of::<mechs::ctr_mech_with_df::CtrDrbgMech_DF<Aes192>>();
    let ctr_df_aes_256 = TypeId::of::<mechs::ctr_mech_with_df::CtrDrbgMech_DF<Aes256>>();

    let fun_id;
    if this_id == hash_sha_256 || this_id == hmac_sha_256 {
        fun_id = "Sha 256";
    }
    else if this_id == hash_sha_512 || this_id == hmac_sha_512 {
        fun_id = "Sha 512";
    }
    else if this_id == ctr_no_df_aes_128 || this_id == ctr_df_aes_128 {
        fun_id = "AES 128";
    }
    else if this_id == ctr_no_df_aes_192 || this_id == ctr_df_aes_192 {
        fun_id = "AES 192";
    }
    else if this_id == ctr_no_df_aes_256 || this_id == ctr_df_aes_256 {
        fun_id = "AES 256";
    }
    else {
        // Mechanism is not implemented, return error
        return 1;
    }
    
    return instantiation_test::run_tests::<T>(strength) + 
            generate_test::run_tests::<T>(strength) +
            reseed_test::run_tests::<T>(strength) +
            nist_vectors::test_vectors::<T>(fun_id, strength);
}