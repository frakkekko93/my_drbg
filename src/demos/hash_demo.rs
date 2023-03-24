use crate::drbgs::gen_drbg::DRBG;
use crate::mechs::hash_mech::HashDrbgMech;
use sha2::Sha256;

pub fn hash_drbg_demo(_drbg: &mut DRBG<HashDrbgMech<Sha256>>) -> usize {
    0
}