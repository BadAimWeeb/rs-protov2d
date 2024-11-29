use core::cmp;
use std::cmp::Ordering;

use rand::RngCore;

// https://codereview.stackexchange.com/a/233876
pub fn compare(a: &[u8], b: &[u8]) -> cmp::Ordering {
    for (ai, bi) in a.iter().zip(b.iter()) {
        match ai.cmp(&bi) {
            Ordering::Equal => continue,
            ord => return ord
        }
    }

    /* if every single element was equal, compare length */
    a.len().cmp(&b.len())
}

pub const PRIVATE_KEY_LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH + ed25519_dalek::PUBLIC_KEY_LENGTH + pqc_dilithium::SECRETKEYBYTES;
pub const PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH + pqc_dilithium::PUBLICKEYBYTES;
pub fn generate_key() -> (
    [u8; PRIVATE_KEY_LENGTH], 
    [u8; PUBLIC_KEY_LENGTH]
) {
    let pq = pqc_dilithium::Keypair::generate();
    
    let mut classic_seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut classic_seed);
    let classic_sign = ed25519_dalek::SigningKey::from_bytes(&classic_seed);
    let classic_public = classic_sign.verifying_key();

    let pq_secret = pq.expose_secret();
    let pq_public = pq.public;

    let mut priv_key = [0u8; PRIVATE_KEY_LENGTH];
    let mut pub_key = [0u8; PUBLIC_KEY_LENGTH];

    priv_key[..ed25519_dalek::SECRET_KEY_LENGTH].copy_from_slice(&classic_seed);
    priv_key[ed25519_dalek::SECRET_KEY_LENGTH..ed25519_dalek::SECRET_KEY_LENGTH + ed25519_dalek::PUBLIC_KEY_LENGTH].copy_from_slice(classic_public.as_bytes());
    priv_key[ed25519_dalek::SECRET_KEY_LENGTH + ed25519_dalek::PUBLIC_KEY_LENGTH..].copy_from_slice(pq_secret);

    pub_key[..ed25519_dalek::PUBLIC_KEY_LENGTH].copy_from_slice(classic_public.as_bytes());
    pub_key[ed25519_dalek::PUBLIC_KEY_LENGTH..].copy_from_slice(&pq_public);

    (priv_key, pub_key)
}
