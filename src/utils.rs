use core::cmp;
use std::cmp::Ordering;

use aes_gcm::aead::generic_array::typenum::U16;
use aes_gcm::aead::AeadMutInPlace;
use aes_gcm::Nonce;
use aes_gcm::{aead::Aead, aes::Aes256, KeyInit};
use rand::RngCore;
use sha2::{Digest, Sha256};

// https://codereview.stackexchange.com/a/233876
pub fn compare(a: &[u8], b: &[u8]) -> cmp::Ordering {
    for (ai, bi) in a.iter().zip(b.iter()) {
        match ai.cmp(&bi) {
            Ordering::Equal => continue,
            ord => return ord,
        }
    }

    /* if every single element was equal, compare length */
    a.len().cmp(&b.len())
}

pub const PRIVATE_KEY_LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH
    + ed25519_dalek::PUBLIC_KEY_LENGTH
    + pqc_dilithium::SECRETKEYBYTES;
pub const PUBLIC_KEY_LENGTH: usize =
    ed25519_dalek::PUBLIC_KEY_LENGTH + pqc_dilithium::PUBLICKEYBYTES;

pub fn generate_key() -> ([u8; PRIVATE_KEY_LENGTH], [u8; PUBLIC_KEY_LENGTH]) {
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
    priv_key[ed25519_dalek::SECRET_KEY_LENGTH
        ..ed25519_dalek::SECRET_KEY_LENGTH + ed25519_dalek::PUBLIC_KEY_LENGTH]
        .copy_from_slice(classic_public.as_bytes());
    priv_key[ed25519_dalek::SECRET_KEY_LENGTH + ed25519_dalek::PUBLIC_KEY_LENGTH..]
        .copy_from_slice(pq_secret);

    pub_key[..ed25519_dalek::PUBLIC_KEY_LENGTH].copy_from_slice(classic_public.as_bytes());
    pub_key[ed25519_dalek::PUBLIC_KEY_LENGTH..].copy_from_slice(&pq_public);

    (priv_key, pub_key)
}

pub fn aes_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    // JS implementation uses a 16-byte (128-bit) IV:
    let mut cipher = aes_gcm::AesGcm::<Aes256, U16>::new_from_slice(key).map_err(|_| aes_gcm::Error)?;
    let nonce = Nonce::<U16>::from_slice(&iv);

    let mut enc = data.to_vec();
    let tag = cipher.encrypt_in_place_detached(nonce, &[0u8; 0], &mut enc)?;
    // tag is specified as 128-bit length, truncate
    let tag = &tag[..16];
    enc.extend_from_slice(tag);

    let mut hasher = Sha256::new();
    hasher.update(data);
    let sha = hasher.finalize();

    let mut result = vec![];
    result.extend_from_slice(&iv);
    result.extend_from_slice(&sha);
    result.extend(enc);

    Ok(result)
}

pub fn aes_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let iv = &data[..16];
    let sha = &data[16..48];
    let enc = &data[48..];

    let mut cipher = aes_gcm::AesGcm::<Aes256, U16>::new_from_slice(key).unwrap();
    let nonce = Nonce::<U16>::from_slice(iv);

    let tag = &enc[..16];
    let dec = &enc[16..];
    let mut dec = dec.to_vec();

    cipher.decrypt_in_place_detached(nonce, &[0u8; 0], &mut dec, tag.into()).unwrap();
    
    let mut hasher = Sha256::new();
    hasher.update(&dec);
    let sha2 = hasher.finalize();

    if compare(&sha, &sha2) != Ordering::Equal {
        return Err("SHA256 mismatch");
    }

    Ok(dec)
}
