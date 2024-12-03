use std::cmp::Ordering;

use client::{Client, ClientHandshakeConfig, PublicKey, PublicKeyType};
use utils::compare;

use crate::*;

#[test]
fn test_key_generation() {
    let (priv_key, pub_key) = utils::generate_key();
    let (priv_key_2, pub_key_2) = utils::generate_key();
    assert_eq!(priv_key.len(), utils::PRIVATE_KEY_LENGTH, "checking for private key length");
    assert_eq!(pub_key.len(), utils::PUBLIC_KEY_LENGTH, "checking for public key length");

    assert_eq!(priv_key_2.len(), utils::PRIVATE_KEY_LENGTH, "checking for private key length, 2nd time");
    assert_eq!(pub_key_2.len(), utils::PUBLIC_KEY_LENGTH, "checking for public key length, 2nd time");

    assert!(compare(&priv_key, &priv_key_2) != Ordering::Equal, "both private keys should be different");
    assert!(compare(&pub_key, &pub_key_2) != Ordering::Equal, "both public keys should be different");
}


#[tokio::test]
async fn connect() {
    rustls::crypto::aws_lc_rs::default_provider().install_default().expect("Failed to install rustls crypto provider");

    let result = Client::connect("wss://id-backend.badaimweeb.me/", ClientHandshakeConfig {
        public_keys: vec![PublicKey {
            key_type: PublicKeyType::NoVerify,
            data: None
        }],
        ping_interval: None
    }).await;

    if result.is_err() {
        println!("{:?}", result.err().unwrap());
        panic!("connection should be successful");
    }
}
