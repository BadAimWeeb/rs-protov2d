use crate::*;

#[test]
fn test_key_generation() {
    let (priv_key, pub_key) = utils::generate_key();
    let (priv_key_2, pub_key_2) = utils::generate_key();
    assert_eq!(priv_key.len(), utils::PRIVATE_KEY_LENGTH, "checking for private key length");
    assert_eq!(pub_key.len(), utils::PUBLIC_KEY_LENGTH, "checking for public key length");

    assert_eq!(priv_key_2.len(), utils::PRIVATE_KEY_LENGTH, "checking for private key length, 2nd time");
    assert_eq!(pub_key_2.len(), utils::PUBLIC_KEY_LENGTH, "checking for public key length, 2nd time");

    assert_ne!(priv_key, priv_key_2, "both private keys should be different");
    assert_ne!(pub_key, pub_key_2, "both public keys should be different");
}
