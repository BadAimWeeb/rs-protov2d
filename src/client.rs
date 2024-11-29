use ed25519_dalek::ed25519::signature::SignerMut;
use sha2::{Digest, Sha256};
use x25519_dalek::EphemeralSecret;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};

use crate::utils::{self, aes_encrypt, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH};

#[derive(PartialEq)]
pub enum PublicKeyType {
    Key,
    Hash,
    NoVerify,
}

pub struct PublicKey {
    pub key_type: PublicKeyType,
    pub data: Option<String>,
}

pub struct ClientHandshakeConfig {
    pub ping_interval: Option<std::time::Duration>,
    pub public_keys: Vec<PublicKey>,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidDataHandshake,
    WebsocketError,
    ConnectionClosed,
    InvalidHandshakeVersion,
    ServerKeyVerificationFailed,
    ExchangeError,
}

pub struct BareClient {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    session: ([u8; PRIVATE_KEY_LENGTH], [u8; PUBLIC_KEY_LENGTH]),
    pub config: ClientHandshakeConfig
}

impl BareClient {
    pub async fn handshake(&mut self) -> Result<(), Error> {
        let no_verify = self.config
            .public_keys
            .iter()
            .any(|k| k.key_type == PublicKeyType::NoVerify);

        let full_pk_only = if no_verify {
            false
        } else {
            self.config
                .public_keys
                .iter()
                .all(|k| k.key_type == PublicKeyType::Key)
        };

        // Send the initial handshake
        let init_handshake =
            rmp_serde::to_vec(&(1, 2, [2], if full_pk_only || no_verify { 0 } else { 1 })).unwrap();
        let init_handshake_send = self.ws.send(Message::binary(init_handshake)).await;
        if init_handshake_send.is_err() {
            return Err(Error::WebsocketError);
        }

        let mut encryption_pqc;
        let mut encryption_classic;

        // Wait for response from handshake request
        loop {
            let msg = self.ws.next().await;

            if let Some(Err(_)) = msg {
                let _ = self.ws.close(None).await;
                return Err(Error::WebsocketError);
            }

            if let Some(Ok(msg)) = msg {
                if msg.is_close() {
                    return Err(Error::ConnectionClosed);
                }

                if msg.is_binary() || msg.is_text() {
                    let d = msg.into_data();

                    if d[0] != 0x02 {
                        return Err(Error::InvalidDataHandshake);
                    }

                    // Rust implementation ONLY supports version 2
                    if d[1] != 0x02 {
                        return Err(Error::InvalidHandshakeVersion);
                    }

                    // ...and also does not support disabling encryption
                    if d[2] != 0x01 {
                        return Err(Error::InvalidDataHandshake);
                    }

                    let exchange_classic = &d[3..35];
                    let exchange_pq = &d[35..1603];
                    let random_challenge = &d[6262..6326];

                    if !no_verify {
                        let signature_classic = &d[1603..1667];
                        let signature_pq = &d[1667..6262];

                        let pk = &d[6326..];
                        let s256 = &Sha256::digest(pk);
                        let pkh = if full_pk_only { pk } else { s256 };

                        let k = self.config.public_keys.iter().find_map(|key| {
                            if let None = key.data {
                                return None;
                            };

                            let kdata = <Option<String> as Clone>::clone(&key.data).unwrap();
                            let kd = hex::decode(kdata);
                            if kd.is_err() {
                                return None;
                            }
                            let kd = &kd.unwrap()[..];
                            if key.key_type == PublicKeyType::Key {
                                // compute to hash and compare
                                let s256 = &Sha256::digest(&kd);
                                if utils::compare(&s256, pkh) != std::cmp::Ordering::Equal {
                                    Some(kd.to_vec())
                                } else {
                                    None
                                }
                            } else if key.key_type == PublicKeyType::Hash {
                                // hash vs hash
                                if utils::compare(&kd, pkh) != std::cmp::Ordering::Equal {
                                    Some(pk.to_vec())
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        });

                        if k.is_none() {
                            return Err(Error::ServerKeyVerificationFailed);
                        }

                        let k = k.unwrap();
                        let k = &k[..];
                        let full_exchange = &d[3..1603];
                        let ed25519pk = &k[0..32];
                        let pqcpk = &k[32..];

                        // i don't like this.
                        let ed25519_verify_key = ed25519_dalek::VerifyingKey::from_bytes(
                            ed25519pk
                                .try_into()
                                .map_err(|_| Error::ServerKeyVerificationFailed)?,
                        )
                        .map_err(|_| Error::ServerKeyVerificationFailed);
                        let ed25519_signature = ed25519_dalek::Signature::from_bytes(
                            signature_classic
                                .try_into()
                                .map_err(|_| Error::ServerKeyVerificationFailed)?,
                        );

                        if ed25519_verify_key.is_err() {
                            return Err(Error::ServerKeyVerificationFailed);
                        }

                        let ed25519_verify_key = ed25519_verify_key.unwrap();
                        let result_ed25519 =
                            ed25519_verify_key.verify_strict(full_exchange, &ed25519_signature);
                        if result_ed25519.is_err() {
                            return Err(Error::ServerKeyVerificationFailed);
                        }

                        let result_pqc = pqc_dilithium::verify(signature_pq, full_exchange, pqcpk);
                        if result_pqc.is_err() {
                            return Err(Error::ServerKeyVerificationFailed);
                        }
                    }

                    let mut rng = rand::thread_rng();
                    let pq_data = pqc_kyber::encapsulate(exchange_pq, &mut rng);

                    if pq_data.is_err() {
                        return Err(Error::ExchangeError);
                    }

                    let pq_data = pq_data.unwrap();
                    encryption_pqc = pq_data.1;

                    let classic_secret = EphemeralSecret::random_from_rng(&mut rng);
                    let classic_public = x25519_dalek::PublicKey::from(&classic_secret);
                    let classic_exchange_public = x25519_dalek::PublicKey::from(
                        <[u8; 32]>::try_from(exchange_classic)
                            .map_err(|_| Error::InvalidDataHandshake)?,
                    );
                    encryption_classic = classic_secret
                        .diffie_hellman(&classic_exchange_public)
                        .to_bytes();

                    let priv_session_classic = &self.session.0[0..32].try_into().map_err(|_| Error::InvalidDataHandshake)?;
                    let mut priv_session_classic = ed25519_dalek::SigningKey::from_bytes(priv_session_classic);
                    let signature_session_classic = priv_session_classic.sign(random_challenge);
                    let signature_session_classic = signature_session_classic.to_bytes();
                    
                    let priv_session_pqc = &self.session.0[64..];
                    let pub_session_pqc = &self.session.1[32..];
                    let key_session_pqc = pqc_dilithium::Keypair::new(pub_session_pqc.to_vec(), priv_session_pqc.to_vec());
                    if key_session_pqc.is_err() {
                        return Err(Error::ExchangeError);
                    }
                    let key_session_pqc = key_session_pqc.ok();
                    let key_session_pqc = key_session_pqc.unwrap();
                    let signature_session_pqc = key_session_pqc.sign(random_challenge);

                    let mut response = vec![0x02u8, 0x03];
                    response.extend_from_slice(classic_public.as_bytes());
                    response.extend_from_slice(&pq_data.0);
                    
                    let mut enc_response = vec![];
                    enc_response.extend_from_slice(&self.session.1);
                    enc_response.extend_from_slice(&signature_session_classic);
                    enc_response.extend_from_slice(&signature_session_pqc);

                    let aes_l1 = aes_encrypt(&encryption_pqc, &enc_response);
                    if aes_l1.is_err() {
                        return Err(Error::ExchangeError);
                    }
                    let aes_l1 = aes_l1.unwrap();

                    let aes_l2 = aes_encrypt(&encryption_classic, &aes_l1);
                    if aes_l2.is_err() {
                        return Err(Error::ExchangeError);
                    }
                    let aes_l2 = aes_l2.unwrap();

                    response.extend_from_slice(&aes_l2);

                    self.ws.send(Message::binary(response)).await.map_err(|_| Error::WebsocketError)?;
                    break;
                }
            }
        }

        // TODO: handle final packet and start data exchange

        Ok(())
    }
}
