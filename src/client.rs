use std::{collections::HashMap, task::Poll};

use ed25519_dalek::ed25519::signature::SignerMut;
use sha2::{Digest, Sha256};
use x25519_dalek::EphemeralSecret;

use futures_util::{stream::FusedStream, FutureExt, Sink, SinkExt, Stream, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite::{client::IntoClientRequest, Message}, MaybeTlsStream, WebSocketStream};

use crate::utils::{self, aes_decrypt, aes_encrypt, generate_key, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH};

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
    CannotConnect
}

pub struct ProtoV2dPacket {
    pub qos: u8,
    pub data: Vec<u8>,
}

pub struct Client {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    session: ([u8; PRIVATE_KEY_LENGTH], [u8; PUBLIC_KEY_LENGTH]),

    encryption: Option<([u8; 32], [u8; 32])>,
    handshaked: bool,

    pub track_count: usize,
    pub config: ClientHandshakeConfig,

    qos1_track_in: HashMap<u64, bool>,
    qos1_track_out: HashMap<u64, Vec<u8>>,

    terminated: bool,
    last_ping: u64
}

impl Stream for Client {
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        if !self.handshaked {
            return Poll::Ready(None);
        }

        if self.terminated {
            return Poll::Ready(None);
        }

        if !self.encryption.is_none() {
            return Poll::Ready(None);
        }

        // TODO this should not return None, we may attempt to reconnect here.
        if !self.ws.is_terminated() {
            return Poll::Ready(None);
        }

        match futures_util::ready!(self.ws.next().poll_unpin(cx)) {
            Some(Ok(msg)) => {
                if msg.is_close() {
                    return Poll::Ready(None);
                }

                if msg.is_binary() || msg.is_text() {
                    let d = msg.into_data();

                    match d[0] {
                        0x03 => {
                            // Data packet
                            let k = self.encryption.as_ref().unwrap();

                            let enc_data = &d[1..];
                            let data = aes_decrypt(&k.1, enc_data);
                            if data.is_err() {
                                return Poll::Ready(None);
                            }

                            let data = data.unwrap();
                            let data = aes_decrypt(&k.0, &data);

                            if data.is_err() {
                                return Poll::Ready(None);
                            }

                            let data = data.unwrap();
                            let data = data.as_slice();

                            let qos = data[0];
                            match qos {
                                0x00 => {
                                    let data = &data[1..];
                                    return Poll::Ready(Some(ProtoV2dPacket {
                                        qos,
                                        data: data.to_vec(),
                                    }));
                                }

                                0x01 => {
                                    let dup_id = (u64::from(data[1]) << 24)
                                        | (u64::from(data[2]) << 16)
                                        | (u64::from(data[3]) << 8)
                                        | u64::from(data[4]);

                                    let control = data[5];

                                    match control {
                                        0xFF => {
                                            // ACK
                                            self.qos1_track_out.remove(&dup_id);
                                        }
                                        _ => {
                                            // Data
                                            let t_data = &data[6..];

                                            let mut resp = vec![0x03u8];
                                            let enc_part = vec![
                                                0x01u8, data[1], data[2], data[3], data[4], 0xFF,
                                            ];
                                            let enc_part = aes_encrypt(&k.0, &enc_part);
                                            if enc_part.is_err() {
                                                return Poll::Ready(None);
                                            }
                                            let enc_part = enc_part.unwrap();
                                            let enc_part = aes_encrypt(&k.1, &enc_part);
                                            if enc_part.is_err() {
                                                return Poll::Ready(None);
                                            }
                                            let enc_part = enc_part.unwrap();
                                            resp.extend_from_slice(&enc_part);

                                            let _ = self.ws.send(Message::binary(resp));

                                            if !self.qos1_track_in.contains_key(&dup_id) {
                                                self.qos1_track_in.insert(dup_id, true);
                                                return Poll::Ready(Some(ProtoV2dPacket {
                                                    qos,
                                                    data: t_data.to_vec(),
                                                }));
                                            }

                                            return Poll::Ready(None);
                                        }
                                    }
                                }

                                _ => {
                                    return Poll::Ready(None);
                                }
                            }
                        }
                        0x04 => {
                            // Ping
                            if d[1] != 0x00 {
                                return Poll::Ready(None);
                            }

                            let mut resp = vec![0x04u8, 0x01];
                            resp.extend_from_slice(&d[2..]);
                            let _ = self.ws.send(Message::binary(resp));

                            return Poll::Ready(None);
                        }
                        0x05 => {
                            todo!("implement graceful closing");
                        }
                        _ => {
                            return Poll::Ready(None);
                        }
                    }
                }

                return Poll::Ready(None);
            }
            Some(Err(_)) => {
                return Poll::Ready(None);
            }
            None => {
                return Poll::Ready(None);
            }
        }
    }

    type Item = ProtoV2dPacket;
}

impl Sink<ProtoV2dPacket> for Client {
    type Error = Error;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.ws
            .poll_ready_unpin(cx)
            .map_err(|_| Error::WebsocketError)
    }

    fn start_send(mut self: std::pin::Pin<&mut Self>, item: ProtoV2dPacket) -> Result<(), Self::Error> {
        let k = self.encryption.as_ref().unwrap();

        let mut data = vec![item.qos];
        data.extend_from_slice(&item.data);

        let mut resp = vec![0x03u8];
        let enc_part = aes_encrypt(&k.0, &data);
        if enc_part.is_err() {
            return Err(Error::WebsocketError);
        }

        let enc_part = enc_part.unwrap();
        let enc_part = aes_encrypt(&k.1, &enc_part);
        if enc_part.is_err() {
            return Err(Error::WebsocketError);
        }

        let enc_part = enc_part.unwrap();
        resp.extend_from_slice(&enc_part);

        self.ws.start_send_unpin(Message::binary(resp))
            .map_err(|_| Error::WebsocketError)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.ws
            .poll_flush_unpin(cx)
            .map_err(|_| Error::WebsocketError)
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        let _ = self.ws.send(Message::binary(vec![0x05u8]));

        self.ws
            .poll_close_unpin(cx)
            .map_err(|_| Error::WebsocketError)
    }
}

impl Client {
    pub async fn connect<R>(request: R, config: ClientHandshakeConfig) -> Result<Client, Error> 
    where R: IntoClientRequest + Unpin
    {
        // TODO handle reconnection
        let stream = tokio_tungstenite::connect_async(request).await;
        if stream.is_err() {
            dbg!(stream.unwrap_err());
            return Err(Error::CannotConnect);
        }

        let stream = stream.unwrap();
        let ws = stream.0;

        let mut c = Client {
            ws,
            config,
            encryption: None,
            handshaked: false,
            last_ping: 0,
            qos1_track_in: HashMap::new(),
            qos1_track_out: HashMap::new(),
            session: generate_key(),
            terminated: false,
            track_count: 0
        };

        c.handshake().await?;

        Ok(c)
    }

    async fn handshake(&mut self) -> Result<(), Error> {
        let no_verify = self
            .config
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
        let mut init_handshake =
            rmp_serde::to_vec(&(1, 2, [2], if full_pk_only || no_verify { 0 } else { 1 })).unwrap();

        init_handshake.insert(0, 0x02);

        let init_handshake_send = self.ws.send(Message::binary(init_handshake)).await;
        if init_handshake_send.is_err() {
            return Err(Error::WebsocketError);
        }

        let encryption_pqc;
        let encryption_classic;

        // Wait for response from handshake request
        loop {
            let msg = self.ws.next().await;

            if let Some(Err(_)) = msg {
                let _ = self.ws.close(None).await;
                return Err(Error::WebsocketError);
            }

            if let Some(Ok(msg)) = msg {
                if msg.is_close() {
                    dbg!("closed on first handshake packet");
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

                        let pqcpk = crystals_dilithium::dilithium5::PublicKey::from_bytes(pqcpk);
                        let result_pqc = pqcpk.verify(full_exchange, signature_pq);
                        if result_pqc == false {
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

                    let priv_session_classic = &self.session.0[0..32]
                        .try_into()
                        .map_err(|_| Error::InvalidDataHandshake)?;
                    let mut priv_session_classic =
                        ed25519_dalek::SigningKey::from_bytes(priv_session_classic);
                    let signature_session_classic = priv_session_classic.sign(random_challenge);
                    let signature_session_classic = signature_session_classic.to_bytes();

                    let priv_session_pqc = &self.session.0[64..];
                    let key_session_pqc =
                        crystals_dilithium::dilithium5::SecretKey::from_bytes(priv_session_pqc);

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

                    self.ws
                        .send(Message::binary(response))
                        .await
                        .map_err(|_| Error::WebsocketError)?;
                    break;
                }
            }
        }

        loop {
            let msg = self.ws.next().await;

            if let Some(Err(_)) = msg {
                let _ = self.ws.close(None).await;
                return Err(Error::WebsocketError);
            }

            if let Some(Ok(msg)) = msg {
                if msg.is_close() {
                    dbg!("closed on second handshake packet");
                    return Err(Error::ConnectionClosed);
                }

                if msg.is_binary() || msg.is_text() {
                    let d = msg.into_data();

                    if d[0] != 0x02 {
                        return Err(Error::InvalidDataHandshake);
                    }

                    if d[1] != 0x04 {
                        return Err(Error::InvalidDataHandshake);
                    }

                    self.handshaked = true;

                    let resumed = d[2] == 0x00;
                    if !resumed {
                        self.track_count += 1;
                    }

                    break;
                }
            }
        }

        self.encryption = Some((encryption_pqc, encryption_classic));

        Ok(())
    }
}
