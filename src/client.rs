use std::{collections::HashMap, task::Poll, time::Duration};

use ed25519_dalek::ed25519::signature::SignerMut;
use rand::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use x25519_dalek::EphemeralSecret;

use futures_util::{stream::FusedStream, FutureExt, Sink, SinkExt, Stream, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    tungstenite::{client::IntoClientRequest, Message},
    MaybeTlsStream, WebSocketStream,
};

use crate::utils::{
    self, aes_decrypt, aes_encrypt, compare, generate_key, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH,
};

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
    CannotConnect,
    ReconnectionNotPossible,
}

pub struct ProtoV2dPacket {
    pub qos: u8,
    pub qos1_id: Option<u64>,
    pub data: Vec<u8>,
}

pub struct Client<R>
where
    R: IntoClientRequest + Unpin + Copy,
{
    dial_target_reconnect: Option<R>,
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    session: ([u8; PRIVATE_KEY_LENGTH], [u8; PUBLIC_KEY_LENGTH]),

    encryption: Option<([u8; 32], [u8; 32])>,
    handshaked: bool,

    pub track_count: usize,
    pub config: ClientHandshakeConfig,

    qos1_id: u64,
    qos1_track_in: HashMap<u64, bool>,
    qos1_track_out: HashMap<u64, Vec<u8>>,
    qos1_callback: HashMap<u64, tokio::sync::oneshot::Sender<()>>,

    last_ping: u64,
    last_ping_data: Option<[u8; 16]>,
}

impl<R> Stream for Client<R>
where
    R: IntoClientRequest + Unpin + Copy,
{
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        loop {
            if self.ws.is_terminated() {
                self.handshaked = false;
                self.encryption = None;
                return Poll::Ready(None);
            }

            if !self.handshaked {
                return Poll::Ready(None);
            }

            if self.encryption.is_none() {
                return Poll::Ready(None);
            }

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if self.last_ping_data.is_some() {
                if now - self.last_ping > 15 {
                    return Poll::Ready(None);
                }
            } else {
                if now - self.last_ping
                    > self
                        .config
                        .ping_interval
                        .unwrap_or_else(|| Duration::from_secs(15))
                        .as_secs()
                {
                    let mut data = [0u8; 16];
                    rand::rngs::StdRng::from_entropy().fill_bytes(&mut data);
                    self.last_ping_data = Some(data);

                    let mut resp = vec![0x04u8, 0x00];
                    resp.extend_from_slice(&data);
                    let _ = self.ws.send(Message::binary(resp)).poll_unpin(cx); // we don't care about the result

                    self.last_ping = now;
                }
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
                                    continue;
                                }

                                let data = data.unwrap();
                                let data = aes_decrypt(&k.0, &data);

                                if data.is_err() {
                                    continue;
                                }

                                let data = data.unwrap();
                                let data = data.as_slice();

                                let qos = data[0];
                                match qos {
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

                                                if self.qos1_callback.contains_key(&dup_id) {
                                                    let _ = self
                                                        .qos1_callback
                                                        .remove(&dup_id)
                                                        .unwrap()
                                                        .send(());
                                                }
                                            }
                                            _ => {
                                                // Data
                                                let t_data = &data[6..];

                                                let mut resp = vec![0x03u8];
                                                let enc_part = vec![
                                                    0x01u8, data[1], data[2], data[3], data[4],
                                                    0xFF,
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

                                                let _ = self
                                                    .ws
                                                    .send(Message::binary(resp))
                                                    .poll_unpin(cx);

                                                if !self.qos1_track_in.contains_key(&dup_id) {
                                                    self.qos1_track_in.insert(dup_id, true);
                                                    return Poll::Ready(Some(ProtoV2dPacket {
                                                        qos,
                                                        qos1_id: Some(dup_id),
                                                        data: t_data.to_vec(),
                                                    }));
                                                }
                                            }
                                        }
                                    }

                                    _ => {
                                        let data = &data[1..];
                                        return Poll::Ready(Some(ProtoV2dPacket {
                                            qos,
                                            qos1_id: None,

                                            data: data.to_vec(),
                                        }));
                                    }
                                }
                            }
                            0x04 => {
                                // Ping
                                match d[1] {
                                    0x00 => {
                                        let mut resp = vec![0x04u8, 0x01];
                                        resp.extend_from_slice(&d[2..]);
                                        match self.ws.send(Message::binary(resp)).poll_unpin(cx) {
                                            Poll::Ready(_) => {}
                                            Poll::Pending => {
                                                return Poll::Pending;
                                            }
                                        }
                                    }

                                    0x01 => {
                                        if self.last_ping_data.is_some() {
                                            let data = &d[2..];
                                            if data.len() != 16 {
                                                return Poll::Ready(None);
                                            }

                                            if compare(data, self.last_ping_data.as_ref().unwrap())
                                                != std::cmp::Ordering::Equal
                                            {
                                                return Poll::Ready(None);
                                            }

                                            self.last_ping_data = None;
                                        }
                                    }

                                    _ => {
                                        return Poll::Ready(None);
                                    }
                                }
                            }
                            0x05 => {
                                todo!("implement graceful closing");
                            }
                            _ => {}
                        }
                    }
                }
                Some(Err(_)) => {
                    return Poll::Ready(None);
                }
                None => {
                    return Poll::Ready(None);
                }
            }
        }
    }

    type Item = ProtoV2dPacket;
}

impl<R> Sink<ProtoV2dPacket> for Client<R>
where
    R: IntoClientRequest + Unpin + Copy,
{
    type Error = Error;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.ws
            .poll_ready_unpin(cx)
            .map_err(|_| Error::WebsocketError)
    }

    fn start_send(
        mut self: std::pin::Pin<&mut Self>,
        item: ProtoV2dPacket,
    ) -> Result<(), Self::Error> {
        let k = self.encryption.as_ref().unwrap();

        let mut data = vec![item.qos];
        if item.qos == 1 {
            let qos = [
                ((item.qos1_id.unwrap() >> 24) & 0xFF) as u8,
                ((item.qos1_id.unwrap() >> 16) & 0xFF) as u8,
                ((item.qos1_id.unwrap() >> 8) & 0xFF) as u8,
                (item.qos1_id.unwrap() & 0xFF) as u8,
            ];
            data.extend_from_slice(&qos);
            data.extend([0x00u8]);
        }
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

        self.ws
            .start_send_unpin(Message::binary(resp))
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

impl<R> Client<R>
where
    R: IntoClientRequest + Unpin + Copy,
{
    async fn connect_ws(
        request: R,
    ) -> Result<WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Error>
    {
        let stream = tokio_tungstenite::connect_async(request).await;
        if stream.is_err() {
            return Err(Error::CannotConnect);
        }

        let stream = stream.unwrap();
        Ok(stream.0)
    }

    pub fn is_terminated(&self) -> bool {
        self.ws.is_terminated()
    }

    pub async fn terminate(&mut self) {
        let _ = self.ws.close(None).await;
    }

    pub async fn try_reconnect(&mut self) -> Result<bool, Error> {
        if !self.ws.is_terminated() {
            return Ok(false);
        }

        if self.dial_target_reconnect.is_none() {
            return Err(Error::ReconnectionNotPossible);
        }

        let ws = Client::connect_ws(self.dial_target_reconnect.unwrap()).await?;
        self.ws = ws;

        let old_cid = self.track_count;
        self.last_ping = 0;
        self.last_ping_data = None;
        self.handshake().await?;
        let new_cid = self.track_count;

        if old_cid != new_cid {
            // welp, server might have dropped our connection, or the server is a different one.
            self.qos1_id = 0;
            self.qos1_track_in.clear();
            self.qos1_track_out.clear();

            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn connect(request: R, config: ClientHandshakeConfig) -> Result<Client<R>, Error>
    where
        R: IntoClientRequest + Unpin + Copy,
    {
        let ws = Client::connect_ws(request).await?;

        let mut c = Client {
            dial_target_reconnect: Some(request),
            ws,
            config,
            encryption: None,
            handshaked: false,
            last_ping: 0,
            last_ping_data: None,
            qos1_id: 0,
            qos1_track_in: HashMap::new(),
            qos1_track_out: HashMap::new(),
            qos1_callback: HashMap::new(),
            session: generate_key(),
            track_count: 0,
        };

        c.handshake().await?;

        Ok(c)
    }

    /// Send packet without awaiting ACK. Flushing still needs to be done.
    pub async fn send_packet(&mut self, qos: u8, data: Vec<u8>) {
        match qos {
            0x01 => {
                // QoS1 packet
                let send_id = self.qos1_id << 1;
                self.qos1_id += 1;

                let packet = ProtoV2dPacket {
                    qos,
                    qos1_id: Some(send_id),
                    data,
                };

                let mut pinned = std::pin::pin!(self);
                let _ = pinned.as_mut().send(packet).await;
            }
            _ => {
                // QoS0 or custom implementation
                let packet = ProtoV2dPacket {
                    qos,
                    qos1_id: None,
                    data,
                };

                let mut pinned = std::pin::pin!(self);
                let _ = pinned.as_mut().send(packet).await;
            }
        }
    }

    /// Send QoS1 packet, awaiting ACK from server.
    pub async fn send_packet_qos1_with_ack(&mut self, data: Vec<u8>) {
        let send_id = self.qos1_id << 1;
        self.qos1_id += 1;

        let packet = ProtoV2dPacket {
            qos: 0x01,
            qos1_id: Some(send_id),
            data,
        };

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.qos1_callback.insert(send_id, tx);

        let mut pinned = std::pin::pin!(self);
        let _ = pinned.as_mut().send(packet).await;

        rx.await.unwrap();
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
                                let s256 = &Sha256::digest(&kd)[..];
                                if utils::compare(&s256, pkh) == std::cmp::Ordering::Equal {
                                    Some(kd.to_vec())
                                } else {
                                    None
                                }
                            } else if key.key_type == PublicKeyType::Hash {
                                // hash vs hash
                                if utils::compare(&kd, pkh) == std::cmp::Ordering::Equal {
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

                    let mut rng = rand::rngs::StdRng::from_entropy();
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
