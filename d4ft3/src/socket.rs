use crate::error::{D4FTError, D4FTResult};
use crate::{json, Connection, TransferMode};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::XChaCha20;
use chacha20poly1305::aead::{AeadInPlace, NewAead};
use chacha20poly1305::XChaCha20Poly1305;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use scrypt::scrypt;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::cell::RefCell;
use std::{io, thread};
use std::io::{ErrorKind, Read, Write};
use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{Sender, SyncSender};
use std::time::Duration;
use cancellable_io::{TcpListener, TcpStream, Canceller, is_cancelled};

fn read_plaintext_message(socket: &mut TcpStream) -> D4FTResult<Vec<u8>> {
    let mut buffer = [0_u8; 8];
    socket
        .read_exact(&mut buffer)
        .map_err(|source| D4FTError::CommunicationFailure { source })?;
    if &buffer[0..4] != b"D4FT" {
        return Err(D4FTError::PacketStructureError {
            msg: "invalid header".to_string(),
        });
    }
    // Should be safe to unwrap as we know the source (4 bytes of an array)
    let mut message = vec![0_u8; u32::from_be_bytes(buffer[4..8].try_into().unwrap()) as usize];
    socket
        .read_exact(&mut message)
        .map_err(|source| D4FTError::CommunicationFailure { source })?;
    Ok(message)
}

fn build_message<T: Serialize>(msg: &T) -> Result<Vec<u8>, serde_json::Error> {
    let message = serde_json::to_vec(msg)?;
    Ok([
        b"D4FT",
        &(message.len() as u32).to_be_bytes(),
        message.as_slice(),
    ]
    .concat())
}

fn derive_key(password: String, salt: [u8; 32]) -> [u8; 32] {
    let mut key = [0_u8; 32];
    scrypt(
        password.as_bytes(),
        &salt,
        &scrypt::Params::new(16, 8, 1).expect("Should not error on hardcoded params"),
        &mut key,
    )
    .expect("Should not error on hardcoded output length");
    key
}

fn gen_iv<const NONCE_SIZE: usize>() -> (String, String, [u8; NONCE_SIZE], [u8; 32]) {
    let mut rng = ChaCha20Rng::from_entropy();

    let mut raw_nonce = [0_u8; NONCE_SIZE];
    rng.fill_bytes(&mut raw_nonce);
    let nonce = hex::encode_upper(raw_nonce);

    let mut raw_salt = [0_u8; 32];
    rng.fill_bytes(&mut raw_salt);
    let salt = hex::encode_upper(raw_salt);

    (nonce, salt, raw_nonce, raw_salt)
}

fn check_decode_iv<const SIZE: usize>(iv: String, name: &str) -> D4FTResult<[u8; SIZE]> {
    hex::decode(iv)
        .map_err(|_| D4FTError::PacketStructureError {
            msg: format!("invalid data for {}", name),
        })?
        .try_into()
        .map_err(|_| D4FTError::PacketStructureError {
            msg: format!("invalid data for {}", name),
        })
}

fn start_connect<T: ToSocketAddrs>(
    address: T,
    setup: &json::EncryptionSetup,
) -> D4FTResult<TcpStream> {
    // TODO: Resolve DNS
    // Connect socket
    // let address = address.to_socket_addrs()
    //     .map_err(|source| D4FTError::ConnectionFailure { source })?
    //     .skip(2).next().ok_or(D4FTError::ResolutionError {
    //     msg: "could not resolve hostname".to_string(),
    // })?;
    // println!("{:?}", address);
    let (mut socket, _) =
        TcpStream::connect(address).map_err(|source| D4FTError::ConnectionFailure { source })?;

    // thread::sleep(Duration::from_millis(1000));

    // Send encryption setup
    // TODO: testing this, put err?' back on the same line
    let err = socket
        .write_all(&build_message(setup).expect("This should be successful"))
        .map_err(|source| D4FTError::CommunicationFailure { source });

    err?;

    // Receive encryption setup response
    let response = serde_json::from_slice::<json::EncryptionSetupResponse>(
        &read_plaintext_message(&mut socket)?,
    )
    .map_err(|source| D4FTError::JsonError { source })?;

    // Close if disagreement
    if !response.confirm {
        return Err(D4FTError::Disagreement {
            msg: "The listener refused the connection (likely security types did not match)"
                .to_string(),
        });
    }

    Ok(socket)
}

fn start_listen<T: ToSocketAddrs, Iv, F: FnOnce(json::EncryptionSetup) -> Option<Iv>>(
    address: T,
    iv_extraction_fn: F,
    canceller_sender: Option<Sender<Canceller>>,
) -> D4FTResult<(TcpStream, Iv)> {
    // TODO: Resolve DNS
    // Bind socket
    // let (mut socket, _) = TcpListener::bind(address)
    //     .and_then(|l| l.accept())
    //     .map_err(|source| D4FTError::ConnectionFailure { source })?;

    let (mut socket, _, _) = TcpListener::bind(address)
        .map(|(l, c)| {
            if let Some(cs) = canceller_sender {
                cs.send(c).ok(); // If the receiver has hung up that's its problem
            }
            l
        })
        .and_then(|l| l.accept())
        .map_err(|source| if is_cancelled(&source) {
            D4FTError::Cancelled { msg: "listen".to_string() }
        } else {
            D4FTError::ConnectionFailure { source }
        })?;

    // Receive encryption setup
    let message =
        serde_json::from_slice::<json::EncryptionSetup>(&read_plaintext_message(&mut socket)?)
            .map_err(|source| D4FTError::JsonError { source })?;

    // Extract initialization vectors if agreement, respond and close otherwise
    let iv = match iv_extraction_fn(message) {
        Some(iv) => {
            // Respond with agreement if security types match
            let response = build_message(&json::EncryptionSetupResponse { confirm: true })
                .expect("This should be completely static");
            socket
                .write_all(&response)
                .map_err(|source| D4FTError::CommunicationFailure { source })?;

            iv
        }
        None => {
            // Respond and close if disagreement
            let response = build_message(&json::EncryptionSetupResponse { confirm: false })
                .expect("This should be completely static");
            socket
                .write_all(&response)
                .map_err(|source| D4FTError::CommunicationFailure { source })?;

            return Err(D4FTError::Disagreement {
                msg: "Security types did not match.".to_string(),
            });
        }
    };

    Ok((socket, iv))
}

pub struct UnencryptedSocket {
    is_client: bool,
    socket: RefCell<TcpStream>,
    mode: TransferMode,
}

impl UnencryptedSocket {
    /// Connect to a listening peer.
    pub fn connect<T: ToSocketAddrs>(address: T, mode: TransferMode) -> D4FTResult<Self> {
        // Connect socket
        let mut socket = start_connect(address, &json::EncryptionSetup::Unencrypted)?;

        // Send transfer setup
        let message = build_message(&json::TransferSetup::from(&mode))
            .expect("This should be completely static");
        socket
            .write_all(&message)
            .map_err(|source| D4FTError::CommunicationFailure { source })?;

        // Receive transfer setup response
        let response = serde_json::from_slice::<json::TransferSetupResponse>(
            &read_plaintext_message(&mut socket)?,
        )
        .map_err(|source| D4FTError::JsonError { source })?;

        // Close if disagreement
        if !response.verify(&mode) {
            return Err(D4FTError::Disagreement {
                msg: "The listener disagreed on transfer mode".to_string(),
            });
        }

        Ok(Self {
            is_client: true,
            socket: RefCell::new(socket),
            mode,
        })
    }

    /// Open a port and listen for a connection from a peer.
    pub fn listen<T: ToSocketAddrs>(
        address: T,
        mode: TransferMode,
        canceller_sender: Option<Sender<Canceller>>,
    ) -> D4FTResult<Self> {
        // Bind socket
        let (mut socket, _) = start_listen(address, |setup| match setup {
            json::EncryptionSetup::Unencrypted => Some(()),
            _ => None,
        }, canceller_sender)?;

        // Receive transfer setup
        let message =
            serde_json::from_slice::<json::TransferSetup>(&read_plaintext_message(&mut socket)?)
                .map_err(|source| D4FTError::JsonError { source })?;

        // If disagreement, close the connection
        if !message.verify(&mode) {
            let response = build_message(&json::TransferSetupResponse::failure())
                .expect("This should be completely static");
            socket
                .write_all(&response)
                .map_err(|source| D4FTError::CommunicationFailure { source })?;

            return Err(D4FTError::Disagreement {
                msg: "The client disagreed on transfer mode".to_string(),
            });
        }

        // Respond with agreement if transfer modes match
        let response = build_message(&json::TransferSetupResponse::from(&mode))
            .expect("This should be completely static");
        socket
            .write_all(&response)
            .map_err(|source| D4FTError::CommunicationFailure { source })?;

        Ok(Self {
            is_client: false,
            socket: RefCell::new(socket),
            mode,
        })
    }
}

impl Connection for UnencryptedSocket {
    fn transfer_mode(&self) -> TransferMode {
        self.mode.clone()
    }

    fn send_message<T: Serialize>(&self, msg: &T) -> D4FTResult<()> {
        self.socket
            .borrow_mut()
            .write_all(&build_message(msg).map_err(|source| D4FTError::JsonError { source })?)
            .map_err(|source| D4FTError::CommunicationFailure { source })
    }

    fn receive_message<T: DeserializeOwned>(&self) -> D4FTResult<T> {
        serde_json::from_slice(&read_plaintext_message(&mut self.socket.borrow_mut())?)
            .map_err(|source| D4FTError::JsonError { source })
    }
}

pub struct ChaChaSocket {
    is_client: bool,
    socket: RefCell<TcpStream>,
    mode: TransferMode,
    enc_cipher: RefCell<XChaCha20>,
    dec_cipher: RefCell<XChaCha20>,
}

impl ChaChaSocket {
    fn from_iv(
        is_client: bool,
        socket: TcpStream,
        mode: TransferMode,
        password: String,
        nonce: [u8; 48],
        salt: [u8; 32],
    ) -> Self {
        // Derive key
        let key = derive_key(password, salt);

        // Split nonce
        let mut nonce_halves = [[0_u8; 24]; 2];
        nonce_halves[0].copy_from_slice(&nonce[..24]);
        nonce_halves[1].copy_from_slice(&nonce[24..]);

        Self {
            is_client,
            socket: RefCell::new(socket),
            mode,
            enc_cipher: RefCell::new(XChaCha20::new(
                chacha20::Key::from_slice(&key),
                chacha20::XNonce::from_slice(&if is_client {
                    nonce_halves[0]
                } else {
                    nonce_halves[1]
                }),
            )),
            dec_cipher: RefCell::new(XChaCha20::new(
                chacha20::Key::from_slice(&key),
                chacha20::XNonce::from_slice(&if is_client {
                    nonce_halves[1]
                } else {
                    nonce_halves[0]
                }),
            )),
        }
    }

    /// Connect to a listening peer.
    pub fn connect<T: ToSocketAddrs>(
        address: T,
        mode: TransferMode,
        password: String,
    ) -> D4FTResult<Self> {
        // Generate initialization vectors
        let (nonce, salt, raw_nonce, raw_salt) = gen_iv();

        // Connect socket
        let socket = start_connect(
            address,
            &json::EncryptionSetup::XChaCha20Psk { nonce, salt },
        )?;

        // Set up ciphers
        let socket = Self::from_iv(true, socket, mode, password, raw_nonce, raw_salt);

        // Send transfer setup
        socket.send_message(&json::TransferSetup::from(&socket.mode))?;

        // Receive transfer setup response
        let response = socket.receive_message::<json::TransferSetupResponse>();

        // Emit proper error message for failed encryption
        if let Err(D4FTError::CipherError { .. }) = &response {
            return Err(D4FTError::EncryptionFailure {
                msg: "could not understand the listener".to_string(),
            });
        }
        let response = response?;

        // Close if disagreement
        if !response.verify(&socket.mode) {
            return Err(D4FTError::Disagreement {
                msg: "The listener disagreed on transfer mode".to_string(),
            });
        }

        Ok(socket)
    }

    /// Open a port and listen for a connection from a peer.
    pub fn listen<T: ToSocketAddrs>(
        address: T,
        mode: TransferMode,
        password: String,
        canceller_sender: Option<Sender<Canceller>>,
    ) -> D4FTResult<Self> {
        // Bind socket
        let (socket, (nonce, salt)) = start_listen(address, |setup| {
            if let json::EncryptionSetup::XChaCha20Psk { nonce, salt } = setup {
                Some((nonce, salt))
            } else {
                None
            }
        }, canceller_sender)?;

        // Set up ciphers
        let socket = Self::from_iv(
            false,
            socket,
            mode,
            password,
            check_decode_iv(nonce, "nonce")?,
            check_decode_iv(salt, "salt")?,
        );

        // Receive transfer setup
        let message = socket.receive_message::<json::TransferSetup>();

        // If encryption failed, send FAILED and close the connection
        if let Err(D4FTError::CipherError { .. }) = &message {
            socket
                .socket
                .borrow_mut()
                .write_all(b"D4FT\x00\x00\x00\x0EFAILED")
                .map_err(|source| D4FTError::CommunicationFailure { source })?;
            return Err(D4FTError::EncryptionFailure {
                msg: "could not understand the client".to_string(),
            });
        }
        let message = message?;

        // If disagreement, close the connection
        if !message.verify(&socket.mode) {
            socket.send_message(&json::TransferSetupResponse::failure())?;
            return Err(D4FTError::Disagreement {
                msg: "The client disagreed on transfer mode".to_string(),
            });
        }

        socket.send_message(&json::TransferSetupResponse::from(&socket.mode))?;

        Ok(socket)
    }
}

impl Connection for ChaChaSocket {
    fn transfer_mode(&self) -> TransferMode {
        self.mode.clone()
    }

    fn send_message<T: Serialize>(&self, msg: &T) -> D4FTResult<()> {
        let mut message = build_message(msg).map_err(|source| D4FTError::JsonError { source })?;
        self.enc_cipher
            .borrow_mut()
            .try_apply_keystream(&mut message)
            .map_err(|source| D4FTError::CipherError { source })?;
        self.socket
            .borrow_mut()
            .write_all(&message)
            .map_err(|source| D4FTError::CommunicationFailure { source })
    }

    fn receive_message<T: DeserializeOwned>(&self) -> D4FTResult<T> {
        let mut message = [0_u8; 8];
        self.socket
            .borrow_mut()
            .read_exact(&mut message)
            .map_err(|source| D4FTError::CommunicationFailure { source })?;
        self.dec_cipher
            .borrow_mut()
            .try_apply_keystream(&mut message)
            .map_err(|source| D4FTError::CipherError { source })?;
        if &message[0..4] != b"D4FT" {
            return Err(D4FTError::EncryptionFailure {
                msg: "could not understand the peer".to_string(),
            });
        }
        let mut message =
            vec![0_u8; u32::from_be_bytes(message[4..8].try_into().unwrap()) as usize];
        self.socket
            .borrow_mut()
            .read_exact(&mut message)
            .map_err(|source| D4FTError::CommunicationFailure { source })?;
        self.dec_cipher
            .borrow_mut()
            .try_apply_keystream(&mut message)
            .map_err(|source| D4FTError::CipherError { source })?;
        serde_json::from_slice(&message).map_err(|source| D4FTError::JsonError { source })
    }
}

pub struct ChaChaPoly1305Socket {
    is_client: bool,
    socket: RefCell<TcpStream>,
    mode: TransferMode,
    enc_nonce_base: [u8; 20],
    dec_nonce_base: [u8; 20],
    enc_nonce_counter: RefCell<u32>,
    dec_nonce_counter: RefCell<u32>,
    cipher: XChaCha20Poly1305,
}

impl ChaChaPoly1305Socket {
    fn from_iv(
        is_client: bool,
        socket: TcpStream,
        mode: TransferMode,
        password: String,
        nonce: [u8; 40],
        salt: [u8; 32],
    ) -> Self {
        let mut nonce_halves = [[0_u8; 20]; 2];
        nonce_halves[0].copy_from_slice(&nonce[..20]);
        nonce_halves[1].copy_from_slice(&nonce[20..]);

        Self {
            is_client,
            socket: RefCell::new(socket),
            mode,
            enc_nonce_base: if is_client {
                nonce_halves[0]
            } else {
                nonce_halves[1]
            },
            dec_nonce_base: if is_client {
                nonce_halves[1]
            } else {
                nonce_halves[0]
            },
            enc_nonce_counter: RefCell::new(0),
            dec_nonce_counter: RefCell::new(0),
            cipher: XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&derive_key(
                password, salt,
            ))),
        }
    }

    fn next_enc_nonce(&self) -> [u8; 24] {
        let mut nonce = [0_u8; 24];
        nonce[..4].copy_from_slice(&self.enc_nonce_counter.borrow().to_be_bytes());
        nonce[4..].copy_from_slice(&self.enc_nonce_base);
        *self.enc_nonce_counter.borrow_mut() += 1;
        nonce
    }

    fn next_dec_nonce(&self) -> [u8; 24] {
        let mut nonce = [0_u8; 24];
        nonce[..4].copy_from_slice(&self.dec_nonce_counter.borrow().to_be_bytes());
        nonce[4..].copy_from_slice(&self.dec_nonce_base);
        *self.dec_nonce_counter.borrow_mut() += 1;
        nonce
    }

    /// Connect to a listening peer.
    pub fn connect<T: ToSocketAddrs>(
        address: T,
        mode: TransferMode,
        password: String,
    ) -> D4FTResult<Self> {
        // Generate initialization vectors
        let (nonce, salt, raw_nonce, raw_salt) = gen_iv();

        // Connect socket
        let socket = start_connect(
            address,
            &json::EncryptionSetup::XChaCha20Poly1305Psk { nonce, salt },
        )?;

        // Set up ciphers
        let socket = Self::from_iv(true, socket, mode, password, raw_nonce, raw_salt);

        // Send transfer setup
        socket.send_message(&json::TransferSetup::from(&socket.mode))?;

        // Receive transfer setup response
        let response = socket.receive_message::<json::TransferSetupResponse>();

        // Emit proper error message for failed encryption
        if let Err(D4FTError::AeadError { .. }) = &response {
            return Err(D4FTError::EncryptionFailure {
                msg: "could not understand the listener".to_string(),
            });
        }
        let response = response?;

        // Close if disagreement
        if !response.verify(&socket.mode) {
            return Err(D4FTError::Disagreement {
                msg: "The listener disagreed on transfer mode".to_string(),
            });
        }

        Ok(socket)
    }

    pub fn listen<T: ToSocketAddrs>(
        address: T,
        mode: TransferMode,
        password: String,
        canceller_sender: Option<Sender<Canceller>>,
    ) -> D4FTResult<Self> {
        // Bind socket
        let (socket, (nonce, salt)) = start_listen(address, |setup| {
            if let json::EncryptionSetup::XChaCha20Poly1305Psk { nonce, salt } = setup {
                Some((nonce, salt))
            } else {
                None
            }
        }, canceller_sender)?;

        // Set up ciphers
        let socket = Self::from_iv(
            false,
            socket,
            mode,
            password,
            check_decode_iv(nonce, "nonce")?,
            check_decode_iv(salt, "salt")?,
        );

        // Receive transfer setup
        let message = socket.receive_message::<json::TransferSetup>();

        // If encryption failed, send FAILED and close the connection
        if let Err(D4FTError::AeadError { .. }) = &message {
            socket
                .socket
                .borrow_mut()
                .write_all(b"D4FT\x00\x00\x00\x0E                FAILED                ")
                .map_err(|source| D4FTError::CommunicationFailure { source })?;
            return Err(D4FTError::EncryptionFailure {
                msg: "could not understand the client".to_string(),
            });
        }
        let message = message?;

        // If disagreement, close the connection
        if !message.verify(&socket.mode) {
            socket.send_message(&json::TransferSetupResponse::failure())?;
            return Err(D4FTError::Disagreement {
                msg: "The client disagreed on transfer mode".to_string(),
            });
        }

        socket.send_message(&json::TransferSetupResponse::from(&socket.mode))?;

        Ok(socket)
    }
}

impl Connection for ChaChaPoly1305Socket {
    fn transfer_mode(&self) -> TransferMode {
        self.mode.clone()
    }

    fn send_message<T: Serialize>(&self, msg: &T) -> D4FTResult<()> {
        // Build plaintext message
        let payload = serde_json::to_vec(msg).map_err(|source| D4FTError::JsonError { source })?;
        let mut message = vec![0_u8; payload.len() + 40];
        message[..4].copy_from_slice(b"D4FT");
        message[4..8].copy_from_slice(&(payload.len() as u32 + 8).to_be_bytes());
        message[24..payload.len() + 24].copy_from_slice(&payload);

        // Encrypt header and insert tag
        let tag = self
            .cipher
            .encrypt_in_place_detached(
                chacha20poly1305::XNonce::from_slice(&self.next_enc_nonce()),
                &[0_u8; 0],
                &mut message[..8],
            )
            .map_err(|source| D4FTError::AeadError { source })?;
        message[8..24].copy_from_slice(&tag);

        // Encrypt payload and insert tag
        let tag = self
            .cipher
            .encrypt_in_place_detached(
                chacha20poly1305::XNonce::from_slice(&self.next_enc_nonce()),
                &[0_u8; 0],
                &mut message[24..payload.len() + 24],
            )
            .map_err(|source| D4FTError::AeadError { source })?;
        message[payload.len() + 24..].copy_from_slice(&tag);

        // Send message
        self.socket
            .borrow_mut()
            .write_all(&message)
            .map_err(|source| D4FTError::CommunicationFailure { source })
    }

    fn receive_message<T: DeserializeOwned>(&self) -> D4FTResult<T> {
        // Read header
        let mut message = [0_u8; 24];
        self.socket
            .borrow_mut()
            .read_exact(&mut message)
            .map_err(|source| D4FTError::CommunicationFailure { source })?;

        // Decrypt and verify header
        let mut tag = [0_u8; 16];
        tag.copy_from_slice(&message[8..]);
        self.cipher
            .decrypt_in_place_detached(
                chacha20poly1305::XNonce::from_slice(&self.next_dec_nonce()),
                &[0_u8; 0],
                &mut message[..8],
                chacha20poly1305::Tag::from_slice(&tag),
            )
            .map_err(|source| D4FTError::AeadError { source })?;
        let mut size = [0_u8; 4];
        size.copy_from_slice(&message[4..8]);
        let size = u32::from_be_bytes(size) as usize;

        // Read payload
        let mut message = vec![0_u8; size + 8];
        self.socket
            .borrow_mut()
            .read_exact(&mut message)
            .map_err(|source| D4FTError::CommunicationFailure { source })?;

        // Decrypt and verify payload
        let mut tag = [0_u8; 16]; // Probably don't need this
        tag.copy_from_slice(&message[size - 8..]);
        self.cipher
            .decrypt_in_place_detached(
                chacha20poly1305::XNonce::from_slice(&self.next_dec_nonce()),
                &[0_u8; 0],
                &mut message[..size - 8],
                chacha20poly1305::Tag::from_slice(&tag),
            )
            .map_err(|source| D4FTError::AeadError { source })?;

        serde_json::from_slice(&message[..message.len() - 16])
            .map_err(|source| D4FTError::JsonError { source })
    }
}
