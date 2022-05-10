use std::cell::RefCell;
use std::fmt::Error;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use chacha20::cipher::{StreamCipher, KeyIvInit};
use chacha20::XChaCha20;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use scrypt::scrypt;
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use sha2::Digest;
use enum_dispatch::enum_dispatch;
use crate::error::{D4FTError, D4FTResult};
use crate::{json, TransferMode};
use crate::json::SendTextResponse;

// /// Contains the logic for the initial handshake process.
// ///
// /// After the handshake is complete, this should be consumed by whichever secure socket type is used
// /// to continue the exchange.
// pub struct HandshakeSocket {
//     is_client: bool,
//     socket: RefCell<TcpStream>,
// }
//
// impl HandshakeSocket {
//     /// Open a port and listen for a connection from a peer.
//     pub fn listen(address: &str, port: u16) -> D4FTResult<Self> {
//         // TODO: Resolve DNS
//         let (socket, _) = TcpListener::bind((address, port))
//             .and_then(|l| l.accept())
//             .map_err(|source| D4FTError::ConnectionFailure { source })?;
//         Ok(Self { is_client: false, socket: RefCell::new(socket) })
//     }
//
//     /// Connect to a listening peer.
//     pub fn connect(address: &str, port: u16) -> D4FTResult<Self> {
//         // TODO: Resolve DNS
//         let socket = TcpStream::connect((address, port))
//             .map_err(|source| D4FTError::ConnectionFailure { source })?;
//         Ok(Self { is_client: true, socket: RefCell::new(socket) })
//     }
//
//     // pub fn start_encryption<T: CompleteSocket>(self) -> T {
//     //     todo!()
//     // }
//
//     pub fn echo(&self, text: &str) -> D4FTResult<()> {
//         if self.is_client {
//             self.socket.borrow_mut().write_all(text.as_bytes())
//                 .map_err(|source| D4FTError::CommunicationFailure { source })
//         } else {
//             let mut data = [0_u8; 1024];
//             loop {
//                 match self.socket.borrow_mut().read(&mut data) {
//                     Ok(size) => {
//                         println!("{}", std::str::from_utf8(&data[0..size])
//                             .map_err(|source| D4FTError::UnicodeError { source })?);
//                     }
//                     Err(err) => {
//                         // TODO: Handle this
//                         println!("closing on error");
//                         self.socket.borrow().shutdown(Shutdown::Both).unwrap();
//                         return Err(D4FTError::CommunicationFailure { source: err });
//                     }
//                 }
//             }
//         }
//     }
// }

fn read_plaintext_message(socket: &mut TcpStream) -> D4FTResult<Vec<u8>> {
    let mut buffer = [0_u8; 8];
    socket.read_exact(&mut buffer)
        .map_err(|source| D4FTError::CommunicationFailure { source })?;
    if &buffer[0..4] != b"D4FT" {
        return Err(D4FTError::PacketStructureError { msg: "invalid header".to_string() })
    }
    // Should be safe to unwrap as we know the source (4 bytes of an array)
    let mut message = vec![0_u8;
                            u32::from_be_bytes(buffer[4..8].try_into().unwrap()) as usize];
    socket.read_exact(&mut message)
        .map_err(|source| D4FTError::CommunicationFailure { source })?;
    Ok(message)
}

fn build_message<T: Serialize>(msg: &T) -> Result<Vec<u8>, serde_json::Error> {
    let message = serde_json::to_vec(msg)?;
    Ok([b"D4FT", &(message.len() as u32).to_be_bytes(), message.as_slice()].concat())
}

/// Represents a socket after the handshake process is completed.
#[enum_dispatch]
pub trait Socket {
    // /// Connect to a listening peer.
    // fn connect<T: ToSocketAddrs>(address: T, mode: TransferMode) -> D4FTResult<Self>;

    // /// Open a port and listen for a connection from a peer.
    // fn listen<T: ToSocketAddrs>(address: T, mode: TransferMode) -> D4FTResult<Self>;

    /// Get the transfer mode of this socket.
    fn transfer_mode(&self) -> TransferMode;

    /// Send a message.
    fn send_message<T: Serialize>(&self, msg: &T) -> D4FTResult<()>;

    /// Receive a message.
    fn receive_message<T: DeserializeOwned>(&self) -> D4FTResult<T>;

    /// Send text.
    ///
    /// # Arguments
    /// * `text` - The text to send
    /// * `retries` - The number of times to allow resending the text if it fails before giving up
    fn send_text(&self, text: &str, retries: u32) -> D4FTResult<()> {
        if !matches!(self.transfer_mode(), TransferMode::SendText) {
            return Err(D4FTError::InvalidAction {
                msg: "Attempted to send text when this socket was not set up to do so."
                    .to_string(),
            })
        }

        let hash = hex::encode_upper(
            sha2::Sha256::new_with_prefix(text.as_bytes())
                .finalize()
        );
        let mut retries = retries;

        loop {
            self.send_message(&json::SendText {
                text: text.to_string(),
                hash: hash.clone(),
                remaining_tries: retries,
            })?;
            let response = self.receive_message::<json::SendTextResponse>()?;
            match response {
                SendTextResponse::Success => { break Ok(()); }
                SendTextResponse::Failure => {
                    break Err(D4FTError::TransmissionFailure {
                        msg: "Transmission failure and out of retries.".to_string(),
                    });
                }
                SendTextResponse::Retry => {
                    if retries == 0 {
                        break Err(D4FTError::TransmissionFailure {
                            msg: "Transmission failure and out of retries.".to_string(),
                        });
                    }
                    retries -= 1;
                }
            }
        }
    }

    fn receive_text(&self) -> D4FTResult<String> {
        if !matches!(
            self.transfer_mode(),
            TransferMode::ReceiveText | TransferMode::ReceiveEither
        ) {
            return Err(D4FTError::InvalidAction {
                msg: "Attempted to receive text when this socket was not set up to do so."
                    .to_string(),
            })
        }

        loop {
            let message = self.receive_message::<json::SendText>()?;

            let hash = hex::encode_upper(
                sha2::Sha256::new_with_prefix(message.text.as_bytes())
                    .finalize()
            );
            if message.hash == hash {
                self.send_message(&json::SendTextResponse::Success)?;
                break Ok(message.text);
            }

            if message.remaining_tries == 0 {
                self.send_message(&json::SendTextResponse::Failure)?;
                break Err(D4FTError::TransmissionFailure {
                    msg: "Transmission failure and out of retries.".to_string(),
                });
            }

            self.send_message(&json::SendTextResponse::Retry)?;
        }
    }
}

#[enum_dispatch(Socket)]
pub enum SocketType {
    UnencryptedSocket,
    ChaChaSocket,
}

pub struct UnencryptedSocket {
    is_client: bool,
    socket: RefCell<TcpStream>,
    mode: TransferMode,
}

// impl UnencryptedSocket {
//     pub fn echo(&self, text: &str) -> D4FTResult<()> {
//         if self.is_client {
//             self.socket.borrow_mut().write_all(text.as_bytes())
//                 .map_err(|source| D4FTError::CommunicationFailure { source })
//         } else {
//             let mut data = [0_u8; 1024];
//             loop {
//                 match self.socket.borrow_mut().read(&mut data) {
//                     Ok(size) => {
//                         println!("{}", std::str::from_utf8(&data[0..size])
//                             .map_err(|source| D4FTError::UnicodeError { source })?);
//                     }
//                     Err(err) => {
//                         // TODO: Handle this
//                         println!("closing on error");
//                         self.socket.borrow().shutdown(Shutdown::Both).unwrap();
//                         return Err(D4FTError::CommunicationFailure { source: err });
//                     }
//                 }
//             }
//         }
//     }
// }

impl UnencryptedSocket {
    /// Connect to a listening peer.
    pub fn connect<T: ToSocketAddrs>(address: T, mode: TransferMode) -> D4FTResult<Self> {
        // TODO: Resolve DNS
        // Connect socket
        let mut socket = TcpStream::connect(address)
            .map_err(|source| D4FTError::ConnectionFailure { source })?;

        // Send encryption setup
        let message = build_message(&json::EncryptionSetup::Unencrypted)
            .expect("This should be completely static");
        socket.write_all(&message)
            .map_err(|source| D4FTError::CommunicationFailure { source })?;

        // Receive encryption setup response
        let response = serde_json::from_slice::<json::EncryptionSetupResponse>(
            &read_plaintext_message(&mut socket)?
        )
            .map_err(|source| D4FTError::JsonError { source })?;

        // Close if disagreement
        if !response.confirm {
            socket.shutdown(Shutdown::Both);
            return Err(D4FTError::Disagreement {
                msg: "The listener refused the connection (likely security types did not match)"
                    .to_string(),
            });
        }

        // Send transfer setup
        let message = build_message(&json::TransferSetup::from(&mode))
            .expect("This should be completely static");
        socket.write_all(&message)
            .map_err(|source| D4FTError::CommunicationFailure { source })?;

        // Receive transfer setup response
        let response = serde_json::from_slice::<json::TransferSetupResponse>(
            &read_plaintext_message(&mut socket)?
        )
            .map_err(|source| D4FTError::JsonError { source })?;

        // Close if disagreement
        if !response.verify(&mode) {
            socket.shutdown(Shutdown::Both);
            return Err(D4FTError::Disagreement {
                msg: "The listener disagreed on transfer mode".to_string()
            });
        }

        Ok(Self { is_client: true, socket: RefCell::new(socket), mode })
    }

    /// Open a port and listen for a connection from a peer.
    pub fn listen<T: ToSocketAddrs>(address: T, mode: TransferMode) -> D4FTResult<Self> {
            // TODO: Resolve DNS
            // Bind socket
            let (mut socket, _) = TcpListener::bind(address)
                .and_then(|l| l.accept())
                .map_err(|source| D4FTError::ConnectionFailure { source })?;

            // Receive encryption setup
            let message = serde_json::from_slice::<json::EncryptionSetup>(
                &read_plaintext_message(&mut socket)?
            )
                .map_err(|source| D4FTError::JsonError { source })?;
            if !matches!(message, json::EncryptionSetup::Unencrypted)  {
                // Respond and close if disagreement
                let response = build_message(&json::EncryptionSetupResponse { confirm: false })
                    .expect("This should be completely static");
                socket.write_all(&response)
                    .map_err(|source| D4FTError::CommunicationFailure { source })?;

                socket.shutdown(Shutdown::Both);
                return Err(D4FTError::Disagreement { msg: "Security types did not match.".to_string()})
            }

            // Respond with agreement if security types match
            let response = build_message(&json::EncryptionSetupResponse { confirm: true })
                .expect("This should be completely static");
            socket.write_all(&response)
                .map_err(|source| D4FTError::CommunicationFailure { source })?;

            // Receive transfer setup
            let message = serde_json::from_slice::<json::TransferSetup>(
                &read_plaintext_message(&mut socket)?
            )
                .map_err(|source| D4FTError::JsonError { source })?;

            // If disagreement, close the connection
            if !message.verify(&mode) {
                let response = build_message(&json::TransferSetupResponse::failure())
                    .expect("This should be completely static");
                socket.write_all(&response)
                    .map_err(|source| D4FTError::CommunicationFailure { source })?;

                socket.shutdown(Shutdown::Both);
                return Err(D4FTError::Disagreement {
                    msg: "The client disagreed on transfer mode".to_string()
                });
            }

            // Respond with agreement if transfer modes match
            let response = build_message(&json::TransferSetupResponse::from(&mode))
                .expect("This should be completely static");
            socket.write_all(&response)
                .map_err(|source| D4FTError::CommunicationFailure { source })?;

            Ok(Self { is_client: false, socket: RefCell::new(socket), mode })
        }
}

impl Socket for UnencryptedSocket {
    fn transfer_mode(&self) -> TransferMode {
        self.mode.clone()
    }

    fn send_message<T: Serialize>(&self, msg: &T) -> D4FTResult<()> {
        self.socket.borrow_mut().write_all(
            &build_message(msg)
                .map_err(|source| D4FTError::JsonError { source })?,
        ).map_err(|source| D4FTError::CommunicationFailure { source })
    }

    fn receive_message<T: DeserializeOwned>(&self) -> D4FTResult<T> {
        serde_json::from_slice(
            &read_plaintext_message(&mut self.socket.borrow_mut())?
        ).map_err(|source| D4FTError::JsonError { source })
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
    /// Connect to a listening peer.
    pub fn connect<T: ToSocketAddrs>(address: T, mode: TransferMode, password: String) -> D4FTResult<Self> {
        // TODO: Resolve DNS
        // Connect socket
        let mut socket = TcpStream::connect(address)
            .map_err(|source| D4FTError::ConnectionFailure { source })?;

        // Generate initialization vectors
        let mut rng = ChaCha20Rng::from_entropy();

        let mut raw_nonce = [0_u8; 48];
        rng.fill_bytes(&mut raw_nonce);
        let nonce = hex::encode_upper(raw_nonce);

        let mut raw_salt = [0_u8; 32];
        rng.fill_bytes(&mut raw_salt);
        let salt = hex::encode_upper(raw_salt);

        // Send encryption setup
        let message = build_message(&json::EncryptionSetup::XChaCha20Psk { nonce, salt })
            .expect("This should be successful");
        socket.write_all(&message)
            .map_err(|source| D4FTError::CommunicationFailure { source })?;

        // Receive encryption setup response
        let response = serde_json::from_slice::<json::EncryptionSetupResponse>(
            &read_plaintext_message(&mut socket)?
        )
            .map_err(|source| D4FTError::JsonError { source })?;

        // Close if disagreement
        if !response.confirm {
            socket.shutdown(Shutdown::Both);
            return Err(D4FTError::Disagreement {
                msg: "The listener refused the connection (likely security types did not match)"
                    .to_string(),
            });
        }

        // Set up ciphers
        let mut key = [0_u8; 32];
        scrypt(
            password.as_bytes(),
            &raw_salt,
            &scrypt::Params::new(16, 8, 1)
                .expect("Should not error on hardcoded params"),
            &mut key,
        ).expect("Should not error on hardcoded output length");

        let mut enc_cipher = XChaCha20::new(
            chacha20::Key::from_slice(&key),
            chacha20::XNonce::from_slice(&raw_nonce[..24]),
        );
        let mut dec_cipher = XChaCha20::new(
            chacha20::Key::from_slice(&key),
            chacha20::XNonce::from_slice(&raw_nonce[24..]),
        );

        // Send transfer setup
        let mut message = build_message(&json::TransferSetup::from(&mode))
            .expect("This should be completely static");
        enc_cipher.try_apply_keystream(&mut message)
            .map_err(|source| D4FTError::CipherError { source });
        socket.write_all(&message)
            .map_err(|source| D4FTError::CommunicationFailure { source })?;

        // Receive transfer setup response
        let mut response = [0_u8; 8];
        socket.read_exact(&mut response)
            .map_err(|source| D4FTError::CommunicationFailure { source })?;
        dec_cipher.try_apply_keystream(&mut response)
            .map_err(|source| D4FTError::CipherError { source });
        if &response[0..4] != b"D4FT" {
            // If encryption failed, close the connection
            socket.shutdown(Shutdown::Both);
            return Err(D4FTError::EncryptionFailure {
                msg: "could not understand the listener".to_string()
            })
        }
        let mut response = vec![
            0_u8;
            u32::from_be_bytes(response[4..8].try_into().unwrap()) as usize
        ];
        socket.read_exact(&mut response)
            .map_err(|source| D4FTError::CommunicationFailure { source })?;
        dec_cipher.try_apply_keystream(&mut response)
            .map_err(|source| D4FTError::CipherError { source });
        let response = serde_json::from_slice::<json::TransferSetupResponse>(&response)
            .map_err(|source| D4FTError::JsonError { source })?;

        // Close if disagreement
        if !response.verify(&mode) {
            socket.shutdown(Shutdown::Both);
            return Err(D4FTError::Disagreement {
                msg: "The listener disagreed on transfer mode".to_string()
            });
        }

        Ok(Self {
            is_client: true,
            socket: RefCell::new(socket),
            mode,
            enc_cipher: RefCell::new(enc_cipher),
            dec_cipher: RefCell::new(dec_cipher),
        })
    }

    /// Open a port and listen for a connection from a peer.
    pub fn listen<T: ToSocketAddrs>(address: T, mode: TransferMode, password: String) -> D4FTResult<Self> {
        // TODO: Resolve DNS
        // Bind socket
        let (mut socket, _) = TcpListener::bind(address)
            .and_then(|l| l.accept())
            .map_err(|source| D4FTError::ConnectionFailure { source })?;

        // Receive encryption setup
        let message = serde_json::from_slice::<json::EncryptionSetup>(
            &read_plaintext_message(&mut socket)?
        )
            .map_err(|source| D4FTError::JsonError { source })?;

        // Extract initialization vectors if agreement, respond and close otherwise
        let (nonce, salt) = if let json::EncryptionSetup::XChaCha20Psk {nonce, salt} = message {
            // Respond with agreement if security types match
            let response = build_message(&json::EncryptionSetupResponse { confirm: true })
                .expect("This should be completely static");
            socket.write_all(&response)
                .map_err(|source| D4FTError::CommunicationFailure { source })?;

            (nonce, salt)
        } else {
            // Respond and close if disagreement
            let response = build_message(&json::EncryptionSetupResponse { confirm: false })
                .expect("This should be completely static");
            socket.write_all(&response)
                .map_err(|source| D4FTError::CommunicationFailure { source })?;

            socket.shutdown(Shutdown::Both);
            return Err(D4FTError::Disagreement { msg: "Security types did not match.".to_string() })
        };

        let raw_nonce = hex::decode(nonce)
            .map_err(|_| D4FTError::PacketStructureError {
                msg: "invalid data for nonce".to_string(),
            })?;
        if raw_nonce.len() != 48 {
            return Err(D4FTError::PacketStructureError {
                msg: "invalid data for nonce".to_string(),
            })
        }

        let raw_salt = hex::decode(salt)
            .map_err(|_| D4FTError::PacketStructureError {
                msg: "invalid data for salt".to_string(),
            })?;
        if raw_salt.len() != 32 {
            return Err(D4FTError::PacketStructureError {
                msg: "invalid data for salt".to_string(),
            })
        }

        // Set up ciphers
        let mut key = [0_u8; 32];
        scrypt(
            password.as_bytes(),
            &raw_salt,
            &scrypt::Params::new(16, 8, 1)
                .expect("Should not error on hardcoded params"),
            &mut key,
        ).expect("Should not error on hardcoded output length");

        let mut enc_cipher = XChaCha20::new(
            chacha20::Key::from_slice(&key),
            chacha20::XNonce::from_slice(&raw_nonce[24..]),
        );
        let mut dec_cipher = XChaCha20::new(
            chacha20::Key::from_slice(&key),
            chacha20::XNonce::from_slice(&raw_nonce[..24]),
        );

        // Receive transfer setup
        let mut message = [0_u8; 8];
        socket.read_exact(&mut message)
            .map_err(|source| D4FTError::CommunicationFailure { source })?;
        dec_cipher.try_apply_keystream(&mut message)
            .map_err(|source| D4FTError::CipherError { source });
        if &message[0..4] != b"D4FT" {
            // If encryption failed, send FAILED and close the connection
            socket.write_all(b"D4FT\x00\x00\x00\x0EFAILED")
                .map_err(|source| D4FTError::CommunicationFailure { source })?;
            socket.shutdown(Shutdown::Both);
            return Err(D4FTError::EncryptionFailure {
                msg: "could not understand the client".to_string()
            })
        }
        let mut message = vec![
            0_u8;
            u32::from_be_bytes(message[4..8].try_into().unwrap()) as usize
        ];
        socket.read_exact(&mut message)
            .map_err(|source| D4FTError::CommunicationFailure { source })?;
        dec_cipher.try_apply_keystream(&mut message)
            .map_err(|source| D4FTError::CipherError { source });
        let message = serde_json::from_slice::<json::TransferSetup>(&message)
            .map_err(|source| D4FTError::JsonError { source })?;

        // If disagreement, close the connection
        if !message.verify(&mode) {
            let mut response = build_message(&json::TransferSetupResponse::failure())
                .expect("This should be completely static");
            enc_cipher.try_apply_keystream(&mut response)
                .map_err(|source| D4FTError::CipherError { source });
            socket.write_all(&response)
                .map_err(|source| D4FTError::CommunicationFailure { source })?;

            socket.shutdown(Shutdown::Both);
            return Err(D4FTError::Disagreement {
                msg: "The client disagreed on transfer mode".to_string()
            });
        }

        let mut response = build_message(&json::TransferSetupResponse::from(&mode))
            .expect("This should be completely static");
        enc_cipher.try_apply_keystream(&mut response)
            .map_err(|source| D4FTError::CipherError { source });
        socket.write_all(&response)
            .map_err(|source| D4FTError::CommunicationFailure { source })?;

        Ok(Self {
            is_client: false,
            socket: RefCell::new(socket),
            mode,
            enc_cipher: RefCell::new(enc_cipher),
            dec_cipher: RefCell::new(dec_cipher),
        })
    }
}

impl Socket for ChaChaSocket {
    fn transfer_mode(&self) -> TransferMode {
        self.mode.clone()
    }

    fn send_message<T: Serialize>(&self, msg: &T) -> D4FTResult<()> {
        println!("send message");
        let mut message = build_message(msg)
            .map_err(|source| D4FTError::JsonError { source })?;
        self.enc_cipher.borrow_mut().try_apply_keystream(&mut message)
            .map_err(|source| D4FTError::CipherError { source });
        self.socket.borrow_mut().write_all(&message)
            .map_err(|source| D4FTError::CommunicationFailure { source })
    }

    fn receive_message<T: DeserializeOwned>(&self) -> D4FTResult<T> {
        println!("receive message");
        let mut message = [0_u8; 8];
        self.socket.borrow_mut().read_exact(&mut message)
            .map_err(|source| D4FTError::CommunicationFailure { source })?;
        self.dec_cipher.borrow_mut().try_apply_keystream(&mut message)
            .map_err(|source| D4FTError::CipherError { source });
        if &message[0..4] != b"D4FT" {
            return Err(D4FTError::EncryptionFailure {
                msg: "could not understand the peer".to_string()
            })
        }
        let mut message = vec![
            0_u8;
            u32::from_be_bytes(message[4..8].try_into().unwrap()) as usize
        ];
        self.socket.borrow_mut().read_exact(&mut message)
            .map_err(|source| D4FTError::CommunicationFailure { source })?;
        self.dec_cipher.borrow_mut().try_apply_keystream(&mut message)
            .map_err(|source| D4FTError::CipherError { source });
        serde_json::from_slice(&message)
            .map_err(|source| D4FTError::JsonError { source })
    }
}
