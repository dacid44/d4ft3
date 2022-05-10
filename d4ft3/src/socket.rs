use std::cell::RefCell;
use std::fmt::Error;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use sha2::Digest;
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
pub trait Socket: Sized {
    /// Connect to a listening peer.
    fn connect<T: ToSocketAddrs>(address: T, mode: TransferMode) -> D4FTResult<Self>;

    /// Open a port and listen for a connection from a peer.
    fn listen<T: ToSocketAddrs>(address: T, mode: TransferMode) -> D4FTResult<Self>;

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

impl Socket for UnencryptedSocket {
    fn connect<T: ToSocketAddrs>(address: T, mode: TransferMode) -> D4FTResult<Self> {
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

    fn listen<T: ToSocketAddrs>(address: T, mode: TransferMode) -> D4FTResult<Self> {
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
