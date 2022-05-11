#![feature(io_error_more)]

mod socket;
mod error;
mod json;

use std::io;
use std::fs::File;
use std::path::PathBuf;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};
use enum_dispatch::enum_dispatch;
pub use socket::{UnencryptedSocket, ChaChaSocket, ChaChaPoly1305Socket};
pub use error::{D4FTError, D4FTResult};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}

/// Represents the possible transfer modes of the application.
#[derive(Clone, PartialEq)]
pub enum TransferMode {
    SendText,
    SendFile,
    ReceiveText,
    ReceiveFile,
    ReceiveEither,
}

impl TransferMode {
    fn is_sending(&self) -> bool {
        matches!(self, Self::SendText | Self::SendFile)
    }

    fn is_text(&self) -> bool {
        matches!(self, Self::SendText | Self::ReceiveText | Self::ReceiveEither)
    }

    fn is_file(&self) -> bool {
        matches!(self, Self::SendFile | Self::ReceiveFile | Self::ReceiveEither)
    }
}

/// Represents a socket after the handshake process is completed.
#[enum_dispatch]
pub trait Connection {
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
                json::SendTextResponse::Success => { break Ok(()); }
                json::SendTextResponse::Failure => {
                    break Err(D4FTError::TransmissionFailure {
                        msg: "Transmission failure and out of retries.".to_string(),
                    });
                }
                json::SendTextResponse::Retry => {
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

    /// Receive text.
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

    /// Send a single file.
    ///
    /// # Arguments
    /// * `path` - The path of the file to send
    /// * `retries` - The number of times to allow resending the file if it fails before giving up
    fn send_file(&self, path: &PathBuf, retries: u32) -> D4FTResult<()> {
        let file_data = path.metadata()
            .map_err(|source| D4FTError::FileError { source })?;
        if !file_data.is_file() {
            return Err(D4FTError::FileError { source: std::io::Error::from(std::io::ErrorKind::IsADirectory) })
        }

        let mut hasher = Sha256::new();
        io::copy(
            &mut File::open(&path)
                .map_err(|source| D4FTError::FileError { source })?,
            &mut hasher,
        )
            .map_err(|source| D4FTError::FileError { source })?;
        let hash = hex::encode_upper(hasher.finalize());

        self.send_message(&json::FileList { file_list: vec![json::FileType::File {
            path: path.clone(),
            length: file_data.len().to_string(),
            hash: Some(hash.clone()),
            verify_immediately: true,
            remaining_tries: retries,
        }] })?;

        let response = self.receive_message::<json::FileListResponse>()?;
        let disagreed_error = Err(D4FTError::PacketStructureError {
            msg: "Receiver disagreed on file list.".to_string(),
        });
        if let Some(list) = response.confirm_file_list {
            println!("{:?}", list);
            if list.len() == 1
                // Not sure if I can do File { path: path } but this is easier to read
                && matches!(&list[0], json::MinimalFileType::File { path: p } if p == path)
            { Ok(()) } else { disagreed_error }
        } else { disagreed_error }
    }

    // TODO: finish this
    fn receive_file(&self) -> D4FTResult<()> {
        let message = self.receive_message::<json::FileList>()?;
        let file_list = message.file_list;
        println!("{:?}", file_list);

        let response_list: Vec<json::MinimalFileType> = file_list.iter()
            .map(json::MinimalFileType::from)
            .collect();

        self.send_message(&json::FileListResponse {
            confirm_file_list: Some(response_list),
        })
    }
}

#[enum_dispatch(Connection)]
pub enum ConnectionType {
    UnencryptedSocket,
    ChaChaSocket,
    ChaChaPoly1305Socket,
}