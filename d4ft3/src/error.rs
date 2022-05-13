use chacha20::cipher::StreamCipherError;
use std::io;
use std::str::Utf8Error;
use thiserror::Error;

/// D4FTError represents all possible errors returned by this library.
#[derive(Error, Debug)]
pub enum D4FTError {
    /// Represents a failure to connect to the peer.
    #[error("Failed to connect")]
    ConnectionFailure { source: io::Error },

    /// Represents a failed socket send or receive.
    #[error("Communication failure")]
    CommunicationFailure { source: io::Error },

    /// Represents a failure to decode UTF8 data.
    #[error("Unicode error")]
    UnicodeError {
        #[from]
        source: Utf8Error,
    },

    /// Represents a mangled packet, usually an incorrect header.
    #[error("PacketStructureError: {msg}")]
    PacketStructureError { msg: String },

    /// Represents an error encountered while deserializing JSON data.
    #[error("JSON Error")]
    JsonError {
        #[from]
        source: serde_json::Error,
    },

    /// Represents a failure due to the peers disagreeing.
    #[error("Disgreement: {msg}")]
    Disagreement { msg: String },

    /// Represents a transmission failure.
    #[error("Transmission failure: {msg}")]
    TransmissionFailure { msg: String },

    /// Emitted when an action was attempted that was not set up for.
    #[error("Invalid action: {msg}")]
    InvalidAction { msg: String },

    /// Represents an error with a cipher, usually reaching the end of a keystream.
    #[error("Cipher error")]
    CipherError {
        #[from]
        source: StreamCipherError,
    },

    /// Represents an error with an AEAD cipher, usually a failed authentication check.
    #[error("AEAD error")]
    AeadError {
        #[from]
        source: chacha20poly1305::aead::Error,
    },

    /// Represents a failure due to failed encryption/decryption.
    #[error("Encryption failure: {msg}")]
    EncryptionFailure { msg: String },

    /// Represents an error encountered while reading or writing a file.
    #[error("File I/O error")]
    FileError { source: io::Error },

    /// Raised when a network operation was cancelled.
    #[error("Operation cancelled: {msg}")]
    Cancelled { msg: String },
}

pub type D4FTResult<T> = Result<T, D4FTError>;
