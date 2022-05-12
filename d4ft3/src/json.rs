//! Contains the struct implementations of the various JSON objects in the protocol.

use crate::TransferMode;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The first message sent by the client, designating which encryption type to use and the
/// initialization vectors.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "security")]
pub(crate) enum EncryptionSetup {
    /// No encryption
    #[serde(rename = "none")]
    Unencrypted,

    /// XChaCha20 encryption with passkey-derived key
    #[serde(rename = "xchacha20-psk")]
    XChaCha20Psk { nonce: String, salt: String },

    /// XChaCha20-Poly1305 encryption with passkey-derived key
    #[serde(rename = "xchacha20-poly1305-psk")]
    XChaCha20Poly1305Psk { nonce: String, salt: String },
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct EncryptionSetupResponse {
    pub(crate) confirm: bool,
}

/// Describes the mode of transfer (text or file).
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum BaseTransferMode {
    Text,
    File,
}

/// The message sent by the client after encryption has begun to set up the text or file transfer.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) enum TransferSetup {
    #[serde(rename = "send_mode")]
    Sending(BaseTransferMode),
    #[serde(rename = "receive_modes")]
    Receiving(Vec<BaseTransferMode>),
}

impl From<&TransferMode> for TransferSetup {
    fn from(value: &TransferMode) -> Self {
        match value {
            TransferMode::SendText => Self::Sending(BaseTransferMode::Text),
            TransferMode::SendFile => Self::Sending(BaseTransferMode::File),
            TransferMode::ReceiveText => Self::Receiving(vec![BaseTransferMode::Text]),
            TransferMode::ReceiveFile => Self::Receiving(vec![BaseTransferMode::File]),
            TransferMode::ReceiveEither => {
                Self::Receiving(vec![BaseTransferMode::Text, BaseTransferMode::File])
            }
        }
    }
}

impl TransferSetup {
    pub(crate) fn verify(&self, mode: &TransferMode) -> bool {
        match self {
            Self::Sending(BaseTransferMode::Text) if !mode.is_sending() && mode.is_text() => true,
            Self::Sending(BaseTransferMode::File) if !mode.is_sending() && mode.is_file() => true,
            Self::Receiving(x)
                if mode.is_sending()
                    && ((mode.is_text() && x.contains(&BaseTransferMode::Text))
                        || (mode.is_file() && x.contains(&BaseTransferMode::File))) =>
            {
                true
            }
            _ => false,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TransferSetupResponse {
    confirm: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<BaseTransferMode>,
}

impl TransferSetupResponse {
    pub(crate) fn failure() -> Self {
        Self {
            confirm: false,
            mode: None,
        }
    }

    pub(crate) fn verify(&self, mode: &TransferMode) -> bool {
        self.confirm
            && match (&self.mode, mode) {
                (
                    Some(BaseTransferMode::Text),
                    TransferMode::ReceiveText | TransferMode::ReceiveEither,
                ) => true,
                (
                    Some(BaseTransferMode::File),
                    TransferMode::ReceiveFile | TransferMode::ReceiveEither,
                ) => true,
                (None, TransferMode::SendText | TransferMode::SendFile) => true,
                _ => false,
            }
    }
}

impl From<&TransferMode> for TransferSetupResponse {
    fn from(value: &TransferMode) -> Self {
        Self {
            confirm: true,
            mode: match value {
                TransferMode::SendText => Some(BaseTransferMode::Text),
                TransferMode::SendFile => Some(BaseTransferMode::File),
                _ => None,
            },
        }
    }
}

/// The packet in which the text is actually sent.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SendText {
    pub(crate) text: String,
    pub(crate) hash: String,
    pub(crate) remaining_tries: u32,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "status", rename_all = "lowercase")]
pub(crate) enum SendTextResponse {
    Success,
    Failure,
    Retry,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub(crate) enum FileType {
    File {
        path: PathBuf,
        length: String,
        hash: Option<String>,
        verify_immediately: bool,
        remaining_tries: u32,
    },
    Directory {
        path: PathBuf,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct FileList {
    pub(crate) file_list: Vec<FileType>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub(crate) enum MinimalFileType {
    File { path: PathBuf },
    Directory { path: PathBuf },
}

impl From<&FileType> for MinimalFileType {
    fn from(value: &FileType) -> Self {
        match value {
            FileType::File { path, .. } => Self::File { path: path.clone() },
            FileType::Directory { path } => Self::Directory { path: path.clone() },
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct FileListResponse {
    pub(crate) confirm_file_list: Option<Vec<MinimalFileType>>,
}
