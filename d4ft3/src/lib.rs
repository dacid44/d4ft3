mod socket;
mod error;
mod json;

pub use socket::{Socket, UnencryptedSocket};
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