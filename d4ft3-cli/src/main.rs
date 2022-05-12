mod cli;

use crate::cli::TransferModeOpt;
use d4ft3::{
    ChaChaPoly1305Socket, ChaChaSocket, Connection, ConnectionType, D4FTResult, TransferMode,
    UnencryptedSocket,
};

fn main() -> D4FTResult<()> {
    let opts = cli::parse_cli();

    let socket = if let Some(password) = opts.password {
        ConnectionType::from(if opts.is_client {
            ChaChaPoly1305Socket::connect(opts.address, TransferMode::from(&opts.mode), password)?
        } else {
            ChaChaPoly1305Socket::listen(opts.address, TransferMode::from(&opts.mode), password)?
        })
    } else {
        ConnectionType::from(if opts.is_client {
            UnencryptedSocket::connect(opts.address, TransferMode::from(&opts.mode))?
        } else {
            UnencryptedSocket::listen(opts.address, TransferMode::from(&opts.mode))?
        })
    };
    println!("connected");

    match opts.mode {
        TransferModeOpt::SendText(text) => {
            socket.send_text(&text, opts.attempts)?;
        }
        TransferModeOpt::SendFile(path) => {
            socket.send_file(&path, opts.attempts)?;
        }
        TransferModeOpt::ReceiveText => {
            println!("{}", socket.receive_text()?);
        }
        TransferModeOpt::ReceiveFile => {
            socket.receive_file()?;
        }
        TransferModeOpt::ReceiveEither => {
            println!("{}", socket.receive_text()?);
        }
    }

    Ok(())
}
