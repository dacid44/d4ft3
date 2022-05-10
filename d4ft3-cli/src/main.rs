mod cli;

use std::env;
use d4ft3::{Socket, UnencryptedSocket, TransferMode, D4FTResult, ChaChaSocket, SocketType};
use crate::cli::TransferModeOpt;

fn main() -> D4FTResult<()> {
    let opts = cli::parse_cli();

    let socket = if let Some(password) = opts.password {
        SocketType::from(if opts.is_client {
            ChaChaSocket::connect(opts.address, TransferMode::from(&opts.mode), password)?
        } else {
            ChaChaSocket::listen(opts.address, TransferMode::from(&opts.mode), password)?
        })
    } else {
        SocketType::from(if opts.is_client {
            UnencryptedSocket::connect(opts.address, TransferMode::from(&opts.mode))?
        } else {
            UnencryptedSocket::listen(opts.address, TransferMode::from(&opts.mode))?
        })
    };
    println!("connected");

    // match opts.transfer_mode {
    //     TransferModeOpt::Text(text) => if opts.sending {
    //         socket.send_text(&text.expect("Need text to send"), opts.attempts)?;
    //     } else {
    //         println!("{}", socket.receive_text()?);
    //     }
    //     TransferModeOpt::File(_) => {
    //         unimplemented!("File transfer is not implemented yet.");
    //     }
    // }
    match opts.mode {
        TransferModeOpt::SendText(text) => {
            socket.send_text(&text, opts.attempts)?;
        }
        TransferModeOpt::SendFile(_) => unimplemented!("File transfer is not implemented yet."),
        TransferModeOpt::ReceiveText => {
            println!("{}", socket.receive_text()?);
        }
        TransferModeOpt::ReceiveFile => unimplemented!("File transfer is not implemented yet."),
        TransferModeOpt::ReceiveEither => {
            println!("{}", socket.receive_text()?);
        }
    }

    Ok(())

    // let args: Vec<String> = env::args().collect();
    // if args.len() > 1 {
    //     let socket = UnencryptedSocket::connect(
    //         "127.0.0.1",
    //         2581,
    //         TransferMode::SendText,
    //     ).unwrap();
    //     loop {
    //         let mut input = String::new();
    //         println!("Message: ");
    //         std::io::stdin().read_line(&mut input).unwrap();
    //         socket.send_text(&input, 3);
    //     }
    // } else {
    //     let socket = UnencryptedSocket::listen(
    //         "127.0.0.1",
    //         2581,
    //         TransferMode::ReceiveText,
    //     ).unwrap();
    //     loop {
    //         println!("{}", socket.receive_text().unwrap());
    //     }
    // }
}
