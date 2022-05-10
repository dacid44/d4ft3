mod cli;

use std::env;
use d4ft3::{Socket, UnencryptedSocket, TransferMode, D4FTResult};
use crate::cli::TransferModeOpt;

fn main() -> D4FTResult<()> {
    let opts = cli::parse_cli();

    let mode = match (&opts.sending, &opts.transfer_mode) {
        (true, TransferModeOpt::Text(_)) => TransferMode::SendText,
        (true, TransferModeOpt::File(_)) => TransferMode::SendFile,
        (false, TransferModeOpt::Text(_)) => TransferMode::ReceiveText,
        (false, TransferModeOpt::File(_)) => TransferMode::ReceiveFile,
    };

    let socket = if opts.is_client {
        UnencryptedSocket::connect(opts.address, mode)?
    } else {
        UnencryptedSocket::listen(opts.address, mode)?
    };

    match opts.transfer_mode {
        TransferModeOpt::Text(text) => if opts.sending {
            socket.send_text(&text.expect("Need text to send"), opts.attempts)?;
        } else {
            println!("{}", socket.receive_text()?);
        }
        TransferModeOpt::File(_) => {
            unimplemented!("File transfer is not implemented yet.");
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
