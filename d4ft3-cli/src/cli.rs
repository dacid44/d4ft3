use std::net::ToSocketAddrs;
use clap::{Arg, ArgMatches, ArgGroup, Command};
extern crate rpassword;
use std::path::PathBuf;
use d4ft3::TransferMode;

pub(crate) fn parse_cli() -> Opts {
    let mut app = Command::new("d4ft3")
        .version("1.0")
        .author("Keegan Conlee (dacid44) <dacid44@gmail.com>")
        .about("A simple-to-use secure file and text transfer program.")
        .arg(Arg::new("connect")
            .short('c')
            .long("connect")
            .value_name("ADDRESS[:PORT]")
            .value_hint(clap::ValueHint::Hostname)
            .help("Connect to a device running d4ft3 in listener mode. You must specify at least an address \
            (defaults to port 2581). Conflicts with --listen.")
            .next_line_help(true)
            .help_heading("CONNECT MODE (Choose one)")
            .display_order(0)
            .takes_value(true)
            .validator(validate_dest))
        .arg(Arg::new("listen")
            .short('l')
            .long("listen")
            .value_name("[BIND_ADDRESS]:[PORT]")
            .value_hint(clap::ValueHint::Hostname)
            .help("Listen for a connection from a device running d4ft3 in connect mode. You may specify an address, \
            a port, or both (defaults to 0.0.0.0:2581). Conflicts with --connect.")
            .next_line_help(true)
            .help_heading("CONNECT MODE (Choose one)")
            .display_order(1)
            .takes_value(true)
            .default_missing_value("0.0.0.0")
            .validator(validate_bind))
        .group(ArgGroup::new("connection_mode")
            .args(&["connect", "listen"])
            .required(true))
        .arg(Arg::new("send")
            .short('s')
            .long("send")
            .help("Send something to the other device. Conflicts with --receive.")
            .help_heading("ACTION (Choose one)")
            .display_order(10)
            .requires("transfer_mode"))
        .arg(Arg::new("receive")
            .short('r')
            .long("receive")
            .help("Receive something from the other device. Conflicts with --send.")
            .help_heading("ACTION (Choose one)")
            .display_order(11))
        .group(ArgGroup::new("sending")
            .args(&["send", "receive"])
            .required(true))
        .arg(Arg::new("text")
            .short('t')
            .long("text")
            .value_name("[TEXT]")
            .help("Select text mode. Specify a value only if sending. Conflicts with --file.")
            .help_heading("TRANSFER MODE (Choose one)")
            .display_order(20)
            .takes_value(true)
            .default_missing_value(""))
        .arg(Arg::new("file")
            .short('f')
            .long("file")
            .value_name("[PATH]")
            .value_hint(clap::ValueHint::AnyPath)
            .help("Select file mode. Specify a value only if sending. Conflicts with --text.")
            .help_heading("TRANSFER MODE (Choose one)")
            .display_order(21)
            .takes_value(true)
            .default_missing_value(""))
        .group(ArgGroup::new("transfer_mode")
            .args(&["text", "file"]))
        .arg(Arg::new("password")
            .short('p')
            .long("password")
            .value_name("[PASSWORD]")
            .help("If present, the data will be sent encrypted. The password must be present and identical on both \
            devices. If present but a value is not given, it will be prompted for. IMPORTANT: IF NOT PRESENT, THE DATA \
            WILL BE SENT IN PLAINTEXT!")
            .next_line_help(true)
            .display_order(100)
            .takes_value(true)
            .default_missing_value(""))
        .arg(Arg::new("attempts")
            .short('a')
            .long("attempts")
            .help("How many times to attempt the transfer. Defaults to 3.")
            .display_order(101)
            .takes_value(true)
            .default_value("3")
            .validator(validate_u32));
    let matches = app.get_matches_mut();

    let (is_client, address) = if matches.is_present("connect") {
        (true, validate_dest(
            matches.value_of("connect").expect("We've already checked that this value is present")
        ).expect("This should have already been verified to give Ok()"))
    } else {
        (false, validate_bind(
            matches.value_of("listen").expect("This value should be present if 'connect' is not present")
        ).expect("This should have already been verified to give Ok()"))
    };
    // let sending = matches.is_present("send");
    // let transfer_mode = if matches.is_present("text") {
    //     TransferModeOpt::Text(
    //         match matches.value_of("text").expect("We've already checked that this value is present") {
    //             "" => None,
    //             t => Some(t.to_string()),
    //         })
    // } else {
    //     TransferModeOpt::File(
    //         match matches.value_of("file").expect("This value should be present if 'text' is not present") {
    //             "" => None,
    //             p => {
    //                 let path = PathBuf::from(p);
    //                 if !path.exists() {
    //                     app.error(clap::ErrorKind::InvalidValue, "The specified file does not exist.").exit();
    //                 }
    //                 Some(path)
    //             }
    //         }
    //     )
    // };
    let mode = match (
        matches.is_present("send"),
        matches.is_present("text"),
        matches.is_present("file")
    ) {
        (true, true, false) => TransferModeOpt::SendText(
            match matches.value_of("text")
                .expect("We've already checked that this value is present")
            {
                "" => app.error(
                    clap::ErrorKind::EmptyValue,
                    "Must specify a value for --text if sending",
                ).exit(),
                t => t.to_string(),
            }
        ),
        (true, false, true) => TransferModeOpt::SendFile(
            match matches.value_of("file")
                .expect("This value should be present if 'text' is not present")
            {
                "" => app.error(
                    clap::ErrorKind::EmptyValue,
                    "Must specify a value for --file if sending",
                ).exit(),
                p => {
                    let path = PathBuf::from(p);
                    if !path.exists() {
                        app.error(
                            clap::ErrorKind::ValueValidation,
                            "The specified file does not exist."
                        ).exit();
                    }
                    path
                }
            }
        ),
        (false, true, false) => TransferModeOpt::ReceiveText,
        (false, false, true) => TransferModeOpt::ReceiveFile,
        (false, false, false) => TransferModeOpt::ReceiveEither,
        _ => unreachable!("All other patterns should be impossible"),
    };
    let password = if matches.is_present("password") {
        match matches.value_of("password") {
            Some(p) => Some(p.to_string()),
            None => Some(rpassword::prompt_password("Password: ").expect("Error prompting for password")),
        }
    } else { None };
    let attempts = validate_u32(
        matches.value_of("attempts").expect("This value has a default value, so it should always be present.")
    ).expect("This should have already been verified to give Ok()");
    Opts { is_client, address, mode, password, attempts }
}

#[derive(Debug)]
pub(crate) struct Opts {
    pub(crate) is_client: bool,
    pub(crate) address: String,
    pub(crate) mode: TransferModeOpt,
    pub(crate) password: Option<String>,
    pub(crate) attempts: u32,
}

#[derive(Debug)]
pub(crate) enum TransferModeOpt {
    SendText(String),
    SendFile(PathBuf),
    ReceiveText,
    ReceiveFile,
    ReceiveEither,
}

impl From<&TransferModeOpt> for TransferMode {
    fn from(value: &TransferModeOpt) -> Self {
        match value {
            TransferModeOpt::SendText(_) => Self::SendText,
            TransferModeOpt::SendFile(_) => Self::SendFile,
            TransferModeOpt::ReceiveText => Self::ReceiveText,
            TransferModeOpt::ReceiveFile => Self::ReceiveFile,
            TransferModeOpt::ReceiveEither => Self::ReceiveEither
        }
    }
}

fn validate_dest(v: &str) -> Result<String, String> {
    if v.contains(":") {
        match v.to_socket_addrs() {
            Ok(_) => Ok(v.to_string()),
            Err(_) => Err("Invalid ADDRESS: must be of the form ADDRESS, PORT, or ADDRESS:PORT".to_string()),
        }
    } else {
        match format!("{}:2581", v).to_socket_addrs() {
            Ok(_) => Ok(format!("{}:2581", v)),
            Err(_) =>  Err("Invalid ADDRESS: must be of the form ADDRESS, PORT, or ADDRESS:PORT".to_string()),
        }
    }
}

fn validate_bind(v: &str) -> Result<String, String> {
    if v.contains(":") {
        match v.to_socket_addrs() {
            Ok(_) => Ok(v.to_string()),
            Err(_) => Err("Invalid ADDRESS: must be of the form ADDRESS, PORT, or ADDRESS:PORT".to_string()),
        }
    } else {
        match v.parse::<u16>() {
            Ok(_) => Ok(v.to_string()),
            Err(_) => match format!("{}:2581", v).to_socket_addrs() {
                Ok(_) => Ok(format!("{}:2581", v)),
                Err(_) => Err("Invalid ADDRESS: must be of the form ADDRESS, PORT, or ADDRESS:PORT".to_string()),
            },
        }
    }
}

fn validate_u32(v: &str) -> Result<u32, String> {
    match v.parse::<u32>() {
        Ok(r) => Ok(r),
        Err(_) => Err("Must be a non-negative integer not greater than 4294967295".to_string()),
    }
}