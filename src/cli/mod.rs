#![cfg(feature = "cli")]

use axum_htpasswd::Encoding;
use clap::Parser;
use rpassword::prompt_password;
use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{BufWriter, Error, Write},
};

#[derive(Debug, Clone)]
struct HtpasswdError {
    message: String,
}

impl HtpasswdError {
    fn new(msg: &str) -> HtpasswdError {
        HtpasswdError {
            message: msg.to_owned(),
        }
    }
}

impl fmt::Display for HtpasswdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error: {}", self.message)
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    encoding: Encoding,

    #[arg(short, long)]
    file: String,

    #[arg(short, long)]
    username: String,
}

pub fn run() {
    let args = Args::parse();
    match ask_for_password()
        .and_then(|p| { encode_password(args.encoding, p) })
        .and_then(|password| {
      OpenOptions::new().create(true).append(true).open(args.file)
      .map_err(|_| HtpasswdError::new("Failed to open htpasswd file"))
      .and_then(|f| {
        write_entry(f, args.username, password)
        .map_err(|_| HtpasswdError::new("Failed to write to htpasswd file"))
      })
    }) {
      Ok(_) => {
        println!("Done.")
    }
    Err(e) => {
        println!("{}", e)
    }

    };
}

fn ask_for_password() -> Result<String, HtpasswdError> {
    prompt_password("Enter password: ")
        .map_err(|_| HtpasswdError::new("Failed to read password"))
        .and_then(|first_entry| {
            prompt_password("Confirm password: ")
                .map_err(|_| HtpasswdError::new("Failed to read confirmation"))
                .and_then(|second_entry| {
                    if first_entry == second_entry {
                        Ok(first_entry)
                    } else {
                        Err(HtpasswdError::new("Passwords do not match"))
                    }
                })
        })
}

fn encode_password(enc: Encoding, password: String) -> Result<String, HtpasswdError> {
    match enc {
        Encoding::PlainText => { return Ok(password) },
        Encoding::MD5 => todo!(),
        Encoding::ARGON => { return argon_encode(password)},
    }
}

fn argon_encode(password: String) -> Result<String, HtpasswdError> {
    use argon2::{password_hash::{rand_core::OsRng, PasswordHasher, SaltString},Argon2};

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    match argon2.hash_password(password.as_bytes(), &salt) {
        Ok(password_hash) => { return Ok(password_hash.to_string()); },
        Err(error) => { return Err(HtpasswdError::new(error.to_string().as_str())) }
    }
}

fn write_entry(f: File, username: String, password: String) -> Result<(), Error> {
    let mut buf_writer = BufWriter::new(f);
    writeln!(buf_writer, "{username}:{password}")
}
