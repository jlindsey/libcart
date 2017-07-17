use std::fs::File;
use std::io::prelude::*;

use ::ring::{rand, signature};
use ::base64::{encode, decode};
use ::untrusted;

use errors::Error;

pub fn load_or_create_key(path: &str) -> Result<signature::Ed25519KeyPair, Error> {
    let pair = load_key(path);

    match pair {
        Ok(key) => Ok(key),
        Err(Error::IOError(_)) => {
            let key = gen_key_bytes()?;
            let encoded = encode(&key[..]);
            write_key_file(&encoded, path)?;

            let key = signature::Ed25519KeyPair::from_pkcs8(untrusted::Input::from(&key))?;

            Ok(key)
        }
        Err(error) => panic!(error),
    }
}

fn gen_key_bytes() -> Result<[u8; 85], Error> {
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)?;

    Ok(pkcs8_bytes)
}

fn write_key_file(key: &str, filename: &str) -> Result<(), Error> {
    let mut f = File::create(filename)?;
    f.write_all(key.as_bytes())?;
    f.sync_all()?;

    Ok(())
}

fn load_key(path: &str) -> Result<signature::Ed25519KeyPair, Error> {
    let mut f = File::open(path)?;
    let mut buf = Vec::new();

    f.read_to_end(&mut buf)?;

    let decoded = decode(&buf)?;
    let mut der_bytes: [u8; 85] = [0; 85];
    der_bytes.clone_from_slice(&decoded);

    let pair = signature::Ed25519KeyPair::from_pkcs8(untrusted::Input::from(&der_bytes))?;

    Ok(pair)
}

