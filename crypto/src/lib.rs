#[macro_use]
extern crate log;
extern crate base64;
extern crate ring;
extern crate untrusted;

pub mod errors;
pub mod keys;
pub mod aead;

use self::base64::{encode, decode};

pub fn encode_base64(input: &[u8]) -> String {
    encode(input)
}

pub fn decode_base64(input: &[u8]) -> Vec<u8> {
    decode(input).unwrap()
}

pub fn verify(pub_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), errors::Error> {
    let pub_key = untrusted::Input::from(pub_key);
    let msg = untrusted::Input::from(msg);
    let sig = untrusted::Input::from(sig);

    let result = ring::signature::verify(
        &ring::signature::ED25519,
        pub_key,
        msg,
        sig
    );

    match result {
        Ok(()) => Ok(()),
        Err(_) => Err(errors::Error::CryptoError("bad signature".to_string()))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
