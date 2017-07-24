use std::vec::Vec;


use ::ring::signature::Ed25519KeyPair;

mod client;
mod server;

enum Mode {
    Client,
    Server
}

pub struct Proto {
    mode: Mode,
    server_private_key: Option<Ed25519KeyPair>,
    server_signing_key: Option<Vec<u8>>,
}

impl Proto {
    pub fn new_server(key: Ed25519KeyPair) -> Proto {
        Proto {
            mode: Mode::Server,
            server_private_key: Some(key),
            server_signing_key: None,
        }
    }

    pub fn new_client(key: Vec<u8>) -> Proto {
        Proto {
            mode: Mode::Client,
            server_private_key: None,
            server_signing_key: Some(key),
        }
    }
}
