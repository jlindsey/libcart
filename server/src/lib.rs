#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_cbor;
extern crate ring;
extern crate bytes;
extern crate futures;
extern crate tokio_io;
extern crate tokio_core;
extern crate tokio_proto;
extern crate tokio_service;
extern crate crypto;
extern crate byteorder;

pub mod errors;
pub mod message_types;
pub mod proto;
mod client;
mod service;
mod codec;

pub use client::Client;

use ::tokio_proto::TcpServer;
use ::crypto::keys::load_or_create_key;

pub fn start(addr: &str) {
    let addr = addr.parse().unwrap();
    let server_key = load_or_create_key("server.key").unwrap();
    let protocol = proto::Proto::new_server(server_key);

    let server = TcpServer::new(protocol, addr);
    server.serve(move || Ok(service::RPC));
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
