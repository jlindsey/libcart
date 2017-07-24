use std::io;


use proto::Mode;
use proto::Proto;
use codec::Codec;
use ::crypto::{aead, encode_base64, verify};

use message_types::{MessageWrapper, Message, MessageKind};
use ::tokio_io::{AsyncRead, AsyncWrite};
use ::tokio_io::codec::{Framed};
use ::tokio_proto::pipeline::ClientProto;
use ::futures::future;
use ::futures::{Future, Stream, Sink};

impl<T: AsyncRead + AsyncWrite + 'static> ClientProto<T> for Proto {
    type Request = MessageWrapper;
    type Response = MessageWrapper;

    type Transport = Framed<T, Codec>;
    type BindTransport = Box<Future<Item = Self::Transport, Error = io::Error>>;

    fn bind_transport(&self, io: T) -> Self::BindTransport {
        debug!("Binding new protocol");

        if let Mode::Server = self.mode {
            let err = io::Error::new(io::ErrorKind::Other,
                                     "wrong mode for client proto");
            return Box::new(future::err(err));
        }
        let signing_key = self.server_signing_key.clone().unwrap();

        let result = aead::new_ephemeral_key();
        let (private_key, public_key) = match result {
            Ok(keys) => keys,
            Err(_) => {
                let err = io::Error::new(io::ErrorKind::Other,
                                         "unable to generate new ephemeral key pair");
                return Box::new(future::err(err));
            }
        };
        debug!("Generated new public key: {:?}", encode_base64(&public_key));

        let req = MessageWrapper {
            kind: MessageKind::HandshakeInit,
            payload: Message::Handshake(public_key.clone()),
        };

        debug!("Sending handshake init");
        let transport = io.framed(Codec::new());

        let handshake = transport.send(req)
            .and_then(|transport| transport.into_future().map_err(|(e, _)| e))
            .and_then(move |(msg, transport)| {
                match msg {
                    Some(MessageWrapper {
                        kind: MessageKind::HandshakeReply,
                        payload: Message::SignedHandshake(ref server_public_key, ref sig),
                    }) => {
                        debug!("got handshake response: {:?}", msg);

                        if let Err(_) = verify(&signing_key, &server_public_key, &sig) {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "unable to verify server public key signing"
                            ));
                        }

                        let result = aead::EncryptionHandler::from_agreement(
                            (private_key, public_key),
                            server_public_key
                        );
                        let handler = match result {
                            Ok(handler) => handler,
                            Err(_) => {
                                let err = io::Error::new(
                                    io::ErrorKind::Other,
                                    "unable to create encryption handler"
                                );
                                return Err(err);
                            }
                        };
                        let codec = Codec::new_handler(handler);
                        let parts = transport.into_parts();
                        let transport = Framed::from_parts(parts, codec);

                        Ok(transport)
                    },
                    _ => {
                        let err = io::Error::new(
                            io::ErrorKind::Other,
                            "invalid handshake response"
                        );
                        Err(err)
                    }
                }
            });

        Box::new(handshake)
    }
}
