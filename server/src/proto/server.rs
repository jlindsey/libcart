use std::io;

use proto::Mode;
use proto::Proto;
use codec::Codec;
use ::crypto::aead;

use message_types::{MessageWrapper, Message, MessageKind};
use ::tokio_io::{AsyncRead, AsyncWrite};
use ::tokio_io::codec::{Framed};
use ::tokio_proto::pipeline::ServerProto;
use ::futures::future;
use ::futures::{Future, Stream, Sink};

impl<T: AsyncRead + AsyncWrite + 'static> ServerProto<T> for Proto {
    type Request = MessageWrapper;
    type Response = MessageWrapper;

    type Transport = Framed<T, Codec>;
    type BindTransport = Box<Future<Item = Self::Transport, Error = io::Error>>;

    fn bind_transport(&self, io: T) -> Self::BindTransport {
        debug!("Binding new protocol");

        if let Mode::Client = self.mode {
            let err = io::Error::new(io::ErrorKind::Other,
                                     "wrong mode for server proto");
            return Box::new(future::err(err));
        }

        let result = aead::new_ephemeral_key();
        let (private_key, public_key) = match result {
            Ok(keys) => keys,
            Err(_) => {
                let err = io::Error::new(io::ErrorKind::Other,
                                         "unable to generate new ephemeral key pair");
                return Box::new(future::err(err));
            }
        };


        let sig: Option<Vec<u8>> = if let Some(ref server_key) = self.server_private_key {
            let signed = server_key.sign(&public_key);
            Some(Vec::from(signed.as_ref()))
        } else {
            None
        };
        let sig = sig.unwrap();
        debug!("signed server key: {:?}", &sig);

        let transport = io.framed(Codec::new());

        let handshake = transport.into_future()
            .map_err(|(e, _)| e)
            .and_then(|(msg, transport)| {
                debug!("got new handshake attempt: {:?}", msg);

                let error = |message| {
                    warn!("Invalid handshake");
                    let err = io::Error::new(io::ErrorKind::Other,
                                             message);
                    Box::new(future::err(err)) as Self::BindTransport
                };

                match msg {
                    Some(MessageWrapper {
                        kind: MessageKind::HandshakeInit,
                        payload: Message::Handshake(ref peer_public_key),
                    }) => {
                        let response = MessageWrapper {
                            kind: MessageKind::HandshakeReply,
                            payload: Message::SignedHandshake(public_key.clone(), sig),
                        };

                        let result = aead::EncryptionHandler::from_agreement(
                            (private_key, public_key), peer_public_key
                        );
                        let handler = match result {
                            Ok(handler) => handler,
                            Err(_) => return error("unable to create encryption handler")
                        };

                        let codec = Codec::new_handler(handler);
                        let parts = transport.into_parts();
                        let transport = Framed::from_parts(parts, codec);

                        let ret = transport.send(response);
                        Box::new(ret) as Self::BindTransport
                    },
                    _ => error("invalid handshake")
                }
            });

        Box::new(handshake)
    }

}
