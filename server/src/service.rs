use message_types::Message;

use ::tokio_service::{Service, NewService};
use ::futures::future;
use ::futures::Future;

use std::io;

pub struct RPC;

impl Service for RPC {
    type Request = Message;
    type Response = Message;

    type Error = io::Error;
    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, req: Self::Request) -> Self::Future {
        debug!("Service called: {:?}", req);

        match req {
            Message::Ping => future::finished(Message::Pong).boxed(),
            _ => future::err(
                io::Error::new(io::ErrorKind::InvalidInput,
                               format!("unknown message type: {:?}", req))
            ).boxed()
        }
    }
}

impl NewService for RPC {
    type Request = Message;
    type Response = Message;
    type Error = io::Error;
    type Instance = RPC;

    fn new_service(&self) -> io::Result<Self::Instance> {
        Ok(RPC {})
    }
}

