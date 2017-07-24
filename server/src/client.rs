use std::io;
use std::net;

use proto::Proto;
use message_types::MessageWrapper;

use ::futures::Future;
use ::tokio_proto::TcpClient;
use ::tokio_proto::pipeline::ClientService;
use ::tokio_service::{Service, NewService};
use ::tokio_core::reactor::Handle;
use ::tokio_core::net::TcpStream;

struct RPC<T> {
    inner: T,
}

pub struct Client {
    inner: RPC<ClientService<TcpStream, Proto>>,
}

impl<T> Service for RPC<T>
    where T: Service<Request = MessageWrapper, Response = MessageWrapper, Error = io::Error>,
          T::Future: 'static
{
    type Request = MessageWrapper;
    type Response = MessageWrapper;
    type Error = io::Error;
    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, req: Self::Request) -> Self::Future {
        Box::new(self.inner.call(req))
    }
}

impl<T> NewService for RPC<T>
    where T: NewService<Request = MessageWrapper, Response = MessageWrapper, Error = io::Error>,
          <T::Instance as Service>::Future: 'static
{
    type Request = MessageWrapper;
    type Response = MessageWrapper;
    type Error = io::Error;
    type Instance = RPC<T::Instance>;

    fn new_service(&self) -> io::Result<Self::Instance> {
        let inner = try!(self.inner.new_service());
        Ok(RPC { inner: inner })
    }
}

impl Service for Client {
    type Request = MessageWrapper;
    type Response = MessageWrapper;
    type Error = io::Error;
    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, req: Self::Request) -> Self::Future {
        self.inner.call(req)
    }
}

impl Client {
    pub fn connect(addr: &net::SocketAddr, handle: &Handle, server_public_key: Vec<u8>) -> Box<Future<Item = Client, Error = io::Error>> {
        let ret = TcpClient::new(Proto::new_client(server_public_key.clone()))
            .connect(addr, handle)
            .map(|service| {
                let s = RPC { inner: service };
                Client { inner: s }
            });

        Box::new(ret)
    }
}
