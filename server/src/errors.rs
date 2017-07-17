use std::fmt;
use std::io;
use std::error;

use ::crypto;
use ::serde_cbor;

#[derive(Debug)]
pub enum Error {
    IOError(io::Error),
    InvalidPacket,
    CryptoError(crypto::errors::Error),
    EncodingError(serde_cbor::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::IOError(ref err) => write!(f, "IO Error: {}", err),
            Error::InvalidPacket => write!(f, "InvalidPacket"),
            Error::CryptoError(_) => write!(f, "Crypto Error"),
            Error::EncodingError(ref err) => write!(f, "Encoding Error: {}", err),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::IOError(ref err) => err.description(),
            Error::InvalidPacket => "invalid packet",
            _ => "error"
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::IOError(ref err) => Some(err),
            Error::InvalidPacket => None,
            Error::CryptoError(_) => None,
            Error::EncodingError(ref err) => Some(err)
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IOError(err)
    }
}

impl Into<io::Error> for Error {
    fn into(self) -> io::Error {
        match self {
            Error::IOError(err) => err,
            Error::CryptoError(_) => io::ErrorKind::Other.into(),
            Error::InvalidPacket => io::ErrorKind::InvalidData.into(),
            Error::EncodingError(_) => io::ErrorKind::InvalidInput.into(),
        }
    }
}

impl From<crypto::errors::Error> for Error {
    fn from(err: crypto::errors::Error) -> Self {
        Error::CryptoError(err)
    }
}

impl From<serde_cbor::Error> for Error {
    fn from(err: serde_cbor::Error) -> Self {
        Error::EncodingError(err)
    }
}

