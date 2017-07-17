use std::fmt;
use std::io;
use std::error;
use ::base64;
use ::ring::error::Unspecified;

#[derive(Debug)]
pub enum Error {
    CryptoError(String),
    IOError(io::Error),
    Base64DecodeError(base64::DecodeError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::CryptoError(ref err) => write!(f, "Crypto Error: {}", err),
            Error::IOError(ref err) => write!(f, "IO Error: {}", err),
            Error::Base64DecodeError(ref err) => write!(f, "Base64 Error: {}", err),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::CryptoError(ref err) => &err,
            Error::IOError(ref err) => err.description(),
            Error::Base64DecodeError(ref err) => err.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::CryptoError(_) => None,
            Error::IOError(ref err) => Some(err),
            Error::Base64DecodeError(ref err) => Some(err),
        }
    }
}

impl From<Unspecified> for Error {
    fn from(_: Unspecified) -> Self {
        Error::CryptoError("unspecified ring error".to_string())
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IOError(err)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Error::Base64DecodeError(err)
    }
}
