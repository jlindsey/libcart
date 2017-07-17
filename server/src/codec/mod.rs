use message_types::{MessageWrapper, MessageKind};
use crypto::aead::EncryptionHandler;

use ::byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};
use ::serde_cbor;
use ::bytes::BytesMut;

mod decoder;
mod encoder;
mod frame_utils;

pub struct Codec {
    pub handler: Option<EncryptionHandler>,
}

/*
frame: [ u32 (total message size) + u8 (MessageKind) + <message> ]

<message> for encrypted types:
u32 (nonce size) + [u8] (nonce) + [u8] (cbor-serialized payload)

<message> for unencrypted types:
[u8] (cbor-serialized payload)
 */

impl Codec {
    pub fn new() -> Codec {
        Codec {
            handler: None
        }
    }

    pub fn new_handler(handler: EncryptionHandler) -> Codec {
        Codec {
            handler: Some(handler)
        }
    }

}
