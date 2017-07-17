use std::io;
use std::error::Error;

use super::frame_utils::*;
use super::serde_cbor;
use super::{Codec, MessageWrapper, MessageKind, BytesMut, BigEndian, WriteBytesExt};

use ::crypto::encode_base64;
use ::crypto::aead::EncryptionHandler;
use ::tokio_io::codec::Encoder;

type CodingResult = Result<(), io::Error>;

impl Encoder for Codec {
    type Item = MessageWrapper;
    type Error = io::Error;

    fn encode(&mut self, item: MessageWrapper, mut buf: &mut BytesMut) -> CodingResult {
        debug!("new message to encode: {:?}", item);

        match item.kind {
            MessageKind::Normal => {
                if let Some(ref handler) = self.handler {
                    encode_encrypted(handler, item, &mut buf)
                } else {
                    Err(new_io_error("missing encryption handler"))
                }
            },
            _ => encode_decrypted(item, &mut buf)
        }
    }
}


fn encode_encrypted(handler: &EncryptionHandler, item: MessageWrapper, mut buf: &mut BytesMut) -> CodingResult {
    debug!("encoding encrypted");

    let msg = serialize(&item)?;
    let res = handler.seal_data(&msg);
    let (mut nonce, mut crypted) = match res {
        Ok(res) => res,
        Err(err) => return Err(new_io_error(err.description())),
    };
    let nonce_size = nonce.len();
    let crypted_size = crypted.len();
    debug!("nonce: {} {:?}", encode_base64(&nonce), &nonce);
    debug!("crypted payload: {} {:?}", encode_base64(&crypted), &crypted);

    let mut vec: Vec<u8> = Vec::new();
    vec.write_u8(item.kind as u8)?;
    debug_assert!(vec.len() == 1, "vector length should be 1 after writing kind byte");

    vec.write_u32::<BigEndian>(nonce_size as u32)?;
    debug_assert!(vec.len() == 1 + header_size());

    vec.append(&mut nonce);
    debug_assert!(vec.len() == 1 + header_size() + nonce_size);

    vec.append(&mut crypted);
    debug_assert!(vec.len() == 1 + header_size() + nonce_size + crypted_size);

    let mut sized: Vec<u8> = Vec::new();
    debug!("size should be {:?}", vec.len());
    sized.write_u32::<BigEndian>(vec.len() as u32)?;
    sized.append(&mut vec);

    debug!("encoded packet total length: {}", sized.len());
    debug!("sending encoded packet: {:?}", sized);

    buf.extend_from_slice(&sized);

    Ok(())
}

fn encode_decrypted(item: MessageWrapper, mut buf: &mut BytesMut) -> CodingResult {
    debug!("encoding decrypted");

    let mut msg = serialize(&item)?;
    let mut vec: Vec<u8> = Vec::new();
    vec.write_u8(item.kind as u8)?;
    debug_assert!(vec.len() == 1, "vector length should be 1 after writing kind byte");
    let msg_length = msg.len();
    vec.append(&mut msg);
    let total_length = vec.len();

    debug_assert!(total_length == msg_length + 1, "total length should be msg_length + 1");

    let mut sized: Vec<u8> = Vec::new();
    debug!("size should be {:?}", vec.len());
    sized.write_u32::<BigEndian>(vec.len() as u32)?;
    sized.append(&mut vec);
    debug_assert!(sized.len() == total_length + 4, "sized ({}) != total_length + 4 ({})",
                  sized.len(), total_length + 4);

    debug!("encoded packet total length: {}", sized.len());
    debug!("sending encoded packet: {:?}", sized);

    buf.extend_from_slice(&sized);

    Ok(())
}

fn serialize(item: &MessageWrapper) -> Result<Vec<u8>, io::Error> {
    debug!("serializing msg: {:?}", item);
    let res = serde_cbor::to_vec(&item.payload);
    match res {
        Ok(msg) => {
            debug!("serialized message: {:?}", msg);
            Ok(msg)
        },
        Err(err) => {
            let ioerr = new_io_error(err.description());
            Err(ioerr)
        }
    }
}
