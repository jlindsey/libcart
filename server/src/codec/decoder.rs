use std::io;

use super::frame_utils::*;
use super::serde_cbor;
use super::{Codec, BytesMut, MessageWrapper, MessageKind, BigEndian, ReadBytesExt};

use ::crypto::encode_base64;
use ::crypto::aead::EncryptionHandler;
use ::tokio_io::codec::Decoder;

impl Decoder for Codec {
    type Item = MessageWrapper;
    type Error = io::Error;

    fn decode(&mut self, mut buf: &mut BytesMut) -> Result<Option<MessageWrapper>, io::Error> {
        let size = buf.len();
        if size < minimum_frame_size() {
            debug!("buf == 0 waiting for more data");
            return Ok(None);
        }

        debug!("Got new frame: {:?}", &buf);
        debug!("Got new raw frame: {} bytes", size);

        let total_size = extract_frame_size(&mut buf)?;
        debug!("Got total size: {}", total_size);
        let message_size = total_size - 1;

        if buf.len() >= total_size {
            let kind = extract_message_kind(&mut buf)?;
            match kind {
                MessageKind::Normal => {
                    if let Some(ref handler) = self.handler {
                        decode_encrypted(handler, &mut buf, message_size, kind)
                    } else {
                        Err(new_io_error("missing encryption handler"))
                    }
                },
                _ => decode_unencrypted(&mut buf, message_size, kind)
            }
        } else {
            debug!("{} < {} waiting for more data", buf.len(), total_size);
            Ok(None)
        }
    }
}

fn decode_encrypted(handler: &EncryptionHandler, mut buf: &mut BytesMut, _: usize, kind: MessageKind) -> Result<Option<MessageWrapper>, io::Error> {
    debug!("decoding encrypted packet");
    let header_size = header_size();

    let mut rdr = io::Cursor::new(buf.split_to(header_size));
    let nonce_size = rdr.read_u32::<BigEndian>()? as usize;
    debug!("nonce size: {}", nonce_size);
    let nonce = buf.split_to(nonce_size);
    let nonce = nonce.to_vec();
    debug!("nonce: {} {:?}", encode_base64(&nonce), &nonce);

    if nonce.len() != nonce_size {
        return Err(new_io_error("invalid packet"));
    }

    let payload_size = buf.len();
    let payload = extract_raw_payload(&mut buf, payload_size)?;
    debug!("crypted payload: {} {:?}", encode_base64(&payload), &payload);

    if payload.len() != payload_size {
        return Err(new_io_error("invalid packet"));
    }

    let payload = handler.open_data(nonce.clone(), payload);
    let payload = match payload {
        Ok(payload) => payload,
        Err(_) => return Err(new_io_error("unable to decrypt data"))
    };
    debug!("decrypted payload: {:?}", &payload);
    let payload = serde_cbor::from_slice(&payload);
    let payload = match payload {
        Ok(payload) => payload,
        Err(_) => return Err(new_io_error("unable to deserialize data"))
    };
    let wrapper: MessageWrapper = MessageWrapper {
        kind: kind,
        payload: payload,
    };
    debug!("decrypted wrapper: {:?}", wrapper);

    Ok(Some(wrapper))
}

fn decode_unencrypted(mut buf: &mut BytesMut, payload_size: usize, kind: MessageKind) -> Result<Option<MessageWrapper>, io::Error> {
    debug!("decoding unencrypted packet");

    let payload = extract_raw_payload(&mut buf, payload_size)?;
    let payload = serde_cbor::from_slice(&payload);
    debug!("deserialized message: {:?}", payload);
    let payload = match payload {
        Ok(payload) => payload,
        Err(_) => return Err(new_io_error("unable to deserialize data"))
    };
    let wrapper = MessageWrapper {
        kind: kind,
        payload: payload,
    };

    debug!("decoded wrapper: {:?}", wrapper);

    Ok(Some(wrapper))
}

