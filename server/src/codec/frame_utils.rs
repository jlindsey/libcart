use std::io;
use std::mem;

use super::{BytesMut, BigEndian, MessageKind, ReadBytesExt};

#[inline]
pub fn header_size() -> usize {
    mem::size_of::<u32>()
}

#[inline]
pub fn minimum_frame_size() -> usize {
    header_size() + 1
}

pub fn extract_frame_size(buf: &mut BytesMut) -> io::Result<usize> {
    let header_size = header_size();
    let mut rdr = io::Cursor::new(buf.split_to(header_size));
    let total_size = rdr.read_u32::<BigEndian>()? as usize;

    Ok(total_size)
}

pub fn extract_message_kind(buf: &mut BytesMut) -> io::Result<MessageKind> {
    let buf_size = buf.len();
    let mut rdr = io::Cursor::new(buf.split_to(1));
    debug_assert!(buf.len() == buf_size - 1);
    let message_kind = MessageKind::from(rdr.read_u8()?);
    debug!("Message kind: {}", message_kind);

    if let MessageKind::Unknown = message_kind {
        Err(new_io_error("got unknown message kind byte"))
    } else {
        Ok(message_kind)
    }
}

pub fn extract_raw_payload(buf: &mut BytesMut, length: usize) -> io::Result<Vec<u8>> {
    debug_assert!(buf.len() >= length, "{} >= {}", buf.len(), length);
    let payload = buf.split_to(length);
    let payload = payload.to_vec();
    debug!("extracted payload bytes: {:?}", payload);
    Ok(payload)
}

pub fn new_io_error(msg: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        msg
    )
}
