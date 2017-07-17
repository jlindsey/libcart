use std::fmt::{Display, Formatter, Result};
use std::u8::MAX as U8_MAX;

#[derive(Debug)]
pub struct MessageWrapper {
    pub kind: MessageKind,
    pub payload: Message,
}

impl MessageWrapper {
    pub fn new(payload: Message) -> MessageWrapper {
        MessageWrapper {
            kind: MessageKind::Normal,
            payload: payload,
        }
    }

    pub fn new_error(message: String) -> MessageWrapper {
        MessageWrapper {
            kind: MessageKind::Normal,
            payload: Message::Error(message),
        }
    }
}

impl From<Message> for MessageWrapper {
    fn from(msg: Message) -> Self {
        match msg {
            Message::Handshake(key) => MessageWrapper {
                kind: MessageKind::HandshakeInit,
                payload: Message::Handshake(key),
            },
            Message::SignedHandshake(key, sig) => MessageWrapper {
                kind: MessageKind::HandshakeReply,
                payload: Message::SignedHandshake(key, sig),
            },
            _ => MessageWrapper::new(msg),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    Ping,
    Pong,
    Error(String),
    SignedHandshake(Vec<u8>, Vec<u8>),
    Handshake(Vec<u8>),
}

impl From<MessageWrapper> for Message {
    fn from(wrapper: MessageWrapper) -> Self { wrapper.payload }
}

#[derive(Debug, PartialEq)]
pub enum MessageKind {
    HandshakeInit,
    HandshakeReply,
    Normal,
    Unknown,
}

impl From<u8> for MessageKind {
    fn from(val: u8) -> Self {
        match val {
            0 => MessageKind::HandshakeInit,
            1 => MessageKind::HandshakeReply,
            2 => MessageKind::Normal,
            _ => MessageKind::Unknown,
        }
    }
}

impl Display for MessageKind {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let val: u8 = match *self {
            MessageKind::HandshakeInit => 0,
            MessageKind::HandshakeReply => 1,
            MessageKind::Normal => 2,
            _ => U8_MAX
        };

        write!(f, "{}", val)
    }
}
