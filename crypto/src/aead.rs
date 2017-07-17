use std::mem::size_of_val;

use errors::Error;

use super::untrusted;
use super::{encode_base64, decode_base64};
use super::ring::rand::SecureRandom;
use super::ring::{hkdf, hmac, aead, agreement, rand, digest};

const SALT: &'static [u8] = b"oW8+beevA7hLwDgSFE3ny/L/xLp0jaygmgYdgWUpsyY=";

pub type EphemeralKeyPair = (agreement::EphemeralPrivateKey, Vec<u8>);
pub type AEADKeyPair = (aead::SealingKey, aead::OpeningKey);

pub struct EncryptionHandler {
    sealer: aead::SealingKey,
    opener: aead::OpeningKey,
}

impl EncryptionHandler {
    pub fn new(sealer: aead::SealingKey, opener: aead::OpeningKey) -> EncryptionHandler {
        EncryptionHandler {
            sealer: sealer,
            opener: opener,
        }
    }

    pub fn from_agreement(keypair: EphemeralKeyPair, peer_public_key: &[u8]) -> Result<EncryptionHandler, Error> {
        let pair = new_sym_key(keypair.0, &keypair.1, peer_public_key)?;
        Ok(EncryptionHandler::new(pair.0, pair.1))
    }

    pub fn seal_data(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let rng = rand::SystemRandom::new();
        let mut nonce = [0u8; 1024]; // way more space than we need, to be safe
        let nonce = &mut nonce[..self.sealer.algorithm().nonce_len()];
        rng.fill(nonce)?;

        debug!("nonce size: {} bits", size_of_val(nonce) * 8);

        let mut vec = data.to_vec();
        let len = vec.len();
        vec.resize(len + self.sealer.algorithm().tag_len(), 0);

        aead::seal_in_place(&self.sealer, &nonce, &[], &mut vec, self.sealer.algorithm().tag_len())?;

        Ok((nonce.to_vec(), vec))
    }

    pub fn open_data(&self, nonce: Vec<u8>, mut data: Vec<u8>) -> Result<Vec<u8>, Error> {
        let out = aead::open_in_place(&self.opener, &nonce, &[], 0, &mut data)?;
        Ok(out.to_vec())
    }
}

pub fn new_ephemeral_key() -> Result<EphemeralKeyPair, Error> {
    let rng = rand::SystemRandom::new();
    let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;

    let mut public_key = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
    let public_key = &mut public_key[..private_key.public_key_len()];
    private_key.compute_public_key(public_key)?;

    Ok((private_key, public_key.to_vec()))
}

pub fn new_sym_key(private_key: agreement::EphemeralPrivateKey, our_pub_key: &[u8], peer_pub_key: &[u8]) -> Result<AEADKeyPair, Error> {
    let salt_data = decode_base64(SALT);
    let salt = hmac::SigningKey::new(&digest::SHA512_256, &salt_data);
    let pub_key_in = untrusted::Input::from(peer_pub_key);

    let err = Error::CryptoError("unable to generate key agreement".into());
    agreement::agree_ephemeral(private_key, &agreement::X25519, pub_key_in, err, |key_data| {
        let mut sign_kdf_out = [0u8; digest::SHA512_256_OUTPUT_LEN];
        let mut open_kdf_out = [0u8; digest::SHA512_256_OUTPUT_LEN];

        hkdf::extract_and_expand(&salt, key_data, our_pub_key, &mut sign_kdf_out);
        hkdf::extract_and_expand(&salt, key_data, peer_pub_key, &mut open_kdf_out);

        debug!("key data size: {} bits", size_of_val(key_data) * 8);
        debug!("key data: {:?}", encode_base64(key_data));

        let sign_key = aead::SealingKey::new(&aead::AES_256_GCM, &sign_kdf_out)?;
        let open_key = aead::OpeningKey::new(&aead::AES_256_GCM, &open_kdf_out)?;

        Ok((sign_key, open_key))
    })
}
