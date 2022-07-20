use aes::cipher::{KeyIvInit, block_padding::Pkcs7, BlockDecryptMut};
use super::types::*;
use super::errors::{Result, Error, ErrorKind};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// A "Decryptor", which is nothing more than a data structure to keep around the RNCryptor context
pub struct Decryptor {
    pub version: u8,
    pub options: u8,
    encryption_salt: EncryptionSalt,
    hmac_salt: HMACSalt,
    encryption_key: EncryptionKey,
    pub hmac_key: HMACKey,
    iv: IV,
}

impl Decryptor {
    /// Builds a "Decryptor" out of a password and a message (to decrypt).
    pub fn from(password: &str, message: &[u8]) -> Result<Decryptor> {
        let msg_len = message.len();
        if msg_len < 66 {
            return Err(Error::new(ErrorKind::NotEnoughInput(msg_len),
                                  "Decryption failed, not enough input.".to_owned()));
        }

        let version = message[0];
        let options = message[1];
        let encryption_salt = Salt(message[2..10].to_vec());
        let hmac_salt = Salt(message[10..18].to_vec());
        let iv = IV::from(message[18..34].to_vec());
        let encryption_key = EncryptionKey::new(&encryption_salt, password.as_bytes());
        let hmac_key = HMACKey::new(&hmac_salt, password.as_bytes());

        Ok(Decryptor {
            version,
            options,
            encryption_salt,
            encryption_key,
            hmac_key,
            hmac_salt,
            iv,
        })

    }

    fn plain_text(&self, cipher_text: &[u8]) -> Result<Message> {
        let iv  = self.iv.to_vec();
        let key = self.encryption_key.to_vec();

        let decryptor = Aes256CbcDec::new(key.as_slice().into(), iv.as_slice().into());
        let decrypted = decryptor.decrypt_padded_vec_mut::<Pkcs7>(cipher_text).map_err(|error| {
            Error::new(ErrorKind::UnpadError, error.to_string())
        })?;

        Ok(decrypted)
    }

    /// Decrypts a `cipher_text`, returning a `Message` or an `Error`.
    pub fn decrypt(&self, cipher_text: &[u8]) -> Result<Message> {

        let mut header: Vec<u8> = vec![3, 1];
        header.extend(self.encryption_salt.as_slice().iter());
        header.extend(self.hmac_salt.as_slice().iter());
        header.extend(self.iv.as_slice().iter());

        //TODO: Do not depend from drain, as this is O(n).
        let mut cipher_text_vec = Vec::from(&cipher_text[34..]);
        let hmac_position = cipher_text_vec.len() - 32;
        let hmac0 = cipher_text_vec.drain(hmac_position..).collect();

        let encrypted = cipher_text_vec.as_slice();

        let message = self.plain_text(encrypted)?;

        let hmac = HMAC(hmac0);
        let computed_hmac = HMAC::new(&Header(header), cipher_text_vec.as_slice(), &self.hmac_key)?;

        match hmac.is_equal_in_consistent_time_to(&computed_hmac) {
            true  => Ok(message),
            false => Err(Error::new(ErrorKind::HMACValidationFailed, "HMAC mismatch.".to_owned())),
        }
    }
}
