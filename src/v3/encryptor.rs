extern crate aes;
extern crate cbc;

use self::aes::cipher::{block_padding::{NoPadding, Pkcs7}, BlockEncryptMut, KeyIvInit};
use v3::types::*;
use v3::errors::{Result, Error, ErrorKind};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

#[derive(Clone)]
pub struct Encryptor {
    encryption_key: EncryptionKey,
    hmac_key: HMACKey,
    header: Header,
    iv: IV,
}

impl Encryptor {
    pub fn from_password(password: &str,
                         es: EncryptionSalt,
                         hs: HMACSalt,
                         iv: IV)
                         -> Result<Encryptor> {

        if password.is_empty() {
            return Err(Error::new(ErrorKind::WrongInputSize(0),
                                  "Password length cannot be empty.".to_owned()));
        }

        let mut header: Vec<u8> = vec![3, 1];
        header.extend(es.as_slice().iter());
        header.extend(hs.as_slice().iter());
        header.extend(iv.as_slice().iter());

        Ok(Encryptor {
            encryption_key: EncryptionKey::new(&es, password.as_bytes()),
            hmac_key: HMACKey::new(&hs, password.as_bytes()),
            header: Header(header),
            iv,
        })
    }

    pub fn from_keys(ek: EncryptionKey, hk: HMACKey, iv: IV) -> Result<Encryptor> {

        let mut header: Vec<u8> = vec![3, 0];
        header.extend(iv.as_slice().iter());

        Ok(Encryptor {
            encryption_key: ek,
            hmac_key: hk,
            header: Header(header),
            iv,
        })
    }

    pub fn cipher_text(&self, plain_text: &PlainText) -> Result<CipherText> {
        let iv = self.iv.to_vec();
        let key = self.encryption_key.to_vec();

        let encryptor = Aes256CbcEnc::new(key.as_slice().into(), iv.as_slice().into());
        let encrypted = encryptor.encrypt_padded_vec_mut::<NoPadding>(plain_text);

        Ok(CipherText(encrypted))
    }

    pub fn cipher_text_pkcs7(&self, plain_text: &PlainText) -> Result<CipherText> {
        let iv = self.iv.to_vec();
        let key = self.encryption_key.to_vec();

        let encryptor = Aes256CbcEnc::new(key.as_slice().into(), iv.as_slice().into());
        let encrypted = encryptor.encrypt_padded_vec_mut::<Pkcs7>(plain_text);

        Ok(CipherText(encrypted))
    }

    pub fn encrypt(&self, plain_text: &PlainText) -> Result<Message> {

        // If the input is empty, use the Pkcs7 padding as input.
        let cipher_text = match plain_text.is_empty() {
            true  => self.cipher_text(vec![16;16].as_slice())?,
            false => self.cipher_text_pkcs7(plain_text)?,
        };

        let CipherText(ref text) = cipher_text;

        let HMAC(hmac) = HMAC::new(&self.header, text.as_slice(), &self.hmac_key)?;

        let mut message = Vec::new();

        let Header(ref header) = self.header;
        message.extend(header.as_slice());
        message.extend(text);
        message.extend(hmac.as_slice());

        Ok(message)
    }
}
