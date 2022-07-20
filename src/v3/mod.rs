
///! `Error` and `ErrorKind` types.
pub mod errors;
///! The types.
pub mod types;
///! "Low-level" encryption abstractions.
pub mod encryptor;
///! "Low-level" decryption abstractions.
pub mod decryptor;

use types::{Salt, IV, PlainText, Message};
use encryptor::{Encryptor};
use decryptor::{Decryptor};
use errors::{Result};

///! Encrypts a `PlainText` with the given password, producing either an encrypted
///! `Message` or an `Error` otherwise.
///!
///! **Note: This is NOT a streaming function.**
pub fn encrypt(password: &str, plain_text: &PlainText) -> Result<Message> {
    let esalt = Salt::new()?;
    let hsalt = Salt::new()?;
    let iv = IV::new()?;
    let encryptor = Encryptor::from_password(password, esalt, hsalt, iv)?;
    encryptor.encrypt(plain_text)
}

// TODO: Make API signature simmetric.
///! Decrypts a `Message` with the given password, producing either a decrypted
///! `Vec<u8>` or an `Error` otherwise.
///!
///! **Note: This is NOT a streaming function.**
pub fn decrypt(password: &str, message: &Message) -> Result<Vec<u8>> {
    let decryptor = Decryptor::from(password, message)?;
    decryptor.decrypt(message)
}
