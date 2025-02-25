use super::errors::{Error, ErrorKind, Result};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    num::NonZeroU32,
    result::Result as StdResult,
};

type HmacSha256 = Hmac<Sha256>;

/// An `EncryptionKey`, which can be constructed from a `EncryptionSalt` and a password.
#[derive(Clone, Debug)]
pub struct EncryptionKey(Vec<u8>);

impl<'a> EncryptionKey {
    /// Creates a new `EncryptionKey` out of an `EncryptionSalt` and a password.
    pub fn new(encryption_salt: &EncryptionSalt, password: &'a [u8]) -> EncryptionKey {
        EncryptionKey(new_key_with_salt(encryption_salt, password))
    }

    pub fn from(raw_key: Vec<u8>) -> EncryptionKey {
        EncryptionKey(raw_key)
    }

    pub fn to_vec(&self) -> &Vec<u8> {
        let EncryptionKey(ref v) = *self;
        v
    }
}

/// A `Salt`, which can be completely random or user-constructed.
#[derive(Clone, Debug)]
pub struct Salt(pub Vec<u8>);

impl Salt {
    /// Creates a new, completely random `Salt` of 8 bytes.
    pub fn new() -> Result<Salt> {
        match random_data_of_len(8) {
            Err(e) => Err(Error::new(
                ErrorKind::SaltGenerationFailed(e),
                "Salt Generation failed.".to_owned(),
            )),
            Ok(v) => Ok(Salt(v)),
        }
    }

    /// Turns a `Salt` into a `[u8]` slice.
    pub fn as_slice(&self) -> &[u8] {
        let Salt(ref s) = *self;
        s
    }
}

/// A `HMACKey`, which can be constructed from an `HMACSalt` and a password.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HMACKey(Vec<u8>);

fn new_key_with_salt(salt: &Salt, password: &[u8]) -> Vec<u8> {
    use ring::pbkdf2::{derive, PBKDF2_HMAC_SHA1};

    let Salt(ref salt) = *salt;
    let mut result = vec![0;32];

    let iterations = NonZeroU32::new(10_000).expect("zero iterations when non-zero OwO");
    derive(PBKDF2_HMAC_SHA1, iterations, &salt[..], password, &mut result);

    result
}

impl<'a> HMACKey {
    pub fn new(hmac_salt: &Salt, password: &'a [u8]) -> HMACKey {
        HMACKey(new_key_with_salt(hmac_salt, password))
    }

    pub fn from(raw_key: Vec<u8>) -> HMACKey {
        HMACKey(raw_key)
    }
}

/// A RNCryptor `Header` built during the encryption/decryption process.
#[derive(Clone, Debug)]
pub struct Header(pub Vec<u8>);

/// An `IV` (Initialization Vector) which can be completely random or user constructed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IV(Vec<u8>);

impl Display for IV {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match *self {
            IV(ref v) => write!(f, "{:?}", v),
        }
    }
}

/// A password.
pub type Password = [u8];
/// A plain text, which is something not encrypted.
pub type PlainText = [u8];
// TODO: Can we make CipherText & Message to be isomorphic?
/// An encrypted message, the result of the encryption process.
pub type Message = Vec<u8>;

fn random_data_of_len(size: usize) -> StdResult<Vec<u8>, std::io::Error> {
    let mut data = vec![0; size];
    OsRng.try_fill_bytes(&mut data)?;
    Ok(data)
}

impl IV {
    /// Creates a new, completely random `IV` (Initialization Vector) of 16 bytes.
    pub fn new() -> Result<IV> {
        match random_data_of_len(16) {
            Err(e) => Err(Error::new(
                ErrorKind::IVGenerationFailed(e),
                "IV Generation failed.".to_owned(),
            )),
            Ok(v) => Ok(IV(v)),
        }
    }

    /// Creates a new `IV` (Initialization Vector) from a `Vec<u8>`. It's your responsibility
    /// to ensure the `IV` is random and of 16 bytes.
    pub fn from(raw_key: Vec<u8>) -> IV {
        IV(raw_key)
    }

    /// Turns the `IV` into a `[u8]` slice.
    pub fn as_slice(&self) -> &[u8] {
        let IV(ref s) = *self;
        s
    }

    /// Turns the `IV` into a `Vec<u8>` vector.
    pub fn to_vec(&self) -> &Vec<u8> {
        let IV(ref v) = *self;
        v
    }
}

/// An `CipherText`, essentially a wrapper around a `Vec<u8>`.
#[derive(Debug)]
pub struct CipherText(pub Vec<u8>);

/// An `HMAC`, which can be constructed out of an `Header`, some bytes and an `HMACKey`.
#[derive(Debug)]
pub struct HMAC(pub Vec<u8>);

impl HMAC {
    pub fn new(&Header(ref h): &Header, txt: &[u8], &HMACKey(ref key): &HMACKey) -> Result<HMAC> {
        let mut input = Vec::new();
        input.extend(h);
        input.extend(txt);

        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|error| Error::new(ErrorKind::HMACGenerationFailed, error.to_string()))?;
        mac.update(&input);

        let result = mac.finalize().into_bytes().to_vec();
        Ok(HMAC(result))
    }

    pub fn is_equal_in_consistent_time_to(&self, &HMAC(ref other): &HMAC) -> bool {
        let HMAC(ref this) = *self;
        this.iter()
            .zip(other.iter())
            .fold(true, |acc, (x, y)| acc && (x == y))
    }
}

/// Simply  a type synonym for a `Salt`, to make the API more descriptive.
pub type EncryptionSalt = Salt;
/// Simply  a type synonym for a `Salt`, to make the API more descriptive.
pub type HMACSalt = Salt;
