use std;
use std::result::Result as StdResult;

pub type Result<T> = StdResult<T, Error>;

/// All the things which can go wrong :)
#[derive(Debug)]
pub enum ErrorKind {
    /// The generation of the HMAC failed.
    HMACGenerationFailed,
    /// The final check between the embedded HMAC and the computed one failed.
    HMACValidationFailed,
    /// The HMAC wasn't found inside the encrypted packed during decryption.
    HMACNotFound,
    /// The input size was wrong.
    WrongInputSize(usize),
    /// Not enough input for decryption.
    NotEnoughInput(usize),
    /// The IV generation failed.
    IVGenerationFailed(std::io::Error),
    /// The Salt generation failed.
    SaltGenerationFailed(std::io::Error),
    /// The decryption failed due to invalid padding.
    UnpadError,
}

#[derive(Debug)]
pub struct Error {
    pub message: String,
    pub kind: ErrorKind,
}

impl From<ErrorKind> for Error {
    fn from(e: ErrorKind) -> Error {
        Error {
            message: String::from("RNCryptor failed"),
            kind: e,
        }
    }
}

impl Error {
    pub fn new(k: ErrorKind, m: String) -> Error {
        Error {
            message: m,
            kind: k,
        }
    }
}
