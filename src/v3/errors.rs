
use std::result::Result as StdResult;
use std;

pub type Result<T> = StdResult<T, Error>;

#[derive(Debug)]
pub enum ErrorKind {
    HMACValidationFailed,
    WrongInputSize(u8),
    IVGenerationFailed(std::io::Error),
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
