use std::io::Error as IoError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthorizationError {
    #[error("io error")]
    IoError(#[from] IoError),
}
