use std::io;
use aes_gcm::aes::cipher::crypto_common;
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error(transparent)]
    Crypto(#[from] Crypto),

    #[error(transparent)]
    File(#[from] File),

    #[error(transparent)]
    Cryptor(#[from] Cryptor),

    #[error(transparent)]
    CryptorEngine(#[from] CryptorEngine),

    #[error(transparent)]
    Tcp(#[from] Tcp),
    
    #[error(transparent)]
    IoError(#[from] io::Error),
}

#[derive(ThisError, Debug)]
pub enum Crypto {

    #[error("could not encrypt chunk")]
    EncryptFailed,

    #[error("could not decrypt chunk")]
    DecryptFailed,

    #[error("could not initialize cipher")]
    CipherInitializationFailed,

    #[error("could not derive key")]
    KeyDeriveFailed,
    
    #[error("invalid length")]
    InvalidKeyLength(#[from] crypto_common::InvalidLength)
}

#[derive(ThisError, Debug)]
pub enum File {
    #[error("could not manipulate file")]
    FileManipulationFailed(#[from] io::Error),

    #[error("could not open file")]
    FileOpenFailed,

    #[error("could not create file")]
    FileCreateFailed,

    #[error("could not read file")]
    FileReadFailed,
    
    #[error("could not create temp file")]
    TempFileCreationFailed,

    #[error("could not find file name")]
    FileNameNotFound,
    
    #[error("could not write to file")]
    FileWriteFailed,
}

#[derive(ThisError, Debug)]
pub enum Cryptor {
    #[error("could not perform encryption task")]
    CryptoError(Crypto),

    #[error("could not encode chunk")]
    EncodeChunkFailed(#[from] bincode::error::EncodeError),

    #[error("could not decode chunk")]
    DecodeChunkFailed(#[from] bincode::error::DecodeError),

    #[error("could not perform crypto operation")]
    CryptoFailed(#[from] Crypto),

    #[error("could not read chunk")]
    ChunkReadFailed,

    #[error("io error")]
    IOOperationFailed(#[from] io::Error),

    #[error("could not write chunk")]
    ChunkWriteFailed,

    #[error("file is not encrypted")]
    FileNotEncrypted,

    #[error("unexpected chunk type found")]
    UnexpectedChunk,

    #[error("stream flush failed")]
    StreamFlushFailed,

}

#[derive(ThisError, Debug)]
pub enum CryptorEngine {
    #[error("unexpected engine generator failure")]
    UnexpectedEngineGeneratorFailure,

    #[error("this is not suppose to happen...")]
    NoTempFileCreated,

    #[error("unexpected cryptor-rs failure")]
    UnexpectedCryptorFailure(#[from] Cryptor),

    #[error("unexpected file failure")]
    UnexpectedFileFailure(#[from] File),

    #[error("could not fetch file metadata")]
    FetchFileMetadataFailed,

    #[error("could not operate on file")]
    FileIOError(#[from] io::Error),

    #[error("file seek op failed")]
    FileSeekFailed,
}

#[derive(ThisError, Debug)]
pub enum Tcp {
    #[error("tcp connection closed")]
    ConnectionClosed,

    #[error("could not write tcp message")]
    SendMessageFailed,

    #[error("could not read tcp message")]
    ReadMessageFailed,
}