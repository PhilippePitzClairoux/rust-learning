use hkdf::InvalidLength;
use aes_gcm::aead::Error as AeadError;
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum Crypto {
    #[error("could not perform encryption task")]
    EncryptionTaskFailed(#[from] AeadError),

    #[error("key derivation error")]
    KeyDerivationFailed(#[from] InvalidLength),

    #[error("file error")]
    FileOpFailed(#[from] std::io::Error),
}

#[derive(ThisError, Debug)]
pub enum File {
    #[error("could not manipulate file")]
    FileManipulationFailed(#[from] std::io::Error),

    #[error("could not open file")]
    FileOpenFailed,

    #[error("could not create file")]
    FileCreateFailed
}

#[derive(ThisError, Debug)]
pub enum Cryptor {
    #[error("could not perform encryption task")]
    EncryptionFailed(Crypto),

    #[error("could not manipulate file")]
    FileReadFailed(#[from] std::io::Error),

    #[error("could not encode chunk")]
    EncodeChunkFailed(#[from] bincode::error::EncodeError),

    #[error("could not decode chunk")]
    DecodeChunkFailed(#[from] bincode::error::DecodeError),

    #[error("could not read/write chunk")]
    ReadWriteChunkError(#[from] File),

    #[error("could not perform crypto operation")]
    CryptoFailed(#[from] Crypto),
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