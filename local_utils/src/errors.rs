use thiserror::Error as ThisError;

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

    #[error("could not encode chunk")]
    EncodeChunkFailed(#[from] bincode::error::EncodeError),

    #[error("could not decode chunk")]
    DecodeChunkFailed(#[from] bincode::error::DecodeError),

    #[error("could not perform crypto operation")]
    CryptoFailed(#[from] Crypto),

    #[error("could not read chunk")]
    ChunkReadFailed,

    #[error("file error")]
    FileError(File),

    #[error("file write error")]
    FileWriteFailed,

    #[error("could not write chunk")]
    ChunkWriteFailed,

    #[error("file is not encrypted")]
    FileNotEncrypted,

    #[error("unexpected chunk type found")]
    UnexpectedChunk,

    #[error("could not fetch file metadata")]
    FetchFileMetadataFailed,
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