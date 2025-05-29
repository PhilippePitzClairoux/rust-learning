use std::env;
use std::fs::File;
use std::path::{Path, PathBuf};
use derive_builder::Builder;
use tempfile::NamedTempFile;
use crate::{archives, files};
use crate::files::{create_temp_file, replace_file, safe_get_parent};
use crate::stream_encryption::{decrypt_stream, encrypt_stream, EncryptedType, HeaderChunk};
use crate::errors::Cryptor as CryptorError;


#[derive(Builder)]
pub struct EngineGenerator {
    config: Option<bincode::config::Configuration>,
    header_chunk: Option<HeaderChunk>,
}

impl EngineGenerator {
    pub fn from_path(&self, input_file_path: &Path) -> Result<Engine, CryptorError> {
        let mut engine =match input_file_path.is_file() {
            true => {
                Engine::try_from_file(input_file_path)?
            }
            false => {
                Engine::try_with_archive(input_file_path)?
            }
        };

        if self.config.is_some() {
            engine.config =
                self.config.ok_or(CryptorError::UnexpectedEngineGeneratorFailure)?;
        }

        if self.header_chunk.is_some() {
            engine.header_chunk = self.header_chunk.clone()
                    .ok_or(CryptorError::UnexpectedEngineGeneratorFailure)?;
        }

        Ok(engine)
    }
}

pub struct Engine {
    config: bincode::config::Configuration,
    header_chunk: HeaderChunk,
    temp_file: NamedTempFile,
    input_file: File,
    input_file_path: PathBuf,
}

impl Engine {

    pub fn try_from_file(input_file_path: &Path) -> Result<Self, crate::errors::Cryptor> {
        let tmp_file = create_temp_file(
            safe_get_parent(&input_file_path).as_path()
        )?;

        let length = input_file_path.metadata()
            .map_err(|_| crate::errors::Cryptor::FetchFileMetadataFailed)?
            .len();
        let h = HeaderChunk::with_file_length(length);

        Ok(
            Self {
                header_chunk: h,
                config: bincode::config::standard(),
                temp_file: tmp_file,
                input_file: File::options()
                    .read(true)
                    .create(false)
                    .open(input_file_path)?,
                input_file_path: input_file_path.clone().to_path_buf()
            }
        )
    }

    pub fn try_with_archive(input_directory_path: &Path) -> Result<Self, crate::errors::Cryptor> {
        let input_file = files::archive(input_directory_path)?;
        let tmp_file = create_temp_file(
            safe_get_parent(input_directory_path).as_path()
        )?;


        Ok (
            Self {
                config: bincode::config::Configuration::default(),
                header_chunk: HeaderChunk::new(),
                temp_file: tmp_file,
                input_file_path: input_file.path().to_path_buf(),
                input_file: input_file.into_file(),
            }
        )
    }

    pub fn load_header(&mut self, header: &HeaderChunk) {
        self.header_chunk = header.clone();
    }

    pub fn encrypt_archive(&mut self, password: &str) -> Result<(), CryptorError> {
        self.encrypt(password, EncryptedType::Archive)
    }

    pub fn encrypt_file(&mut self, password: &str) -> Result<(), CryptorError> {
        self.encrypt(password, EncryptedType::Raw)
    }

    fn encrypt(&mut self, password: &str, t: EncryptedType) -> Result<(), CryptorError> {
        self.header_chunk.set_filetype(t);
        encrypt_stream(
            &mut self.input_file,
            &mut self.temp_file,
            password,
            &self.header_chunk,
            &self.config
        )
    }
    pub fn decrypt(&mut self, password: &str) -> Result<(), crate::errors::Cryptor> {
        let header = decrypt_stream(
            &mut self.input_file,
            self.temp_file.as_file_mut(),
            password,
            &self.config
        )?;

        // post decryption jobs
        match header.get_filetype() {
            EncryptedType::Archive => {
                files::extract_archive(self.input_file_path.as_path())?;
            }
            _ => {
                replace_file(self.temp_file.path(), self.input_file_path.as_path())?;
            }
        }
        
        Ok(())
    }
}
