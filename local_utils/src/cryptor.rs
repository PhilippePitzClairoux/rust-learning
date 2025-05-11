use std::error::Error;
use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use serde::{Serialize, Deserialize};
use bincode::serde::{encode_into_std_write, decode_from_std_read};

use crate::{crypto, files};
use crate::errors::Cryptor as CryptorError;
use crate::files::{read_chunk, FILE_CHUNK_SIZE};

pub const SALT_SIZE: usize = 12;
pub const NONCE_SIZE: usize = 12;
pub const TOTAL_CHUNK_SIZE: usize = FILE_CHUNK_SIZE as usize + SALT_SIZE + NONCE_SIZE;
pub const ENCRYPTED_FILE_HEADER: &[u8;2] = &[0x43, 0x46]; // CF

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HeaderChunk {
    #[serde(with = "serde_bytes")]
    pub header: Vec<u8>,

    #[serde(with = "serde_bytes")]
    salt: Vec<u8>,

    chunks: u64
}

impl HeaderChunk {
    // Create new CryptorFileHeader - nonce is disabled by default
    pub fn new() -> Self {
        Self {
            header: ENCRYPTED_FILE_HEADER.to_vec(),
            salt: crypto::generate_random_vector(SALT_SIZE).try_into().unwrap(),
            chunks: 0
        }
    }

    pub fn from_ctx(ctx: &Context) -> Self {
        Self {
            header: ENCRYPTED_FILE_HEADER.to_vec(),
            salt: ctx.salt.clone(),
            chunks: ctx.chunks
        }
    }
    pub fn from(header: &[u8], salt: &[u8], chunks: u64) -> Self {
        Self {
            header: header.clone().to_vec(),
            salt: salt.clone().to_vec(),
            chunks
        }
    }

    pub fn with_file_length(file_length: u64) -> Self {
        let tmp = HeaderChunk::new();
        Self {
            header: tmp.header,
            salt: tmp.salt,
            chunks: (file_length / TOTAL_CHUNK_SIZE as u64) + 1
        }
    }
}

#[derive(Clone, Debug, PartialEq,serde::Serialize, serde::Deserialize)]
pub struct Chunk {
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,

    #[serde(with = "serde_bytes")]
    data: Vec<u8>
}

impl Chunk {
    pub fn new() -> Self {
        Self {
            nonce: crypto::generate_random_vector(NONCE_SIZE),
            data: vec![0u8; TOTAL_CHUNK_SIZE]
        }
    }

    pub fn from(data: Vec<u8>) -> Self {
        Self {
            nonce: crypto::generate_random_vector(NONCE_SIZE),
            data
        }
    }

    pub fn encrypt(&mut self, password: &str, salt: &[u8]) -> Result<(), CryptorError> {
        self.data = crypto::encrypt_chunk(
            &self.data, password, salt, &self.nonce
        )?;

        Ok(())
    }

    pub fn decrypt(&mut self, password: &str, salt: &[u8]) -> Result<(), CryptorError> {
        self.data = crypto::decrypt_chunk(
            &self.data.clone(), password, salt, &self.nonce
        )?;

        Ok(())
    }

}

#[derive(Debug, Clone, PartialEq,serde::Serialize, serde::Deserialize)]
pub enum ChunkType {
    Header(HeaderChunk),
    Data(Chunk),
}

pub fn write_encoded_chunk<W>(
    writer: &mut W,
    chunk: &ChunkType,
    config: &bincode::config::Configuration
) -> Result<(), CryptorError>
where
    W: Write,
{
    let _ = encode_into_std_write(chunk, writer, config.clone())?;
    Ok(())
}

pub fn read_decoded_chunk<R>(
    reader: &mut R,
    config: &bincode::config::Configuration
) -> Result<ChunkType, CryptorError>
where
    R: Read
{
    let chunk: ChunkType = decode_from_std_read(reader, config.clone())?;
    Ok(chunk)
}

pub struct Context {
    salt: Vec<u8>,
    chunks: u64,
    config: bincode::config::Configuration,
}

impl Context {
    pub fn new() -> Self {
        let h = HeaderChunk::new();
        Self {
            salt: h.salt,
            chunks: 1,
            config: bincode::config::standard(),
        }
    }

    pub fn from_header(header: HeaderChunk) -> Self {
        Self {
            salt: header.salt.clone(),
            chunks: header.chunks,
            config: bincode::config::standard(),
        }
    }

    pub fn from_file_path(path: &str) -> Result<Self, CryptorError> {
        let metadata = fs::metadata(path)?;
        Ok(Self {
            salt: crypto::generate_random_vector(SALT_SIZE),
            config: bincode::config::standard(),
            chunks: metadata.len() / FILE_CHUNK_SIZE,
        })
    }

    pub fn from_encrypted_source<T: Read>(reader: &mut T) -> Result<Self, CryptorError> {
        let mut s = Self::new();
        s.load_header_from_reader(reader)?;
        Ok(s)
    }

    pub fn load_header(&mut self, header: &HeaderChunk) {
        self.salt = header.salt.clone();
        self.chunks = header.chunks;
    }

    pub fn load_header_from_reader(&mut self, reader: &mut impl Read) -> Result<(), CryptorError> {
        let header: ChunkType = read_decoded_chunk(reader, &self.config)?;
        match header {
            ChunkType::Header(header) => {
                self.load_header(&header);

                if header.header.ne(&ENCRYPTED_FILE_HEADER) {
                    panic!("wrong header type")
                }
            },
            // TODO : replace with custom error
            _ => panic!("invalid chunk type found (requires header)")
        }

        Ok(())
    }

    pub fn encrypt_file<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
        password: &str
    ) -> Result<(), CryptorError>
    where
        R: Read,
        W: Write
    {
        write_encoded_chunk(
            writer, &ChunkType::Header(HeaderChunk::from_ctx(&self)), &self.config
        )?;

        for _ in 0..self.chunks {
            // read a chunk
            let mut chunk = Chunk::from(
                read_chunk(reader, FILE_CHUNK_SIZE as usize)?
            );

            // decrypt chunk
            chunk.encrypt(&password, &self.salt)?;

            write_encoded_chunk(writer, &ChunkType::Data(chunk), &self.config)?;
        }

        Ok(())
    }

    pub fn decrypt_file<R, W>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        password: &str,
    ) -> Result<(), CryptorError>
    where
        R: Read,
        W: Write
    {

        self.load_header_from_reader(reader)?;

        for _ in 0..self.chunks {


            for _ in 0..self.chunks {
                // read chunk
                match read_decoded_chunk(reader, &self.config) {
                    Ok(ChunkType::Data(mut chunk)) => {
                        // encrypt chunk
                        chunk.decrypt(&password, &self.salt)?;

                        // output chunk
                        writer.write_all(&chunk.data)?;
                        writer.flush()?;
                    }
                    Ok(ChunkType::Header(_)) => panic!("invalid chunk type found (requires Data)"),
                    Err(e) => panic!("error loading chunk: {}", e)
                }
            }
        }

        Ok(())
    }
}

pub fn file_is_already_encrypted(file: &String) -> Result<bool, CryptorError> {
    let f = files::open_file(&file)?;
    let mut reader = BufReader::new(f);
    let mut buffer = [0u8; 2];

    reader.read_exact(&mut buffer)?;
    Ok(buffer.eq(ENCRYPTED_FILE_HEADER))
}

#[cfg(test)]
mod test {
    use std::io::{Cursor, Seek};
    use crate::test_common as common;
    use super::*;

    const CONFIG: bincode::config::Configuration =
        bincode::config::standard();

    const ENCODED_CRYPTOR_HEADER: &[u8] =
        &[0, 2, 67, 70, 12, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 1];


    #[test]
    fn encode_decode_decrypt_test() {
        let header: ChunkType = ChunkType::Header(
            HeaderChunk::from(ENCRYPTED_FILE_HEADER, common::SALT, 1)
        );

        let mut writer = Cursor::new(Vec::new());

        write_encoded_chunk(
            &mut writer, &header, &CONFIG
        ).expect("could not process chunk");

        writer.seek(std::io::SeekFrom::Start(0)).unwrap();
        let decoded: ChunkType = read_decoded_chunk(&mut writer, &CONFIG)
                .expect("could not decode chunk");

        assert_eq!(decoded, header);
        assert_eq!(ENCODED_CRYPTOR_HEADER, writer.into_inner());
        println!("Header was encoded and decoded and matched the const version")
    }

}