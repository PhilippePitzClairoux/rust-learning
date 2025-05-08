use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use bincode;
use std::ops::Add;
use local_utils::{crypto, files};
use clap::{Parser};
use std::error::Error;
use serde::Serialize;
use local_utils::files::FILE_CHUNK_SIZE;

const APPEND_ENC_TO_INPUT: &str = "APPEND_ENC";

#[derive(Parser, Debug)]
struct Args {
    // Path to input file
    #[arg(short, long)]
    input: String,

    // Output file name
    #[arg(short, long, default_value = APPEND_ENC_TO_INPUT)]
    output: String,

    // Chunk size
    #[arg(short, long, default_value_t = files::FILE_CHUNK_SIZE)]
    chunk_size: u64,

    // Password used for encryption
    #[arg(short, long)]
    password: String,
}

const SALT_SIZE: usize = 12;
const NONCE_SIZE: usize = 12;

#[derive(serde::Serialize, serde::Deserialize)]
struct CryptorFileHeader {
    salt: [u8; SALT_SIZE],
    use_nonce: bool,
    max_chunk_size: u64,

    #[serde(skip_serializing, skip_deserializing)]
    chunks: u64
}

impl CryptorFileHeader {
    // Create new CryptorFileHeader - nonce is disabled by default
    fn new() -> Self {
        Self {
            salt: crypto::generate_random_vector(SALT_SIZE).into(),
            use_nonce: false,
            max_chunk_size: 0,
            chunks: 0
        }
    }

    fn from(use_nonce: bool) -> Self {
        let mut size = FILE_CHUNK_SIZE + SALT_SIZE as u64;
        if use_nonce {
            size.add(NONCE_SIZE as u64);
        }

        Self {
            salt: crypto::generate_random_vector(SALT_SIZE).into(),
            use_nonce,
            max_chunk_size: size,
            chunks: 0
        }
    }

    fn with_file_length(use_nonce: bool, file_length: u64) -> Self {
        Self::from(use_nonce);
        Self.chunks = (file_length / Self.max_chunk_size) + 1;
        Self
    }

    fn set_nonce(&mut self, nonce: bool) {
        if nonce {
            self.use_nonce = true;
            self.max_chunk_size = FILE_CHUNK_SIZE + SALT_SIZE as u64 + NONCE_SIZE as u64;
        } else {
            self.use_nonce = false;
            self.max_chunk_size = FILE_CHUNK_SIZE + SALT_SIZE as u64;
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CryptorFileChunk {
    nonce: [u8; NONCE_SIZE],
    data: Vec<u8>
}

impl CryptorFileChunk {
    fn new() -> Self {
        Self {
            nonce: [0; NONCE_SIZE],
            data: Vec::new()
        }
    }

    fn with_cryptor_file_header(header: &CryptorFileHeader) -> Self {
        let nonce:[u8;NONCE_SIZE];
        if header.use_nonce {
            nonce = crypto::generate_random_vector(NONCE_SIZE).into();
        } else {
            nonce = vec![0u8; NONCE_SIZE].into();
        }

        Self {
            nonce,
            data: Vec::with_capacity(header.max_chunk_size as usize - NONCE_SIZE)
        }
    }

    fn set_nonce(&mut self, nonce: &[u8]) {
        self.nonce.copy_from_slice(nonce);
    }

}

fn encrypt_file(
    input: &mut BufReader<File>,
    output: &mut BufWriter<File>,
    password: &str,
    headers: &CryptorFileHeader) -> Result<(), Box<dyn Error>>
{
    bincode::serde::encode_into_writer(
        headers, output.into(), bincode::config::standard()
    )?;

    for _ in 0..headers.chunks {
        let chunk = files::read_chunk(input, headers.max_chunk_size as usize)?.as_slice();
        let mut prepared_chunk = CryptorFileChunk::with_cryptor_file_header(headers);

        prepared_chunk.data =
            crypto::encrypt_chunk(
                chunk, password, headers.salt.as_slice(), prepared_chunk.nonce.as_slice()
            )?.into();

        bincode::serde::encode_into_writer(
            prepared_chunk, output.into(), bincode::config::standard()
        )?;
    }

    Ok(())
}


fn main() {
    let args = Args::parse();
    let input_file = files::open_file(&args.input).expect("could not open input file");
    let mut reader = BufReader::new(input_file.try_clone().unwrap());
    let mut output_file_name: String = args.output.clone();

    if args.output == APPEND_ENC_TO_INPUT {
        output_file_name = format!("{}.enc", &args.input);
    }

    println!("Encrypting {} ({})", args.input, output_file_name);
    let output_file: File = files::create_file(&output_file_name)
        .expect("could not create output file");
    let mut writer: BufWriter<File> = BufWriter::new(output_file.try_clone().unwrap());
    let salt = crypto::generate_random_vector(SALT_SIZE);

    let metadata = input_file.metadata().expect("could not read metadata of input file");
    let cryptor_header = CryptorFileHeader::with_file_length(true, metadata.len()
    );
    // write salt to output file
    writer.write_all(&salt).expect("could not write salt to output file");
    writer.flush().expect("could not flush output file");

    println!("Input file length : {} bytes, Total number of chunks : {}", metadata.len(), cryptor_header.chunks);
    for _ in 0..cryptor_header.chunks {
        let chunk = files::read_chunk(&mut reader, args.chunk_size as usize)
           .expect("could not read chunk");
        let nonce = crypto::generate_random_vector(12);

        let encrypted_chunk = crypto::encrypt_chunk(chunk.as_slice(),
                                                   &args.password,
                                                   &salt,
                                                   &nonce,
        ).expect("could not encrypt chunk");

        let mut output_chunk: Vec<u8> = Vec::new();
        output_chunk.append(nonce.clone().by_ref());
        output_chunk.append(encrypted_chunk.clone().by_ref());
        
        println!("Writing encrypted chunk {} bytes (original = {} bytes)", output_chunk.len(), chunk.len());
        files::write_chunk(&mut writer, output_chunk.as_slice())
            .expect("could not write chunk");
        writer.flush().expect("could not flush writer");
    }

    output_file.sync_all().expect("could not sync output file");
    let output_metadata = output_file.metadata()
        .expect("could not read metadata of output file");

    println!("Done! Wrote {} bytes to {}", output_metadata.len(), output_file_name);
}
