use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use bincode;
use serde_big_array::BigArray;
use local_utils::{crypto, files};
use clap::{Parser};
use std::error::Error;
use serde::{Deserialize, Serialize};
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

    // Password used for encryption
    #[arg(short, long)]
    password: String,
}

const SALT_SIZE: usize = 12;
const NONCE_SIZE: usize = 12;
const TOTAL_CHUNK_SIZE: usize = FILE_CHUNK_SIZE as usize + SALT_SIZE + NONCE_SIZE;

#[derive(Serialize, Deserialize)]
struct CryptorFileHeader {
    salt: [u8; SALT_SIZE],

    #[serde(skip)]
    chunks: u64
}

impl CryptorFileHeader {
    // Create new CryptorFileHeader - nonce is disabled by default
    fn new() -> Self {
        Self {
            salt: crypto::generate_random_vector(SALT_SIZE).try_into().unwrap(),
            chunks: 0
        }
    }

    fn with_file_length(file_length: u64) -> Self {
        let tmp = CryptorFileHeader::new();
        Self {
            salt: tmp.salt,
            chunks: (file_length / TOTAL_CHUNK_SIZE as u64) + 1
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CryptorFileChunk {
    nonce: [u8; NONCE_SIZE],

    #[serde(with = "BigArray")]
    data: [u8; TOTAL_CHUNK_SIZE]
}

impl CryptorFileChunk {
    fn new() -> Self {
        Self {
            nonce: crypto::generate_random_vector(NONCE_SIZE).try_into().unwrap(),
            data: [0u8; TOTAL_CHUNK_SIZE]
        }
    }

}

fn encrypt_file(
    input: &mut BufReader<File>,
    output: &mut BufWriter<File>,
    password: &str,
    headers: &CryptorFileHeader) -> Result<(), Box<dyn Error>>
{
    bincode::serde::encode_into_std_write(
        headers, output, bincode::config::standard()
    )?;

    for _ in 0..headers.chunks {
        let chunk = files::read_chunk(input, FILE_CHUNK_SIZE as usize)?;
        let mut prepared_chunk = CryptorFileChunk::new();

        prepared_chunk.data =
            crypto::encrypt_chunk(
                &chunk, password, headers.salt.as_slice(), prepared_chunk.nonce.as_slice()
            )?.try_into()?;

        bincode::serde::encode_into_std_write(
            prepared_chunk, output, bincode::config::standard()
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
    let metadata = input_file.metadata().expect("could not read metadata of input file");
    let cryptor_header =
        CryptorFileHeader::with_file_length(metadata.len());

    encrypt_file(&mut reader, &mut writer, args.password.as_str(), &cryptor_header)
        .expect("could not encrypt file");

    output_file.sync_all().expect("could not sync output file");
    let output_metadata = output_file.metadata()
        .expect("could not read metadata of output file");

    println!("Done! Wrote {} bytes to {}", output_metadata.len(), output_file_name);
}
