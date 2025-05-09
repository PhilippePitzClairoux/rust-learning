use std::convert::{TryInto};
use std::fs::{File};
use std::io::{BufReader, BufWriter, Cursor, Read, Write};
use bincode;
use local_utils::{crypto, files};
use clap::{CommandFactory, Parser};
use std::error::Error;
use std::fs;
use std::process::exit;
use serde::{Deserialize, Serialize};
use local_utils::crypto::{byte_vector_to_string, CryptoError};
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

    // Whether to encrypt or decrypt
    #[clap(short, long)]
    action: String
}

const SALT_SIZE: usize = 12;
const NONCE_SIZE: usize = 12;
const TOTAL_CHUNK_SIZE: usize = FILE_CHUNK_SIZE as usize + SALT_SIZE + NONCE_SIZE;
const ENCRYPTED_FILE_HEADER: &[u8;2] = &[0x43, 0x46]; // CF
type ChunkManipulation = fn(input: &[u8], passphrase: &str, salt: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CryptoError>;


#[derive(Serialize, Deserialize)]
struct CryptorFileHeader {
    #[serde(with = "serde_bytes")]
    header: Vec<u8>,

    #[serde(with = "serde_bytes")]
    salt: Vec<u8>,

    chunks: u64
}

impl CryptorFileHeader {
    // Create new CryptorFileHeader - nonce is disabled by default
    fn new() -> Self {
        Self {
            header: ENCRYPTED_FILE_HEADER.to_vec(),
            salt: crypto::generate_random_vector(SALT_SIZE).try_into().unwrap(),
            chunks: 0
        }
    }

    fn with_file_length(file_length: u64) -> Self {
        let tmp = CryptorFileHeader::new();
        Self {
            header: tmp.header,
            salt: tmp.salt,
            chunks: (file_length / TOTAL_CHUNK_SIZE as u64) + 1
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CryptorFileChunk {
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,

    #[serde(with = "serde_bytes")]
    data: Vec<u8>
}

impl CryptorFileChunk {
    fn new() -> Self {
        Self {
            nonce: crypto::generate_random_vector(NONCE_SIZE),
            data: vec![0u8; TOTAL_CHUNK_SIZE]
        }
    }

}

fn file_is_already_encrypted(file: &String) -> Result<bool, Box<dyn Error>> {
    let f = files::open_file(&file)?;
    let mut reader = BufReader::new(f);
    let mut buffer = [0u8; 2];

    reader.read_exact(&mut buffer)?;
    Ok(buffer.eq(ENCRYPTED_FILE_HEADER))
}

fn encrypt_file<InputType: Sized + Read, OutputType: Sized + Write>(
    input: &mut BufReader<InputType>,
    output: &mut BufWriter<OutputType>,
    password: &str,
    headers: &CryptorFileHeader) -> Result<(), Box<dyn Error>>
{
    bincode::serde::encode_into_std_write(
        headers, output, bincode::config::standard()
    )?;

    for _ in 0..headers.chunks {
        let chunk = files::read_chunk(input, FILE_CHUNK_SIZE as usize)?;
        let mut prepared_chunk = CryptorFileChunk::new();
        let transformed_chunk = crypto::encrypt_chunk(
            &chunk, password, headers.salt.as_slice(), prepared_chunk.nonce.as_slice()
        )?;

        prepared_chunk.data = transformed_chunk;

        bincode::serde::encode_into_std_write(
            prepared_chunk, output, bincode::config::standard()
        )?;
        output.flush()?;
    }

    Ok(())
}

// decrypt_file decrypts a file that was previously encrypted.
// CryptorFileHeader must be parsed beforehand - to validate the file is effectively
// encrypted by us. This also implies that input is at the start of the first chunk
fn decrypt_file<InputType: Sized + Read, OutputType: Sized + Write>(
    input: &mut BufReader<InputType>,
    output: &mut BufWriter<OutputType>,
    password: &str,
    headers: & CryptorFileHeader) -> Result<(), Box<dyn Error>>
{

    // write headers to output
    bincode::serde::encode_into_std_write(&headers, output, bincode::config::standard())?;
    output.flush()?;

    for _ in 0..headers.chunks {
        let chunk: CryptorFileChunk =
            bincode::serde::decode_from_std_read(input, bincode::config::standard())?;
        let decrypted_chunk =
            crypto::decrypt_chunk(&chunk.data, password, &headers.salt, &chunk.nonce)?;

        output.write_all(&decrypted_chunk)?;
        output.flush()?;
    }

    Ok(())
}


fn main() {
    let args = Args::parse();
    let mut input_file = files::open_file(&args.input).expect("could not open input file");
    let mut reader = BufReader::new(input_file.try_clone().unwrap());
    let mut output_file_name: String = args.output.clone();

    if args.output == APPEND_ENC_TO_INPUT {
        output_file_name = format!("{}.enc", &args.input);
    }

    let output_file: File = files::create_file(&output_file_name)
        .expect("could not create output file");
    let mut writer: BufWriter<File> = BufWriter::new(output_file.try_clone().unwrap());
    match args.action.as_str() {
        "encrypt" => {
            let encrypted = file_is_already_encrypted(&args.input)
                .expect("could not check if file was already encrypted");

            if encrypted {
                println!("{} is already encrypted!! Can't encrypt twice dummy...", &args.input);
                exit(1);
            }

            let metadata = input_file.metadata()
                .expect("could not fetch input file metadata");
            let cryptor_header = CryptorFileHeader::with_file_length(metadata.len());

            println!("Encrypting {} ({})", args.input, output_file_name);
            encrypt_file(&mut reader, &mut writer, args.password.as_str(), &cryptor_header)
                .expect("could not encrypt file");
        }
        "decrypt" => {
            let cryptor_header: CryptorFileHeader = bincode::serde::decode_from_std_read(
                &mut input_file, bincode::config::standard()
            ).expect("could not read input file cryptor header");

            if cryptor_header.header != ENCRYPTED_FILE_HEADER {
                println!("Are you sure {} is encrypted ? Check again dummy...", &args.input);
                exit(1);
            }
            let mut capture_output: BufWriter<Cursor<Vec<u8>>> = BufWriter::new(Cursor::new(Vec::new()));
            decrypt_file(&mut reader, &mut capture_output, &args.password, &cryptor_header)
                .expect("could not decrypt file");
        }
        _ => {
            println!("Unknown action: {}", args.action);
            Args::command().print_help().unwrap();
            exit(1);
        }
    }

    let output_metadata = fs::metadata(&output_file_name)
        .expect("could not read metadata of output file");
    println!("Done! Wrote {:?} bytes to {}", &output_metadata.len(), output_file_name);
}
