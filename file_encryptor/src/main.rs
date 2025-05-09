use std::convert::{TryInto};
use std::fs::{File, Metadata};
use std::io::{BufReader, BufWriter};
use bincode;
use local_utils::{files, cryptor};
use clap::{Parser, ValueEnum};
use std::fs;
use std::process::exit;

#[derive(Debug, Clone, ValueEnum)]
enum Action {
    Encrypt,
    Decrypt
}

#[derive(Parser, Debug)]
#[command(
    name = "cryptor",
    version = "1.0",
    author = "an0nym00s3",
    about = "Encrypt/Decrypt files to protect your data!"
)]
struct Args {
    // Whether to encrypt or decrypt
    #[arg(value_enum, help="Whether to encrypt and decrypt files")]
    action: Action,

    // Path to input file
    #[arg(index = 2, help="Input file")]
    input: String,

    // Password used for encryption
    #[arg(index = 3, help="Password used for encryption/decryption")]
    password: String,

    // Output file name
    #[arg(long, required = false, help="Where to output file - will override input if output is empty")]
    output: Option<String>,
}

fn encrypt_file(args: &Args, encrypted: &mut BufReader<File>, output_file_name: &String, mut writer: &mut BufWriter<File>) {
    let is_encrypted = cryptor::file_is_already_encrypted(&args.input)
        .expect("could not check if file was already encrypted");

    if is_encrypted {
        println!("{} is already encrypted!! Can't encrypt twice dummy...", &args.input);
        exit(1);
    }

    let metadata = fs::metadata(&args.input)
        .expect("could not fetch input file metadata");

    let mut ctx = cryptor::Context::from(
        cryptor::HeaderChunk::with_file_length(metadata.len())
    );

    println!("Encrypting {} ({})", args.input, output_file_name);
    ctx.encrypt_file(encrypted, writer, args.password.as_str())
        .expect("could not encrypt file");
}

fn main() {
    let args = Args::parse();

    // input file (read from here)
    let mut input_file = files::open_file(&args.input).expect("could not open input file");

    // create a reader to read from input file
    let mut reader = BufReader::new(input_file.try_clone().unwrap());

    // decide if we replace input with output
    let in_place = args.output.is_none();

    // get the output filename (if none is provided, take input and append .enc)
    let output_file_name =
        args.output.clone()
            .unwrap_or_else(|| format!("{}.enc", &args.input));

    // create output file
    let output_file: File = files::create_file(&output_file_name)
        .expect("could not create output file");

    // create a bufwriter to append data to the output file
    let mut writer: BufWriter<File> =
        BufWriter::new(output_file.try_clone().unwrap());

    match args.action {
        Action::Encrypt => {
            encrypt_file(&args, &mut reader, &output_file_name, &mut writer);

        }
        Action::Decrypt => {
            let mut ctx = cryptor::Context::new();
            ctx.decrypt_file(&mut reader, &mut writer, &args.password)
                .expect("could not decrypt file");

        }
    }


    let output_metadata: Metadata;
    if in_place {
        files::replace_file(&args.input, &output_file_name)
            .expect("could not replace input file with output file");

        output_metadata = fs::metadata(&args.input)
            .expect("could not read output file");

    } else {
        output_metadata = fs::metadata(&output_file_name)
            .expect("could not read output file");

    }

    println!("Done! Wrote {:?} bytes to {}", &output_metadata.len(), output_file_name);
}

