use std::cmp::PartialEq;
use std::fs;
use std::fs::Metadata;
use rustware::{cryptor_engine, stream_encryption};
use clap::{arg, Parser, ValueEnum};
use std::path::Path;
use std::process::exit;
use rustware::cryptor_engine::{Engine, EngineGenerator};
use rustware::stream_encryption::EncryptedType;

#[derive(Debug, Clone, PartialEq,ValueEnum)]
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
    #[arg(index = 2, help="Input")]
    input: String,

    // Password used for encryption
    #[arg(index = 3, help="Password used for encryption/decryption")]
    password: String,

    #[arg(
        long,
        help="When true, directories will be walked recursively. Otherwise, use .tar archives",
        default_value_t = false)
    ]
    walk_directories: bool,

    #[arg(
        long,
        help="When true, will try to see if file is already encrypted. When false, encrypt no matter what.",
        default_value_t = true
    )]
    check_input_encryption_status: bool,
}

fn main() {
    let args = Args::parse();
    let input_is_encrypted = stream_encryption::is_encrypted(&args.input);
    let input_path = Path::new(&args.input);
    let input_info = fs::metadata(input_path).expect("could not read metadata");
    
    let engine_builder = cryptor_engine::EngineGeneratorBuilder::default()
        .build().expect("could not generate cryptor engine generator");

    if args.walk_directories {
        process_directory_files(&args, &input_path, engine_builder, args.action == Action::Encrypt);
        println!("Done!");
        return;
    } else {
        handle_as_file(&args, input_is_encrypted, input_path, input_info, engine_builder);
    }

    println!("Done {:?} {}", &args.action, &args.input);
}

fn handle_as_file(args: &Args, input_is_encrypted: bool, input_path: &Path, input_info: Metadata, engine_builder: EngineGenerator) {
    let encryption_type = match input_info.is_file() {
        true => EncryptedType::Raw,
        false => EncryptedType::Archive
    };
    let mut engine = engine_builder.engine_from_path(input_path)
        .expect("could not generate cryptor engine");

    match &args.action {
        Action::Encrypt => {
            if input_is_encrypted {
                println!("Input is encrypted - cannot encrypt twice...");
                exit(1);
            }

            encrypt_by_type(&args, encryption_type, &mut engine);
        }
        Action::Decrypt => {
            if !input_is_encrypted {
                println!("Input is decrypted - cannot decrypt twice...");
                exit(1);
            }

            engine.decrypt(&args.password)
                .expect("could not decrypt file");
        }
    }
}

fn encrypt_by_type(args: &&Args, encryption_type: EncryptedType, engine: &mut Engine) {
    match encryption_type {
        EncryptedType::Archive => { // the directory is transformed to an archive - so path becomes a file
            engine.encrypt_archive(&args.password)
                .expect("could not encrypt archive");
        }
        EncryptedType::Raw => {
            engine.encrypt_file(&args.password)
                .expect("could not encrypt file");
        }
    }
}

fn process_directory_files(args: &Args, input_file: &Path, engine_generator: EngineGenerator, encrypt: bool) {
    input_file.read_dir().expect("could not walk directory")
        .for_each(|entry| {
            let dir_entry = entry.expect("could not read entry");
            let mut engine = engine_generator.engine_from_path(dir_entry.path().as_path())
                .expect("could not generate engine generator");

            if encrypt {
                engine.encrypt_file(&args.password)
                    .expect("could not encrypt file");
            } else {
                engine.decrypt(&args.password)
                    .expect("could not encrypt file");
            }
        });
}