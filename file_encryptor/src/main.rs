use std::cmp::PartialEq;
use local_utils::{cryptor_engine, stream_encryption};
use clap::{arg, Parser, ValueEnum};
use std::path::Path;
use std::process::exit;
use local_utils::cryptor_engine::EngineGenerator;

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
        help="When true, directories will but put in a tar before encryption. When false, encrypt every file recursively",
        default_value_t = true)
    ]
    directory_as_tar: bool,

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
    let engine_builder = cryptor_engine::EngineGeneratorBuilder::default()
        .build().expect("could not generate cryptor engine generator");
    let mut engine = engine_builder.from_path(input_path)
        .expect("could not generate cryptor engine");


    match &args.action {
        Action::Encrypt => {
            if input_is_encrypted {
                println!("Input is encrypted - cannot encrypt twice...");
                exit(1);
            }

            match (input_path.is_file(), input_path.is_dir(), args.directory_as_tar) {
                (true, false, _) => {
                    engine.encrypt_file(&args.password)
                        .expect("could not encrypt file");
                }
                (false, true, false) => {
                    process_directory_files(&args, &input_path, engine_builder);
                }
                (false, true, true) => {
                    engine.encrypt_archive(&args.password)
                        .expect("could not encrypt archive");
                }
                _ => {
                    panic!("input file is a file and a directory at the same time???")
                }
            }
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

    println!("Done {:?} {}", &args.action, &args.input);
}


fn process_directory_files(args: &Args, input_file: &Path, engine_generator: EngineGenerator) {
    input_file.read_dir().expect("could not walk directory")
        .for_each(|entry| {
            let dir_entry = entry.expect("could not read entry");
            let mut engine = engine_generator.from_path(dir_entry.path().as_path())
                .expect("could not generate engine generator");

            engine.encrypt_file(&args.password)
                .expect("could not encrypt file");
        });
}