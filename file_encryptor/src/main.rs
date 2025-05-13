use std::cmp::PartialEq;
use std::fs::{File, Metadata};
use std::io::{BufReader, BufWriter};
use local_utils::{files, cryptor};
use clap::{Parser, ValueEnum};
use std::fs;
use std::path::Path;
use std::process::exit;
use tempfile::NamedTempFile;
use local_utils::cryptor::{Context, EncryptedType};

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
    let input_file_info = fs::metadata(args.input.as_str())
        .expect("Input not found!");
    let input_is_encrypted = cryptor::is_encrypted(&args.input);

    match &args.action {
        Action::Encrypt => {
            if input_is_encrypted {
                println!("Input is encrypted - cannot encrypt twice...");
                exit(1);
            }

            if input_file_info.is_dir() && args.directory_as_tar {
                encrypt_directory_as_tar()
            } else if input_file_info.is_dir() {
                encrypt_directory_files()
            } else if input_file_info.is_file() {
                encrypt_file(&args, &args.input);
            } else {
                panic!("unknowned file type")
            }
        }
        Action::Decrypt => {
            if !input_is_encrypted {
                println!("Input is decrypted - cannot decrypt twice...");
                exit(1);
            }

            decrypt_file(&args);
        }
    }

    println!("Done {:?} {}", &args.action, &args.input);
}

fn encrypt_file(args: &Args, input_file: &String) {
    let output = create_temp_file();
    let input = File::open(input_file).expect("could not open input file");

    let mut reader = BufReader::new(&input);
    let mut writer = BufWriter::new(&output);

    let ctx = Context::new();
    ctx.encrypt_file(&mut reader, &mut writer, &args.password)
        .expect("could not decrypt file");

    files::replace_file(&mut BufWriter::new(&input), &mut BufReader::new(&output))
        .expect("could not override input file with output file");
}

fn decrypt_file(args: &Args) {
    let output = create_temp_file();
    let input = File::open(&args.input)
        .expect("could not open input");

    let mut output_writer = BufWriter::new(&output);
    let mut input_reader = BufReader::new(&input);
    let mut ctx = Context::from_encrypted_source(&mut input_reader)
        .expect("could not initialize cryptor context");


    println!("Decrypting {}...", &args.input);
    ctx.decrypt_file(&mut input_reader, &mut output_writer, &args.password)
        .expect("could not decrypt file");

    files::replace_file(&mut BufWriter::new(&input), &mut BufReader::new(&output))
        .expect("could not override input file with output file");

    // post decryption task
    match ctx.get_encrypted_type() {
        EncryptedType::File => { /* nothing for now */ }
        EncryptedType::ArchivedDirectory => {
            extract_archive(&args.input.to_string());
        }
        EncryptedType::Undefined => {
            panic!("undefined encrypted file type!")
        }
    }
}
fn process_directory_files(args: &Args) {
    fs::read_dir(&args.input).expect("could not walk directory")
        .for_each(|entry| {
            let input_file = String::from(
                entry.expect("could get directory entry").path().to_str()
                    .expect("could not convert path to string")
            );

            encrypt_file(&args, &input_file);
        });
}

fn extract_archive(path: &String) {
    let file = files::open_file(path)
        .expect("could not open tar file");
    let mut decrypted_archive = tar::Archive::new(file);

    decrypted_archive.unpack(path.clone().replace(".tar", ""))
        .expect("could not unpack tar archive");

    fs::remove_file(path).expect("could not remove old file");
}

fn archive_directory(path: &str) -> String {
    let input_file_name= format!("{}.tar", path.clone());
    let mut archive = tar::Builder::new(
        files::create_file(&input_file_name.to_string()).expect("could not create archive output")
    );

    archive.append_dir_all("", &path)
        .expect("could not append files to archive");
    archive.finish().expect("could not finish archive");

    input_file_name.to_owned()
}

fn create_temp_file() -> File {

    tempfile::tempfile().expect("could not create temp file")
}