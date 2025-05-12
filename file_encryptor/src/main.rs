use std::cmp::PartialEq;
use std::fs::{File};
use std::io::{BufReader, BufWriter};
use local_utils::{files, cryptor};
use clap::{Parser, ValueEnum};
use std::fs;
use std::path::Path;
use std::process::exit;

#[derive(Debug, Clone, PartialEq,ValueEnum)]
enum Action {
    Encrypt,
    Decrypt
}

#[derive(Debug, Clone, ValueEnum)]
enum Type {
    File,
    Directory
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

    #[arg(value_enum, long, required=false, help="Define the type of <input> (file, directory, etc...)",
        default_value_t=Type::File)]
    input_type: Type,

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
        .expect("Input file not found!");

    match &args.input_type {
        Type::Directory => {
            if !input_file_info.is_dir() {
                println!("Input file is not a directory!");
                exit(1);
            }

            match &args.directory_as_tar {
                true => {
                    let input_file_name = format!("{}.tar", &args.input);

                    if args.action.eq(&Action::Encrypt) {
                        let mut archive = tar::Builder::new(
                            files::create_file(&input_file_name).expect("could not create archive output")
                        );

                        archive.append_dir_all("", &args.input)
                            .expect("could not append files to archive");
                        archive.finish().expect("could not finish archive");
                    }

                    handle_cryptor_file(&args, &input_file_name);

                    if args.action.eq(&Action::Decrypt) {
                        let file = files::open_file(&args.input)
                            .expect("could not open tar file");

                        let parent_directory = Path::new(&args.input).parent()
                            .expect("could not get parent directory");

                        let mut decrypted_archive = tar::Archive::new(file);

                        decrypted_archive.unpack(&parent_directory)
                            .expect("could not unpack tar archive");
                    }
                }
                false => {

                    fs::read_dir(&args.input).expect("could not walk directory")
                        .for_each(|entry| {
                            let input_file = String::from(
                                entry.expect("could get directory entry").path().to_str()
                                    .expect("could not convert path to string")
                            );

                            handle_cryptor_file(&args, &input_file);
                        });
                }
            }
        },
        Type::File => {
            if !input_file_info.is_file() {
                println!("Input file is not a file!");
                exit(1);
            }

            handle_cryptor_file(&args, &args.input);
        }
    }
}

fn handle_cryptor_file(args: &Args,input_file_name: &String) {
    let mut reader = BufReader::new(
        files::open_file(input_file_name).expect("could not open input file")
    );

    let output_file_name = format!("{}.enc", input_file_name);
    let mut writer: BufWriter<File> =
        BufWriter::new(files::create_file(
            &output_file_name).expect("could not create output file")
        );

    match &args.action {
        Action::Encrypt => {
            if cryptor::is_encrypted(input_file_name) {
                println!("File is already encrypted : {}", input_file_name);
                exit(1);
            }

            println!("Encrypting {} ...", input_file_name);
            let ctx = cryptor::Context::try_from_file_path(input_file_name)
                .expect("could not generate cryptor context from input file");

            ctx.encrypt_file(&mut reader, &mut writer, &args.password)
                .expect("could not encrypt file");
        }
        Action::Decrypt => {
            if !cryptor::is_encrypted(input_file_name) {
                println!("File already decrypted : {}...", input_file_name);
                exit(1);
            }
            println!("Decrypting {}...", &input_file_name);

            let mut ctx = cryptor::Context::new();
            ctx.decrypt_file(&mut reader, &mut writer, &args.password)
                .expect("could not decrypt file");
        }
    }

    files::replace_file(input_file_name, output_file_name.as_str())
        .expect("could not override input file with output file");

    println!("Done {:?} {}", &args.action, &output_file_name);
}

