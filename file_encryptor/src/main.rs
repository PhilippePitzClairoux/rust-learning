use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use local_utils::{crypto, files};
use clap::{Parser};

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
    let salt = crypto::generate_random_vector(12);

    let metadata = input_file.metadata().expect("could not read metadata of input file");
    let chunks = (metadata.len() / args.chunk_size) + 1;

    // write salt to output file
    writer.write_all(&salt).expect("could not write salt to output file");
    writer.flush().expect("could not flush output file");

    println!("Input file length : {} bytes, Total number of chunks : {}", metadata.len(),chunks);
    for _ in 0..chunks {
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
