use std::fs::File;
use local_utils::crypto;

const FILE_CHUNK_SIZE: usize = 1024 * 1024 * 5;

fn open_file(path: String) -> File {
    match File::open(path) {
        Ok(file) => file,
        Err(e) => {
            panic!("could not open file : {:?}", e);
        }
    }
}

fn create_file(path: String) -> File {
    match File::create(path) {
        Ok(file) => file,
        Err(e) => {
            panic!("could not create file : {:?}", e);
        }
    }
}


fn main() {
    let salt = crypto::generate_random_vector(12);
    let nonce = crypto::generate_random_vector(12);
    let password = String::from("test#!12345!!!");
    let input = Vec::from("wow this is cool!");

    let encrypted = crypto::encrypt_chunk(&input, &password, &salt, &nonce).unwrap();
    let decrypted = crypto::decrypt_chunk(&encrypted, &password, &salt, &nonce).unwrap();

    println!("Input : {}", crypto::print_random_bytes(&input));
    println!("Encrypted : {}", crypto::print_random_bytes(&encrypted));
    println!("Decrypted : {}", crypto::print_random_bytes(&decrypted));

}
