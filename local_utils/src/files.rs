use std::error::Error;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};

// Default chunk size - 5 MB
pub const FILE_CHUNK_SIZE: u64 = 1024 * 1024;

type FileError = Box<dyn Error>;

pub fn open_file(path: &String) -> Result<File, FileError> {
    match File::open(path) {
        Ok(file) => Ok(file),
        Err(e) => Err(e.into()),
    }
}

pub fn create_file(path: &String) -> Result<File, FileError> {
    match File::create(path) {
        Ok(file) => Ok(file),
        Err(e) => Err(e.into())
    }
}

pub fn read_chunk<InputType: Sized + Read>(file: &mut BufReader<InputType>, size: usize) -> Result<Vec<u8>, FileError> {
    let mut buffer: Vec<u8> = vec![0u8; size];
    match file.read(buffer.as_mut_slice()) {
        Ok(s) => {
            buffer.truncate(s);
            Ok(buffer)
        }
        Err(e) => Err(e.into())
    }
}

pub fn write_chunk<OutputType: Sized + Write>(file: &mut BufWriter<OutputType>, data: &[u8]) -> Result<(), FileError> {
    match file.write_all(data) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into())
    }
}