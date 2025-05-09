use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};

// Default chunk size - 5 MB
pub const FILE_CHUNK_SIZE: u64 = 1024 * 1024;

pub fn open_file(path: &String) -> Result<File, Box<dyn Error>> {
    match File::open(path) {
        Ok(file) => Ok(file),
        Err(e) => Err(e.into()),
    }
}

pub fn create_file(path: &String) -> Result<File, Box<dyn Error>> {
    match File::create(path) {
        Ok(file) => Ok(file),
        Err(e) => Err(e.into())
    }
}

pub fn read_chunk<R>(file: &mut R, size: usize) -> Result<Vec<u8>, Box<dyn Error>>
where
    R: Read,
{
    let mut buffer: Vec<u8> = vec![0u8; size];
    match file.read(buffer.as_mut_slice()) {
        Ok(s) => {
            buffer.truncate(s);
            Ok(buffer)
        }
        Err(e) => Err(e.into())
    }
}

pub fn write_chunk<W>(file: &mut W, data: &[u8]) -> Result<(), Box<dyn Error>>
where
    W: Write,
{
    match file.write_all(data) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into())
    }
}

pub fn replace_file(replace: &str, by: &str) -> Result<(), Box<dyn Error>> {
    fs::exists(replace)?;
    fs::exists(by)?;

    fs::remove_file(replace)?;
    match fs::rename(by, replace) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into())
    }
}