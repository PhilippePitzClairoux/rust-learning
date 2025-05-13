use std::{fs, io};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use crate::errors::File as FileError;

// Default chunk size - 5 MB
pub const FILE_CHUNK_SIZE: u64 = 1024 * 1024;

pub fn open_file(path: &String) -> Result<File, FileError> {
    match File::open(path) {
        Ok(file) => Ok(file),
        Err(e) => Err(FileError::FileOpenFailed)
    }
}

pub fn create_file(path: &String) -> Result<File, FileError> {
    match File::create(path) {
        Ok(file) => Ok(file),
        Err(_) => Err(FileError::FileCreateFailed)
    }
}

pub fn read_chunk<R>(file: &mut R, size: usize) -> Result<Vec<u8>, FileError>
where
    R: Read,
{
    let mut buffer: Vec<u8> = vec![0u8; size];
    let s = file.read(buffer.as_mut_slice())?;
    buffer.truncate(s);
    Ok(buffer)
}

pub fn write_chunk<W>(file: &mut W, data: &[u8]) -> Result<(), FileError>
where
    W: Write,
{
    file.write_all(data)?;
    Ok(())
}

pub fn replace_file(replace: &mut File, by: &mut File) -> Result<(), FileError> {

    replace.seek(SeekFrom::Start(0))?;
    by.seek(SeekFrom::Start(0))?;

    io::copy(by, replace)?;

    Ok(())
}