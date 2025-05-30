use std::{env, fs};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use lazy_static::lazy_static;
use tempfile::{NamedTempFile, TempDir};
use crate::errors::File as FileError;


lazy_static! {
    /// Points to the OS default temp directory - this is a fallback in case we can't get parent directory
    /// for a specific file.
    static ref DEFAULT_TEMP_DIR: PathBuf = env::temp_dir();
}

// Default chunk size - 5 MB
pub const FILE_CHUNK_SIZE: u64 = 1024 * 1024;

/// Open a file for reading purposes. Returns a wrapped error if we can't.
///
/// # Errors
///   * if we don't have the permissions to read file
///
/// # Example
/// ```no_run
/// use std::path::Path;
/// use rustware::files::open_file;
///
/// let shadow_reader = open_file(Path::new("/etc/shadow")).unwrap();
/// println!("{:?}", shadow_reader)
/// ```
pub fn open_file<P: AsRef<Path>>(path: P) -> Result<File, FileError> {
    match File::open(path) {
        Ok(file) => Ok(file),
        Err(_) => Err(FileError::FileOpenFailed)
    }
}

/// Create a new file (for writing purposes) and return a handle to that file.
///
/// # Errors
///   * if we can't create a file in the specified location
///   * if the file already exists
///
/// # Examples
///
/// ```no_run
/// use std::io::Write;
/// use std::path::Path;
/// use rustware::files::create_file;
///
/// let mut f = create_file(Path::new("/tmp/wow.txt")).unwrap();
/// f.write_all(b"Damn right!").unwrap();
/// ```
pub fn create_file<P: AsRef<Path>>(path: P) -> Result<File, FileError> {
    match File::create(path) {
        Ok(file) => Ok(file),
        Err(_) => Err(FileError::FileCreateFailed)
    }
}

/// Read a vector of `size` bytes from `file` and return its content.
///
/// # Errors
///   * if the file can't be read anymore
///
/// # Example
///
/// ```no_run
/// use std::path::Path;
/// use rustware::files::{open_file, read_chunk};
///
/// let mut shadow_reader = open_file(Path::new("/etc/shadow")).unwrap();
/// let chunk = read_chunk(&mut shadow_reader, 4096); // read 4096 bytes from shadow_reader
/// ```
pub fn read_chunk<R>(file: &mut R, size: usize) -> Result<Vec<u8>, FileError>
where
    R: Read,
{
    let mut buffer: Vec<u8> = vec![0u8; size];
    let s = file.read(buffer.as_mut_slice())?;
    buffer.truncate(s);
    Ok(buffer)
}

/// Write a `data` (aka `chunk` aka vector of bytes) to target `file`
/// 
/// # Errors
///   * I/O errors while writing
/// 
/// # Examples
/// 
/// ```no_run
/// use std::io::Write;
/// use std::path::Path;
/// use rustware::files::{create_file, write_chunk};
///
/// let mut f = create_file(Path::new("/tmp/wow.txt")).unwrap();
/// write_chunk(&mut f, "oh no... why all this wrapping!!!".as_bytes()).unwrap();
/// ```
pub fn write_chunk<W>(file: &mut W, data: &[u8]) -> Result<(), FileError>
where
    W: Write,
{
    file.write_all(data)?;
    Ok(())
}

/// Rename `input` to `output`. This will completely erase the original content of `output`.
/// The `input` file will be moved to the location of `output` with the exact same name.
///
/// # Errors
///   * if one of the files is deleted beforehand
///   * if the files aren't on the same device (linux only I belive)
/// 
/// # Examples
/// ```no_run
/// use std::path::Path;
/// use rustware::files::replace_file;
///  
/// replace_file(Path::new("/tmp/a.xt"), Path::new("/tmp/b.txt")).unwrap();
/// ```
pub fn replace_file<P: AsRef<Path>, Q: AsRef<Path>>(input: P, output: Q) -> Result<(), FileError> {
    fs::rename(input, output)?;
    Ok(())
}

pub fn safe_get_parent(path: &Path) -> PathBuf {
    path.parent()
        .unwrap_or_else(|| DEFAULT_TEMP_DIR.as_path())
        .to_path_buf()
}

pub fn create_temp_file(target_dir: &Path) -> Result<NamedTempFile, FileError> {
    tempfile::Builder::new()
        .tempfile_in(target_dir)
        .map_err(|_| FileError::TempFileCreationFailed)
}

pub fn create_temp_dir(target_dir: &Path) -> Result<TempDir, FileError> {
    tempfile::tempdir_in(target_dir)
        .map_err(|_| FileError::TempFileCreationFailed)
}

pub fn extract_archive(path: &Path) -> Result<(), FileError>{
    let mut archive = tar::Archive::new(
        open_file(path)?
    );
    
    let target_directory = safe_get_parent(&path);
    let temp : PathBuf = match (path.is_dir(), path.is_file()||path.is_symlink()) {
        (false, true) => {
            let f = create_temp_file(target_directory.as_path())?;
            Ok(f.path().to_path_buf())
        },
        (true, _) => {
            let d = create_temp_dir(target_directory.as_path())?;
            Ok(d.keep())
        },
        (_, _) => {
            Err(FileError::TempFileCreationFailed)
        }
    }?;

    archive.unpack(temp.as_path())?;
    
    fs::remove_file(path)?;
    replace_file(temp.as_path(), path)?;
    Ok(())
}

pub fn archive(path: &Path) -> Result<NamedTempFile, FileError> {
    let mut archive = tar::Builder::new(
        create_temp_file(
            safe_get_parent(&path).as_path()
        )?
    );

    if path.is_dir() {
        archive.append_dir_all("", path)?;
        fs::remove_dir_all(path)?;
    }

    if path.is_file() || path.is_symlink() {
        archive.append_path(path)?;
        fs::remove_file(path)?;
    }


    let new_input_file = archive.into_inner()
        .map_err(|e| FileError::FileManipulationFailed(e))?;

    replace_file(new_input_file.path(), path)?;
    Ok(new_input_file)
}